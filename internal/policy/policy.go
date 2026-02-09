// Package policy provides policy enforcement for Docker images.
// Rules are defined in YAML and evaluated against analysis, scan, and build results.
package policy

import (
	"fmt"
	"os"
	"strings"

	"github.com/maxlar/docker-image-optimizer/internal/models"
	"github.com/maxlar/docker-image-optimizer/pkg/docker"
	"gopkg.in/yaml.v3"
)

// Config represents the policy configuration file.
type Config struct {
	MaxImageSize    string `yaml:"max_image_size"`
	ForbidLatestTag bool   `yaml:"forbid_latest_tag"`
	RequireNonRoot  bool   `yaml:"require_non_root"`
	MaxCriticalCVEs int    `yaml:"max_critical_cves"`
	MaxHighCVEs     int    `yaml:"max_high_cves"`
	RequireHealthcheck bool `yaml:"require_healthcheck"`
	ForbidRootUser  bool   `yaml:"forbid_root_user"`
	MaxLayers       int    `yaml:"max_layers"`
	MinScore        int    `yaml:"min_score"` // minimum analyzer score
}

// DefaultConfig returns the default policy configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxImageSize:    "500MB",
		ForbidLatestTag: true,
		RequireNonRoot:  true,
		MaxCriticalCVEs: 0,
		MaxHighCVEs:     5,
		RequireHealthcheck: false,
		ForbidRootUser:  true,
		MaxLayers:       20,
		MinScore:        50,
	}
}

// LoadConfig reads a policy configuration from a YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	return config, nil
}

// Enforcer evaluates policy rules against pipeline results.
type Enforcer struct {
	config *Config
}

// NewEnforcer creates a new policy enforcer.
func NewEnforcer(config *Config) *Enforcer {
	return &Enforcer{config: config}
}

// Evaluate checks all policy rules and returns the result.
func (e *Enforcer) Evaluate(result *models.PipelineResult) *models.PolicyResult {
	policyResult := &models.PolicyResult{Passed: true}

	// Check image size
	if result.OptimizedImage != nil && e.config.MaxImageSize != "" {
		maxSize, err := docker.ParseImageSize(e.config.MaxImageSize)
		if err == nil {
			passed := result.OptimizedImage.Size <= maxSize
			rule := models.PolicyRule{
				Name:        "max_image_size",
				Description: fmt.Sprintf("Image size must be <= %s", e.config.MaxImageSize),
				Value:       e.config.MaxImageSize,
				Passed:      passed,
			}
			if !passed {
				rule.Message = fmt.Sprintf("Image size %s exceeds maximum %s",
					result.OptimizedImage.SizeHuman, e.config.MaxImageSize)
				policyResult.Passed = false
			}
			policyResult.Rules = append(policyResult.Rules, rule)
		}
	} else if result.BaselineImage != nil && e.config.MaxImageSize != "" {
		maxSize, err := docker.ParseImageSize(e.config.MaxImageSize)
		if err == nil {
			passed := result.BaselineImage.Size <= maxSize
			rule := models.PolicyRule{
				Name:        "max_image_size",
				Description: fmt.Sprintf("Image size must be <= %s", e.config.MaxImageSize),
				Value:       e.config.MaxImageSize,
				Passed:      passed,
			}
			if !passed {
				rule.Message = fmt.Sprintf("Image size %s exceeds maximum %s",
					result.BaselineImage.SizeHuman, e.config.MaxImageSize)
				policyResult.Passed = false
			}
			policyResult.Rules = append(policyResult.Rules, rule)
		}
	}

	// Check latest tag
	if e.config.ForbidLatestTag && result.Analysis != nil {
		passed := true
		for _, issue := range result.Analysis.Issues {
			if issue.ID == "DIO001" {
				passed = false
				break
			}
		}
		rule := models.PolicyRule{
			Name:        "forbid_latest_tag",
			Description: "Base images must use pinned version tags",
			Value:       true,
			Passed:      passed,
		}
		if !passed {
			rule.Message = "Unpinned base image tags detected"
			policyResult.Passed = false
		}
		policyResult.Rules = append(policyResult.Rules, rule)
	}

	// Check non-root user
	if e.config.RequireNonRoot && result.Analysis != nil {
		passed := true
		for _, issue := range result.Analysis.Issues {
			if issue.ID == "DIO006" {
				passed = false
				break
			}
		}
		rule := models.PolicyRule{
			Name:        "require_non_root",
			Description: "Container must run as non-root user",
			Value:       true,
			Passed:      passed,
		}
		if !passed {
			rule.Message = "Container runs as root"
			policyResult.Passed = false
		}
		policyResult.Rules = append(policyResult.Rules, rule)
	}

	// Check critical CVEs
	scanResult := result.OptScanResult
	if scanResult == nil {
		scanResult = result.ScanResult
	}
	if scanResult != nil {
		passed := scanResult.CriticalCount <= e.config.MaxCriticalCVEs
		rule := models.PolicyRule{
			Name:        "max_critical_cves",
			Description: fmt.Sprintf("Maximum %d critical CVEs allowed", e.config.MaxCriticalCVEs),
			Value:       e.config.MaxCriticalCVEs,
			Passed:      passed,
		}
		if !passed {
			rule.Message = fmt.Sprintf("Found %d critical CVEs (max: %d)",
				scanResult.CriticalCount, e.config.MaxCriticalCVEs)
			policyResult.Passed = false
		}
		policyResult.Rules = append(policyResult.Rules, rule)

		// Check high CVEs
		passedHigh := scanResult.HighCount <= e.config.MaxHighCVEs
		ruleHigh := models.PolicyRule{
			Name:        "max_high_cves",
			Description: fmt.Sprintf("Maximum %d high CVEs allowed", e.config.MaxHighCVEs),
			Value:       e.config.MaxHighCVEs,
			Passed:      passedHigh,
		}
		if !passedHigh {
			ruleHigh.Message = fmt.Sprintf("Found %d high CVEs (max: %d)",
				scanResult.HighCount, e.config.MaxHighCVEs)
			policyResult.Passed = false
		}
		policyResult.Rules = append(policyResult.Rules, ruleHigh)
	}

	// Check analyzer score
	if result.Analysis != nil && e.config.MinScore > 0 {
		passed := result.Analysis.Score >= e.config.MinScore
		rule := models.PolicyRule{
			Name:        "min_score",
			Description: fmt.Sprintf("Minimum analyzer score of %d required", e.config.MinScore),
			Value:       e.config.MinScore,
			Passed:      passed,
		}
		if !passed {
			rule.Message = fmt.Sprintf("Score %d is below minimum %d",
				result.Analysis.Score, e.config.MinScore)
			policyResult.Passed = false
		}
		policyResult.Rules = append(policyResult.Rules, rule)
	}

	// Check max layers
	if e.config.MaxLayers > 0 {
		img := result.OptimizedImage
		if img == nil {
			img = result.BaselineImage
		}
		if img != nil {
			passed := img.Layers <= e.config.MaxLayers
			rule := models.PolicyRule{
				Name:        "max_layers",
				Description: fmt.Sprintf("Maximum %d layers allowed", e.config.MaxLayers),
				Value:       e.config.MaxLayers,
				Passed:      passed,
			}
			if !passed {
				rule.Message = fmt.Sprintf("Image has %d layers (max: %d)",
					img.Layers, e.config.MaxLayers)
				policyResult.Passed = false
			}
			policyResult.Rules = append(policyResult.Rules, rule)
		}
	}

	return policyResult
}

// FormatPolicyStatus returns a human-readable string of the policy result.
func FormatPolicyStatus(result *models.PolicyResult) string {
	var sb strings.Builder
	if result.Passed {
		sb.WriteString("✅ All policy checks passed\n")
	} else {
		sb.WriteString("❌ Policy checks FAILED\n")
	}
	sb.WriteString("\n")

	for _, rule := range result.Rules {
		if rule.Passed {
			sb.WriteString(fmt.Sprintf("  ✔ %s\n", rule.Description))
		} else {
			sb.WriteString(fmt.Sprintf("  ✘ %s: %s\n", rule.Description, rule.Message))
		}
	}

	return sb.String()
}
