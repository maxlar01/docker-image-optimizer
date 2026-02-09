// Package scanner provides security vulnerability scanning for Docker images
// using Trivy and Grype as backends.
package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/maxlar/docker-image-optimizer/internal/models"
)

// ScannerType represents the type of security scanner to use.
type ScannerType string

const (
	ScannerTrivy ScannerType = "trivy"
	ScannerGrype ScannerType = "grype"
)

// Scanner wraps security scanning tools.
type Scanner struct {
	scannerType ScannerType
	binaryPath  string
}

// New creates a new Scanner, auto-detecting available tools.
func New() (*Scanner, error) {
	// Try Trivy first, then Grype
	if path, err := exec.LookPath("trivy"); err == nil {
		return &Scanner{scannerType: ScannerTrivy, binaryPath: path}, nil
	}
	if path, err := exec.LookPath("grype"); err == nil {
		return &Scanner{scannerType: ScannerGrype, binaryPath: path}, nil
	}
	return nil, fmt.Errorf("no supported security scanner found (install trivy or grype)")
}

// NewWithScanner creates a Scanner using a specific tool.
func NewWithScanner(scannerType ScannerType) (*Scanner, error) {
	name := string(scannerType)
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s not found in PATH: %w", name, err)
	}
	return &Scanner{scannerType: scannerType, binaryPath: path}, nil
}

// Scan performs a vulnerability scan on the given image.
func (s *Scanner) Scan(imageRef string) (*models.ScanResult, error) {
	switch s.scannerType {
	case ScannerTrivy:
		return s.scanWithTrivy(imageRef)
	case ScannerGrype:
		return s.scanWithGrype(imageRef)
	default:
		return nil, fmt.Errorf("unsupported scanner type: %s", s.scannerType)
	}
}

// --- Trivy integration ---

type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string            `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
	PublishedDate    string `json:"PublishedDate"`
}

func (s *Scanner) scanWithTrivy(imageRef string) (*models.ScanResult, error) {
	args := []string{
		"image",
		"--format", "json",
		"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
		"--quiet",
		imageRef,
	}

	cmd := exec.Command(s.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Trivy returns non-zero exit code when vulnerabilities are found
	_ = cmd.Run()

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("trivy produced no output. stderr: %s", stderr.String())
	}

	var output trivyOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %w", err)
	}

	result := &models.ScanResult{
		ImageName: imageRef,
		Scanner:   "trivy",
	}

	for _, r := range output.Results {
		for _, v := range r.Vulnerabilities {
			severity := mapSeverity(v.Severity)
			vuln := models.Vulnerability{
				ID:            v.VulnerabilityID,
				Package:       v.PkgName,
				Version:       v.InstalledVersion,
				FixedVersion:  v.FixedVersion,
				Severity:      severity,
				Title:         v.Title,
				Description:   truncate(v.Description, 200),
				DataSource:    "trivy",
				PublishedDate: v.PublishedDate,
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)

			switch severity {
			case models.SeverityCritical:
				result.CriticalCount++
			case models.SeverityHigh:
				result.HighCount++
			case models.SeverityMedium:
				result.MediumCount++
			case models.SeverityLow:
				result.LowCount++
			}
		}
	}

	return result, nil
}

// --- Grype integration ---

type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	Artifact      grypeArtifact      `json:"artifact"`
}

type grypeVulnerability struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Fix         struct {
		Versions []string `json:"versions"`
	} `json:"fix"`
	DataSource string `json:"dataSource"`
}

type grypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (s *Scanner) scanWithGrype(imageRef string) (*models.ScanResult, error) {
	args := []string{
		imageRef,
		"-o", "json",
		"--quiet",
	}

	cmd := exec.Command(s.binaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	_ = cmd.Run()

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("grype produced no output. stderr: %s", stderr.String())
	}

	var output grypeOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		return nil, fmt.Errorf("failed to parse grype output: %w", err)
	}

	result := &models.ScanResult{
		ImageName: imageRef,
		Scanner:   "grype",
	}

	for _, m := range output.Matches {
		severity := mapSeverity(m.Vulnerability.Severity)
		fixedVersion := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixedVersion = m.Vulnerability.Fix.Versions[0]
		}

		vuln := models.Vulnerability{
			ID:           m.Vulnerability.ID,
			Package:      m.Artifact.Name,
			Version:      m.Artifact.Version,
			FixedVersion: fixedVersion,
			Severity:     severity,
			Description:  truncate(m.Vulnerability.Description, 200),
			DataSource:   "grype",
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vuln)

		switch severity {
		case models.SeverityCritical:
			result.CriticalCount++
		case models.SeverityHigh:
			result.HighCount++
		case models.SeverityMedium:
			result.MediumCount++
		case models.SeverityLow:
			result.LowCount++
		}
	}

	return result, nil
}

// --- Helpers ---

func mapSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
