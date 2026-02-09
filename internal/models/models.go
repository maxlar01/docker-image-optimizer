// Package models defines shared types used across all DIO components.
package models

import "time"

// Severity represents the severity level of an issue.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Issue represents a single problem found during analysis.
type Issue struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Line        int      `json:"line,omitempty"`
	Suggestion  string   `json:"suggestion,omitempty"`
	AutoFixable bool     `json:"auto_fixable"`
}

// AnalysisResult holds the output of the Dockerfile analyzer.
type AnalysisResult struct {
	Dockerfile string  `json:"dockerfile"`
	Issues     []Issue `json:"issues"`
	Score      int     `json:"score"` // 0-100, higher = better
}

// ImageMetrics captures information about a built Docker image.
type ImageMetrics struct {
	ImageName    string    `json:"image_name"`
	ImageID      string    `json:"image_id"`
	Size         int64     `json:"size"`
	SizeHuman    string    `json:"size_human"`
	Layers       int       `json:"layers"`
	BaseImage    string    `json:"base_image"`
	CreatedAt    time.Time `json:"created_at"`
	BuildTime    float64   `json:"build_time_seconds"`
	Architecture string    `json:"architecture"`
	OS           string    `json:"os"`
}

// Vulnerability represents a single CVE or security issue.
type Vulnerability struct {
	ID            string   `json:"id"`
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	FixedVersion  string   `json:"fixed_version,omitempty"`
	Severity      Severity `json:"severity"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	DataSource    string   `json:"data_source"`
	PublishedDate string   `json:"published_date,omitempty"`
}

// ScanResult holds the output of the security scanner.
type ScanResult struct {
	ImageName       string          `json:"image_name"`
	Scanner         string          `json:"scanner"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	CriticalCount   int             `json:"critical_count"`
	HighCount       int             `json:"high_count"`
	MediumCount     int             `json:"medium_count"`
	LowCount        int             `json:"low_count"`
	SecretsFound    []Secret        `json:"secrets_found,omitempty"`
}

// Secret represents a secret or credential found in the image.
type Secret struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	Match    string `json:"match"`
	Severity string `json:"severity"`
}

// Optimization represents a single optimization that can be applied.
type Optimization struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact"` // estimated size reduction
	Applied     bool   `json:"applied"`
	AutoFixable bool   `json:"auto_fixable"`
	Priority    int    `json:"priority"` // 1 = highest
}

// OptimizationResult holds the output of the optimizer engine.
type OptimizationResult struct {
	OriginalDockerfile  string         `json:"original_dockerfile"`
	OptimizedDockerfile string         `json:"optimized_dockerfile"`
	Optimizations       []Optimization `json:"optimizations"`
	EstimatedReduction  string         `json:"estimated_reduction"`
}

// PolicyRule represents a single policy rule.
type PolicyRule struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Value       interface{} `json:"value"`
	Passed      bool        `json:"passed"`
	Message     string      `json:"message,omitempty"`
}

// PolicyResult holds the output of the policy enforcer.
type PolicyResult struct {
	Passed bool         `json:"passed"`
	Rules  []PolicyRule `json:"rules"`
}

// ComparisonMetrics shows before/after comparison.
type ComparisonMetrics struct {
	Baseline  ImageMetrics `json:"baseline"`
	Optimized ImageMetrics `json:"optimized"`
	SizeDiff  int64        `json:"size_diff"`
	SizePct   float64      `json:"size_reduction_pct"`
	LayerDiff int          `json:"layer_diff"`
	CVEDiff   int          `json:"cve_diff"`
}

// PipelineResult is the top-level result of the entire DIO pipeline.
type PipelineResult struct {
	Timestamp      time.Time           `json:"timestamp"`
	Dockerfile     string              `json:"dockerfile"`
	Analysis       *AnalysisResult     `json:"analysis,omitempty"`
	BaselineImage  *ImageMetrics       `json:"baseline_image,omitempty"`
	ScanResult     *ScanResult         `json:"scan_result,omitempty"`
	Optimization   *OptimizationResult `json:"optimization,omitempty"`
	OptimizedImage *ImageMetrics       `json:"optimized_image,omitempty"`
	OptScanResult  *ScanResult         `json:"optimized_scan_result,omitempty"`
	Policy         *PolicyResult       `json:"policy,omitempty"`
	Comparison     *ComparisonMetrics  `json:"comparison,omitempty"`
}
