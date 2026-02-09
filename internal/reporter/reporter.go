// Package reporter generates formatted reports from DIO pipeline results.
package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/maxlar/docker-image-optimizer/internal/models"
)

// Format represents the output format of a report.
type Format string

const (
	FormatMarkdown Format = "markdown"
	FormatJSON     Format = "json"
)

// Reporter generates reports in various formats.
type Reporter struct {
	outputDir string
}

// New creates a new Reporter.
func New(outputDir string) *Reporter {
	return &Reporter{outputDir: outputDir}
}

// Generate creates a report in the specified format.
func (r *Reporter) Generate(result *models.PipelineResult, format Format) (string, error) {
	switch format {
	case FormatMarkdown:
		return r.generateMarkdown(result)
	case FormatJSON:
		return r.generateJSON(result)
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
}

// WriteReport writes the report to a file.
func (r *Reporter) WriteReport(content string, filename string) error {
	if err := os.MkdirAll(r.outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	path := filepath.Join(r.outputDir, filename)
	return os.WriteFile(path, []byte(content), 0o644)
}

// GenerateAll generates both markdown and JSON reports.
func (r *Reporter) GenerateAll(result *models.PipelineResult) error {
	md, err := r.generateMarkdown(result)
	if err != nil {
		return fmt.Errorf("markdown report failed: %w", err)
	}
	if err := r.WriteReport(md, "report.md"); err != nil {
		return err
	}

	jsonReport, err := r.generateJSON(result)
	if err != nil {
		return fmt.Errorf("JSON report failed: %w", err)
	}
	if err := r.WriteReport(jsonReport, "report.json"); err != nil {
		return err
	}

	return nil
}

// --- Markdown ---

func (r *Reporter) generateMarkdown(result *models.PipelineResult) (string, error) {
	var sb strings.Builder

	sb.WriteString("# 🐳 Docker Image Optimizer Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", result.Timestamp.Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("**Dockerfile:** `%s`\n\n", result.Dockerfile))

	// Summary
	sb.WriteString("---\n\n")
	if result.Policy != nil && result.Policy.Passed {
		sb.WriteString("## ✅ Result: PASSED\n\n")
	} else if result.Policy != nil {
		sb.WriteString("## ❌ Result: FAILED\n\n")
	}

	// Comparison
	if result.Comparison != nil {
		sb.WriteString("## 📊 Comparison\n\n")
		sb.WriteString("| Metric | Baseline | Optimized | Change |\n")
		sb.WriteString("|--------|----------|-----------|--------|\n")
		sb.WriteString(fmt.Sprintf("| Size | %s | %s | **-%.1f%%** |\n",
			result.Comparison.Baseline.SizeHuman,
			result.Comparison.Optimized.SizeHuman,
			result.Comparison.SizePct))
		sb.WriteString(fmt.Sprintf("| Layers | %d | %d | -%d |\n",
			result.Comparison.Baseline.Layers,
			result.Comparison.Optimized.Layers,
			result.Comparison.LayerDiff))
		if result.Comparison.CVEDiff != 0 {
			sb.WriteString(fmt.Sprintf("| CVEs | - | - | -%d |\n", result.Comparison.CVEDiff))
		}
		sb.WriteString("\n")
	} else if result.BaselineImage != nil {
		sb.WriteString("## 📊 Image Metrics\n\n")
		sb.WriteString(fmt.Sprintf("- **Size:** %s\n", result.BaselineImage.SizeHuman))
		sb.WriteString(fmt.Sprintf("- **Layers:** %d\n", result.BaselineImage.Layers))
		sb.WriteString(fmt.Sprintf("- **Architecture:** %s/%s\n", result.BaselineImage.OS, result.BaselineImage.Architecture))
		sb.WriteString("\n")
	}

	// Analysis
	if result.Analysis != nil {
		sb.WriteString("## 🔍 Dockerfile Analysis\n\n")
		sb.WriteString(fmt.Sprintf("**Score:** %d/100\n\n", result.Analysis.Score))

		if len(result.Analysis.Issues) > 0 {
			sb.WriteString("| Severity | ID | Issue | Suggestion |\n")
			sb.WriteString("|----------|----|-------|------------|\n")
			for _, issue := range result.Analysis.Issues {
				icon := severityIcon(issue.Severity)
				sb.WriteString(fmt.Sprintf("| %s %s | %s | %s | %s |\n",
					icon, issue.Severity, issue.ID, issue.Title, issue.Suggestion))
			}
		} else {
			sb.WriteString("No issues found! 🎉\n")
		}
		sb.WriteString("\n")
	}

	// Security Scan
	if result.ScanResult != nil {
		sb.WriteString("## 🔒 Security Scan\n\n")
		sb.WriteString(fmt.Sprintf("**Scanner:** %s\n\n", result.ScanResult.Scanner))
		sb.WriteString(fmt.Sprintf("- 🔴 Critical: %d\n", result.ScanResult.CriticalCount))
		sb.WriteString(fmt.Sprintf("- 🟠 High: %d\n", result.ScanResult.HighCount))
		sb.WriteString(fmt.Sprintf("- 🟡 Medium: %d\n", result.ScanResult.MediumCount))
		sb.WriteString(fmt.Sprintf("- 🔵 Low: %d\n", result.ScanResult.LowCount))

		if result.ScanResult.CriticalCount > 0 {
			sb.WriteString("\n### Critical Vulnerabilities\n\n")
			sb.WriteString("| CVE | Package | Version | Fixed Version |\n")
			sb.WriteString("|-----|---------|---------|---------------|\n")
			for _, v := range result.ScanResult.Vulnerabilities {
				if v.Severity == models.SeverityCritical {
					sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
						v.ID, v.Package, v.Version, v.FixedVersion))
				}
			}
		}
		sb.WriteString("\n")
	}

	// Optimizations
	if result.Optimization != nil && len(result.Optimization.Optimizations) > 0 {
		sb.WriteString("## ⚡ Optimizations\n\n")
		for _, opt := range result.Optimization.Optimizations {
			status := "💡"
			if opt.Applied {
				status = "✅"
			}
			sb.WriteString(fmt.Sprintf("- %s **%s** — %s (Impact: %s)\n",
				status, opt.Title, opt.Description, opt.Impact))
		}
		sb.WriteString("\n")
		if result.Optimization.EstimatedReduction != "" {
			sb.WriteString(fmt.Sprintf("**Estimated reduction:** %s\n\n", result.Optimization.EstimatedReduction))
		}
	}

	// Policy
	if result.Policy != nil {
		sb.WriteString("## 📋 Policy Checks\n\n")
		for _, rule := range result.Policy.Rules {
			if rule.Passed {
				sb.WriteString(fmt.Sprintf("- ✅ %s\n", rule.Description))
			} else {
				sb.WriteString(fmt.Sprintf("- ❌ %s: %s\n", rule.Description, rule.Message))
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("---\n")
	sb.WriteString("*Generated by [Docker Image Optimizer (DIO)](https://github.com/maxlar/docker-image-optimizer) by Moustafa Rakha (Maxlar)*\n")

	return sb.String(), nil
}

func severityIcon(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}

// --- JSON ---

func (r *Reporter) generateJSON(result *models.PipelineResult) (string, error) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(data), nil
}
