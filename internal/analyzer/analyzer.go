// Package analyzer provides static analysis for Dockerfiles.
// It checks for common anti-patterns, inefficiencies, and security issues
// before the image is even built.
package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/maxlar/docker-image-optimizer/internal/models"
)

// Analyzer performs static analysis on Dockerfiles.
type Analyzer struct {
	rules       []Rule
	useHadolint bool
}

// New creates a new Analyzer with all built-in rules registered.
// Hadolint integration is enabled automatically if the binary is found in PATH.
func New() *Analyzer {
	a := &Analyzer{
		useHadolint: isHadolintAvailable(),
	}
	a.rules = DefaultRules()
	return a
}

// NewWithOptions creates a new Analyzer with explicit configuration.
func NewWithOptions(enableHadolint bool) *Analyzer {
	a := &Analyzer{
		useHadolint: enableHadolint && isHadolintAvailable(),
	}
	a.rules = DefaultRules()
	return a
}

// Analyze reads a Dockerfile and runs all rules against it.
func (a *Analyzer) Analyze(dockerfilePath string) (*models.AnalysisResult, error) {
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Dockerfile: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	ctx := &AnalysisContext{
		FilePath:   dockerfilePath,
		Content:    string(content),
		Lines:      lines,
		ParsedFile: parseDockerfile(lines),
	}

	// Check for .dockerignore
	dir := filepath.Dir(dockerfilePath)
	if _, err := os.Stat(filepath.Join(dir, ".dockerignore")); os.IsNotExist(err) {
		ctx.MissingDockerignore = true
	}

	var issues []models.Issue
	for _, rule := range a.rules {
		ruleIssues := rule.Check(ctx)
		issues = append(issues, ruleIssues...)
	}

	// Run hadolint if available and merge results
	if a.useHadolint {
		hadolintIssues, err := RunHadolint(dockerfilePath)
		if err == nil {
			issues = mergeHadolintIssues(issues, hadolintIssues)
		}
		// Silently ignore hadolint errors — built-in rules still apply
	}

	score := calculateScore(issues)

	return &models.AnalysisResult{
		Dockerfile: dockerfilePath,
		Issues:     issues,
		Score:      score,
	}, nil
}

// AnalyzeContent analyzes Dockerfile content from a string (no file needed).
func (a *Analyzer) AnalyzeContent(content string) (*models.AnalysisResult, error) {
	lines := strings.Split(content, "\n")
	ctx := &AnalysisContext{
		FilePath:   "<stdin>",
		Content:    content,
		Lines:      lines,
		ParsedFile: parseDockerfile(lines),
	}

	var issues []models.Issue
	for _, rule := range a.rules {
		ruleIssues := rule.Check(ctx)
		issues = append(issues, ruleIssues...)
	}

	score := calculateScore(issues)

	return &models.AnalysisResult{
		Dockerfile: "<stdin>",
		Issues:     issues,
		Score:      score,
	}, nil
}

// AnalysisContext provides parsed Dockerfile information to rules.
type AnalysisContext struct {
	FilePath            string
	Content             string
	Lines               []string
	ParsedFile          *ParsedDockerfile
	MissingDockerignore bool
}

// ParsedDockerfile holds a structured representation of a Dockerfile.
type ParsedDockerfile struct {
	Stages        []Stage
	Instructions  []Instruction
	BaseImages    []string
	HasMultiStage bool
}

// Stage represents a build stage in a Dockerfile.
type Stage struct {
	Name         string
	BaseImage    string
	Instructions []Instruction
	StartLine    int
}

// Instruction represents a single Dockerfile instruction.
type Instruction struct {
	Command string
	Args    string
	Line    int
	Raw     string
}

// parseDockerfile does a lightweight parse of Dockerfile instructions.
func parseDockerfile(lines []string) *ParsedDockerfile {
	pdf := &ParsedDockerfile{}
	var currentStage *Stage
	stageCount := 0

	instructionRegex := regexp.MustCompile(`^(\w+)\s+(.*)`)

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Handle line continuations
		for strings.HasSuffix(trimmed, "\\") && i+1 < len(lines) {
			i++
			trimmed = strings.TrimSuffix(trimmed, "\\") + " " + strings.TrimSpace(lines[i])
		}

		matches := instructionRegex.FindStringSubmatch(trimmed)
		if len(matches) < 3 {
			continue
		}

		inst := Instruction{
			Command: strings.ToUpper(matches[1]),
			Args:    matches[2],
			Line:    i + 1,
			Raw:     trimmed,
		}

		pdf.Instructions = append(pdf.Instructions, inst)

		if inst.Command == "FROM" {
			stageCount++
			if currentStage != nil {
				pdf.Stages = append(pdf.Stages, *currentStage)
			}

			baseImage := parseBaseImage(inst.Args)
			pdf.BaseImages = append(pdf.BaseImages, baseImage)

			stageName := parseStageName(inst.Args)
			currentStage = &Stage{
				Name:      stageName,
				BaseImage: baseImage,
				StartLine: i + 1,
			}
		}

		if currentStage != nil {
			currentStage.Instructions = append(currentStage.Instructions, inst)
		}
	}

	if currentStage != nil {
		pdf.Stages = append(pdf.Stages, *currentStage)
	}

	pdf.HasMultiStage = stageCount > 1
	return pdf
}

func parseBaseImage(args string) string {
	parts := strings.Fields(args)
	if len(parts) == 0 {
		return ""
	}
	return strings.ToLower(parts[0])
}

func parseStageName(args string) string {
	parts := strings.Fields(args)
	for i, p := range parts {
		if strings.ToLower(p) == "as" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func calculateScore(issues []models.Issue) int {
	score := 100
	for _, issue := range issues {
		switch issue.Severity {
		case models.SeverityCritical:
			score -= 20
		case models.SeverityHigh:
			score -= 15
		case models.SeverityMedium:
			score -= 10
		case models.SeverityLow:
			score -= 5
		case models.SeverityInfo:
			score -= 2
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

// hadolintResult represents a single result from hadolint's JSON output.
type hadolintResult struct {
	Line    int    `json:"line"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Column  int    `json:"column"`
	File    string `json:"file"`
	Level   string `json:"level"` // error, warning, info, style
}

// isHadolintAvailable checks whether hadolint is installed and on PATH.
func isHadolintAvailable() bool {
	_, err := exec.LookPath("hadolint")
	return err == nil
}

// RunHadolint invokes hadolint and parses its JSON output into DIO issues.
func RunHadolint(dockerfilePath string) ([]models.Issue, error) {
	hadolintPath, err := exec.LookPath("hadolint")
	if err != nil {
		return nil, fmt.Errorf("hadolint not found: %w", err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(hadolintPath, "--format", "json", "--no-fail", dockerfilePath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// hadolint returns exit code 1 when it finds issues, which is expected.
	_ = cmd.Run()

	// If no output, nothing to parse
	if stdout.Len() == 0 {
		return nil, nil
	}

	var results []hadolintResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		return nil, fmt.Errorf("failed to parse hadolint output: %w", err)
	}

	var issues []models.Issue
	for _, r := range results {
		issues = append(issues, models.Issue{
			ID:          "HL-" + r.Code,
			Severity:    mapHadolintLevel(r.Level),
			Category:    "hadolint",
			Title:       r.Code + ": " + truncate(r.Message, 80),
			Description: r.Message,
			Line:        r.Line,
			AutoFixable: false,
		})
	}

	return issues, nil
}

// mapHadolintLevel converts hadolint severity levels to DIO severity.
func mapHadolintLevel(level string) models.Severity {
	switch strings.ToLower(level) {
	case "error":
		return models.SeverityHigh
	case "warning":
		return models.SeverityMedium
	case "info":
		return models.SeverityLow
	case "style":
		return models.SeverityInfo
	default:
		return models.SeverityLow
	}
}

// mergeHadolintIssues appends hadolint issues, skipping any that overlap with
// existing DIO issues on the same line with equivalent meaning.
func mergeHadolintIssues(dioIssues, hadolintIssues []models.Issue) []models.Issue {
	// Build a set of lines already flagged by built-in rules
	coveredLines := make(map[int]map[string]bool)
	for _, issue := range dioIssues {
		if issue.Line > 0 {
			if coveredLines[issue.Line] == nil {
				coveredLines[issue.Line] = make(map[string]bool)
			}
			coveredLines[issue.Line][issue.Category] = true
		}
	}

	// Known overlaps: hadolint rules that duplicate built-in DIO rules
	hadolintToDIOCategory := map[string]string{
		"DL3007": "base-image",      // Using latest tag
		"DL3008": "version-pinning", // Pin versions in apt-get
		"DL3009": "cleanup",         // Delete apt-get lists
		"DL3015": "apt-get",         // --no-install-recommends
		"DL3025": "best-practice",   // Use JSON for CMD
		"DL3020": "best-practice",   // Use COPY instead of ADD
	}

	for _, hlIssue := range hadolintIssues {
		// Extract the hadolint rule code from ID ("HL-DL3007" -> "DL3007")
		code := strings.TrimPrefix(hlIssue.ID, "HL-")

		// Skip if a built-in DIO rule already covers this line+category
		if dioCategory, ok := hadolintToDIOCategory[code]; ok {
			if cats, exists := coveredLines[hlIssue.Line]; exists && cats[dioCategory] {
				continue
			}
		}

		dioIssues = append(dioIssues, hlIssue)
	}

	return dioIssues
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
