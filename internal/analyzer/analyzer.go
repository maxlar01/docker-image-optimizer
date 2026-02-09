// Package analyzer provides static analysis for Dockerfiles.
// It checks for common anti-patterns, inefficiencies, and security issues
// before the image is even built.
package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/maxlar/docker-image-optimizer/internal/models"
)

// Analyzer performs static analysis on Dockerfiles.
type Analyzer struct {
	rules []Rule
}

// New creates a new Analyzer with all built-in rules registered.
func New() *Analyzer {
	a := &Analyzer{}
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
	FilePath             string
	Content              string
	Lines                []string
	ParsedFile           *ParsedDockerfile
	MissingDockerignore  bool
}

// ParsedDockerfile holds a structured representation of a Dockerfile.
type ParsedDockerfile struct {
	Stages       []Stage
	Instructions []Instruction
	BaseImages   []string
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
	Command   string
	Args      string
	Line      int
	Raw       string
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

// RunHadolint invokes hadolint (if available) and parses its output.
func RunHadolint(dockerfilePath string) ([]models.Issue, error) {
	// Check if hadolint is available
	if _, err := findExecutable("hadolint"); err != nil {
		return nil, fmt.Errorf("hadolint not found: %w", err)
	}

	// This would shell out to hadolint - for now, return empty
	// In production, use os/exec to run: hadolint --format json <path>
	return nil, nil
}

func findExecutable(name string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(os.Getenv("PATH")))
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		for i := 0; i < len(data); i++ {
			if data[i] == ':' {
				return i + 1, data[:i], nil
			}
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	for scanner.Scan() {
		path := filepath.Join(scanner.Text(), name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH", name)
}
