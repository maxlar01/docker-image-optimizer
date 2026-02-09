// Package optimizer provides the core Dockerfile optimization engine.
// It analyzes Dockerfiles and applies optimization strategies to produce
// smaller, more secure, and more efficient images.
package optimizer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/maxlar/docker-image-optimizer/internal/analyzer"
	"github.com/maxlar/docker-image-optimizer/internal/models"
)

// Mode determines how the optimizer operates.
type Mode string

const (
	// ModeSuggest only generates suggestions without modifying the Dockerfile.
	ModeSuggest Mode = "suggest"
	// ModeAutoFix applies optimizations automatically.
	ModeAutoFix Mode = "autofix"
)

// Optimizer is the core optimization engine.
type Optimizer struct {
	mode       Mode
	strategies []Strategy
}

// New creates a new Optimizer with all built-in strategies registered.
func New(mode Mode) *Optimizer {
	return &Optimizer{
		mode: mode,
		strategies: []Strategy{
			&BaseImageStrategy{},
			&CombineLayersStrategy{},
			&MultiStageStrategy{},
			&CacheOptStrategy{},
			&NonRootUserStrategy{},
			&CleanupStrategy{},
			&WorkdirStrategy{},
		},
	}
}

// Optimize reads a Dockerfile, applies optimization strategies, and returns the result.
func (o *Optimizer) Optimize(dockerfilePath string) (*models.OptimizationResult, error) {
	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Dockerfile: %w", err)
	}

	return o.OptimizeContent(string(content))
}

// OptimizeContent optimizes Dockerfile content from a string.
func (o *Optimizer) OptimizeContent(content string) (*models.OptimizationResult, error) {
	lines := strings.Split(content, "\n")
	a := analyzer.New()
	analysisResult, err := a.AnalyzeContent(content)
	if err != nil {
		return nil, fmt.Errorf("analysis failed: %w", err)
	}

	ctx := &OptimizationContext{
		OriginalContent: content,
		Lines:           lines,
		Analysis:        analysisResult,
		CurrentContent:  content,
	}

	var optimizations []models.Optimization

	for _, strategy := range o.strategies {
		opt := strategy.Analyze(ctx)
		if opt == nil {
			continue
		}

		if o.mode == ModeAutoFix && opt.AutoFixable {
			newContent, err := strategy.Apply(ctx)
			if err == nil {
				ctx.CurrentContent = newContent
				ctx.Lines = strings.Split(newContent, "\n")
				opt.Applied = true
			}
		}

		optimizations = append(optimizations, *opt)
	}

	return &models.OptimizationResult{
		OriginalDockerfile:  content,
		OptimizedDockerfile: ctx.CurrentContent,
		Optimizations:       optimizations,
		EstimatedReduction:  estimateReduction(optimizations),
	}, nil
}

// WriteOptimized writes the optimized Dockerfile to disk.
func (o *Optimizer) WriteOptimized(result *models.OptimizationResult, outputPath string) error {
	dir := filepath.Dir(outputPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	return os.WriteFile(outputPath, []byte(result.OptimizedDockerfile), 0o644)
}

// OptimizationContext carries state through the optimization pipeline.
type OptimizationContext struct {
	OriginalContent string
	Lines           []string
	Analysis        *models.AnalysisResult
	CurrentContent  string
}

func estimateReduction(optimizations []models.Optimization) string {
	totalImpact := 0
	for _, opt := range optimizations {
		if opt.Applied {
			switch opt.Category {
			case "base-image":
				totalImpact += 60
			case "multi-stage":
				totalImpact += 50
			case "layer-optimization":
				totalImpact += 15
			case "cleanup":
				totalImpact += 20
			default:
				totalImpact += 5
			}
		}
	}
	if totalImpact > 85 {
		totalImpact = 85
	}
	if totalImpact == 0 {
		return "N/A (suggest mode)"
	}
	return fmt.Sprintf("~%d%% estimated reduction", totalImpact)
}
