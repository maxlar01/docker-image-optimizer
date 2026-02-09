// Package builder handles building Docker images and capturing baseline metrics.
package builder

import (
	"fmt"
	"path/filepath"

	"github.com/maxlar/docker-image-optimizer/internal/models"
	"github.com/maxlar/docker-image-optimizer/pkg/docker"
)

// Builder handles image building and metric collection.
type Builder struct {
	client *docker.Client
}

// New creates a new Builder.
func New() (*Builder, error) {
	client, err := docker.NewClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}
	return &Builder{client: client}, nil
}

// NewWithClient creates a Builder with a provided Docker client.
func NewWithClient(client *docker.Client) *Builder {
	return &Builder{client: client}
}

// BuildBaseline builds the original image and returns metrics.
func (b *Builder) BuildBaseline(dockerfilePath, tag string) (*models.ImageMetrics, error) {
	contextDir := filepath.Dir(dockerfilePath)
	metrics, err := b.client.Build(dockerfilePath, contextDir, tag)
	if err != nil {
		return nil, fmt.Errorf("baseline build failed: %w", err)
	}
	return metrics, nil
}

// BuildOptimized builds the optimized image and returns metrics.
func (b *Builder) BuildOptimized(dockerfilePath, contextDir, tag string) (*models.ImageMetrics, error) {
	metrics, err := b.client.Build(dockerfilePath, contextDir, tag)
	if err != nil {
		return nil, fmt.Errorf("optimized build failed: %w", err)
	}
	return metrics, nil
}

// Compare generates comparison metrics between baseline and optimized images.
func (b *Builder) Compare(baseline, optimized *models.ImageMetrics) *models.ComparisonMetrics {
	sizeDiff := baseline.Size - optimized.Size
	sizePct := float64(0)
	if baseline.Size > 0 {
		sizePct = float64(sizeDiff) / float64(baseline.Size) * 100
	}

	return &models.ComparisonMetrics{
		Baseline:  *baseline,
		Optimized: *optimized,
		SizeDiff:  sizeDiff,
		SizePct:   sizePct,
		LayerDiff: baseline.Layers - optimized.Layers,
	}
}

// Cleanup removes temporary images.
func (b *Builder) Cleanup(tags ...string) {
	for _, tag := range tags {
		_ = b.client.RemoveImage(tag)
	}
}
