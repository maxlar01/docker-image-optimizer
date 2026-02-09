// Package docker provides a wrapper around Docker CLI commands for
// building images, inspecting them, and extracting metrics.
package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/maxlar/docker-image-optimizer/internal/models"
)

// Client wraps Docker CLI operations.
type Client struct {
	dockerBin string
}

// NewClient creates a new Docker client, locating the docker binary.
func NewClient() (*Client, error) {
	bin, err := exec.LookPath("docker")
	if err != nil {
		return nil, fmt.Errorf("docker not found in PATH: %w", err)
	}
	return &Client{dockerBin: bin}, nil
}

// Build builds a Docker image from a Dockerfile and returns metrics.
func (c *Client) Build(dockerfilePath, contextDir, tag string) (*models.ImageMetrics, error) {
	start := time.Now()

	args := []string{"build", "-f", dockerfilePath, "-t", tag, contextDir}
	cmd := exec.Command(c.dockerBin, args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker build failed: %w\nstderr: %s", err, stderr.String())
	}

	elapsed := time.Since(start).Seconds()

	metrics, err := c.Inspect(tag)
	if err != nil {
		return nil, err
	}
	metrics.BuildTime = elapsed

	return metrics, nil
}

// dockerInspectJSON is the subset of docker inspect output we care about.
type dockerInspectJSON struct {
	ID           string    `json:"Id"`
	Created      time.Time `json:"Created"`
	Size         int64     `json:"Size"`
	Architecture string    `json:"Architecture"`
	Os           string    `json:"Os"`
	RootFS       struct {
		Layers []string `json:"Layers"`
	} `json:"RootFS"`
	Config struct {
		Image  string   `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// Inspect returns metrics for an existing Docker image.
func (c *Client) Inspect(imageRef string) (*models.ImageMetrics, error) {
	cmd := exec.Command(c.dockerBin, "inspect", "--type=image", imageRef)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker inspect failed: %w\nstderr: %s", err, stderr.String())
	}

	var results []dockerInspectJSON
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		return nil, fmt.Errorf("failed to parse docker inspect output: %w", err)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no image found for %s", imageRef)
	}

	img := results[0]
	return &models.ImageMetrics{
		ImageName:    imageRef,
		ImageID:      img.ID,
		Size:         img.Size,
		SizeHuman:    humanSize(img.Size),
		Layers:       len(img.RootFS.Layers),
		CreatedAt:    img.Created,
		Architecture: img.Architecture,
		OS:           img.Os,
	}, nil
}

// ImageExists checks if a Docker image exists locally.
func (c *Client) ImageExists(imageRef string) bool {
	cmd := exec.Command(c.dockerBin, "image", "inspect", imageRef)
	return cmd.Run() == nil
}

// RemoveImage removes a Docker image.
func (c *Client) RemoveImage(imageRef string) error {
	cmd := exec.Command(c.dockerBin, "rmi", "-f", imageRef)
	return cmd.Run()
}

// GetHistory returns the image history (layers).
func (c *Client) GetHistory(imageRef string) (string, error) {
	cmd := exec.Command(c.dockerBin, "history", "--no-trunc", imageRef)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return stdout.String(), nil
}

// humanSize converts bytes to a human-readable string.
func humanSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1fGB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.1fMB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.1fKB", float64(bytes)/float64(KB))
	default:
		return strconv.FormatInt(bytes, 10) + "B"
	}
}

// ParseImageSize parses a human-readable size string into bytes.
func ParseImageSize(size string) (int64, error) {
	size = strings.TrimSpace(strings.ToUpper(size))
	multiplier := int64(1)

	switch {
	case strings.HasSuffix(size, "GB"):
		multiplier = 1024 * 1024 * 1024
		size = strings.TrimSuffix(size, "GB")
	case strings.HasSuffix(size, "MB"):
		multiplier = 1024 * 1024
		size = strings.TrimSuffix(size, "MB")
	case strings.HasSuffix(size, "KB"):
		multiplier = 1024
		size = strings.TrimSuffix(size, "KB")
	case strings.HasSuffix(size, "B"):
		size = strings.TrimSuffix(size, "B")
	}

	val, err := strconv.ParseFloat(strings.TrimSpace(size), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %s", size)
	}

	return int64(val * float64(multiplier)), nil
}
