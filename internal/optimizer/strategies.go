package optimizer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/maxlar/docker-image-optimizer/internal/models"
)

// Strategy is an interface for individual optimization strategies.
type Strategy interface {
	Name() string
	Analyze(ctx *OptimizationContext) *models.Optimization
	Apply(ctx *OptimizationContext) (string, error)
}

// --- BaseImageStrategy ---
// Suggests switching to smaller base images.

type BaseImageStrategy struct{}

func (s *BaseImageStrategy) Name() string { return "base-image-optimization" }

// slimAlternatives maps large base images to smaller alternatives.
var slimAlternatives = map[string]string{
	"ubuntu":         "ubuntu:22.04", // at least pin version
	"debian":         "debian:bookworm-slim",
	"node":           "node:lts-alpine",
	"python":         "python:3.12-slim",
	"golang":         "golang:1.22-alpine",
	"ruby":           "ruby:3.3-alpine",
	"php":            "php:8.3-alpine",
	"java":           "eclipse-temurin:21-jre-alpine",
	"openjdk":        "eclipse-temurin:21-jre-alpine",
	"nginx":          "nginx:alpine",
	"httpd":          "httpd:alpine",
	"postgres":       "postgres:16-alpine",
	"mysql":          "mysql:8.0",
	"redis":          "redis:alpine",
	"mongo":          "mongo:7.0",
	"centos":         "debian:bookworm-slim",
	"fedora":         "debian:bookworm-slim",
	"amazoncorretto": "amazoncorretto:21-alpine",
}

func (s *BaseImageStrategy) Analyze(ctx *OptimizationContext) *models.Optimization {
	lines := ctx.Lines
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "FROM") {
			continue
		}

		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		baseImage := strings.ToLower(parts[1])

		// Extract image name without tag
		imageName := baseImage
		if idx := strings.Index(baseImage, ":"); idx != -1 {
			imageName = baseImage[:idx]
		}

		// Already using slim/alpine/distroless? Skip.
		if strings.Contains(baseImage, "slim") ||
			strings.Contains(baseImage, "alpine") ||
			strings.Contains(baseImage, "distroless") ||
			baseImage == "scratch" {
			continue
		}

		if alt, ok := slimAlternatives[imageName]; ok {
			return &models.Optimization{
				ID:          "OPT-BASE",
				Category:    "base-image",
				Title:       "Use a smaller base image",
				Description: fmt.Sprintf("Replace '%s' with '%s' for a significantly smaller image.", baseImage, alt),
				Impact:      "50-80% size reduction",
				Priority:    1,
				AutoFixable: true,
			}
		}
	}
	return nil
}

func (s *BaseImageStrategy) Apply(ctx *OptimizationContext) (string, error) {
	content := ctx.CurrentContent
	lines := strings.Split(content, "\n")
	modified := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToUpper(trimmed), "FROM") {
			continue
		}

		parts := strings.Fields(trimmed)
		if len(parts) < 2 {
			continue
		}
		baseImage := strings.ToLower(parts[1])
		imageName := baseImage
		if idx := strings.Index(baseImage, ":"); idx != -1 {
			imageName = baseImage[:idx]
		}

		if strings.Contains(baseImage, "slim") ||
			strings.Contains(baseImage, "alpine") ||
			strings.Contains(baseImage, "distroless") ||
			baseImage == "scratch" {
			continue
		}

		if alt, ok := slimAlternatives[imageName]; ok {
			parts[1] = alt
			lines[i] = strings.Join(parts, " ")
			modified = true
			break // Only modify the first FROM for safety
		}
	}

	if !modified {
		return content, fmt.Errorf("no applicable base image change")
	}

	return strings.Join(lines, "\n"), nil
}

// --- CombineLayersStrategy ---

type CombineLayersStrategy struct{}

func (s *CombineLayersStrategy) Name() string { return "combine-layers" }

func (s *CombineLayersStrategy) Analyze(ctx *OptimizationContext) *models.Optimization {
	consecutiveRuns := 0
	for _, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "RUN ") {
			consecutiveRuns++
		} else if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			consecutiveRuns = 0
		}
	}

	if consecutiveRuns >= 2 {
		return &models.Optimization{
			ID:          "OPT-LAYERS",
			Category:    "layer-optimization",
			Title:       "Combine consecutive RUN commands",
			Description: "Multiple consecutive RUN commands can be merged to reduce layers.",
			Impact:      "10-20% size reduction",
			Priority:    3,
			AutoFixable: true,
		}
	}
	return nil
}

func (s *CombineLayersStrategy) Apply(ctx *OptimizationContext) (string, error) {
	lines := strings.Split(ctx.CurrentContent, "\n")
	var result []string
	var runBuffer []string
	inRun := false

	flushRuns := func() {
		if len(runBuffer) == 0 {
			return
		}
		if len(runBuffer) == 1 {
			result = append(result, "RUN "+runBuffer[0])
		} else {
			combined := "RUN " + runBuffer[0]
			for _, r := range runBuffer[1:] {
				combined += " && \\\n    " + r
			}
			result = append(result, combined)
		}
		runBuffer = nil
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(strings.ToUpper(trimmed), "RUN ") {
			cmd := strings.TrimSpace(trimmed[4:])
			// Remove trailing backslash continuation from individual commands
			cmd = strings.TrimSuffix(cmd, "\\")
			cmd = strings.TrimSpace(cmd)
			runBuffer = append(runBuffer, cmd)
			inRun = true
			continue
		}

		if inRun && (trimmed == "" || strings.HasPrefix(trimmed, "#")) {
			continue
		}

		if inRun {
			flushRuns()
			inRun = false
		}

		result = append(result, line)
	}

	flushRuns()

	return strings.Join(result, "\n"), nil
}

// --- MultiStageStrategy ---

type MultiStageStrategy struct{}

func (s *MultiStageStrategy) Name() string { return "multi-stage-build" }

func (s *MultiStageStrategy) Analyze(ctx *OptimizationContext) *models.Optimization {
	// Check if already using multi-stage
	fromCount := 0
	for _, line := range ctx.Lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FROM") {
			fromCount++
		}
	}
	if fromCount > 1 {
		return nil
	}

	// Check if there are build commands
	buildIndicators := []string{"npm run build", "go build", "mvn", "gradle", "make", "cargo build", "dotnet publish"}
	for _, line := range ctx.Lines {
		lower := strings.ToLower(line)
		for _, indicator := range buildIndicators {
			if strings.Contains(lower, indicator) {
				return &models.Optimization{
					ID:          "OPT-MULTISTAGE",
					Category:    "multi-stage",
					Title:       "Introduce multi-stage build",
					Description: "Build commands detected. Use multi-stage builds to exclude build tools from the final image.",
					Impact:      "40-70% size reduction",
					Priority:    1,
					AutoFixable: true,
				}
			}
		}
	}
	return nil
}

func (s *MultiStageStrategy) Apply(ctx *OptimizationContext) (string, error) {
	// Multi-stage transformation is complex and language-specific.
	// For auto-fix, we do a best-effort transformation.
	content := ctx.CurrentContent
	lines := strings.Split(content, "\n")

	// Detect the language/runtime
	lang := detectLanguage(lines)
	if lang == "" {
		return content, fmt.Errorf("cannot determine project language for multi-stage optimization")
	}

	template := getMultiStageTemplate(lang, lines)
	if template == "" {
		return content, fmt.Errorf("no multi-stage template available for %s", lang)
	}

	return template, nil
}

// --- CacheOptStrategy ---

type CacheOptStrategy struct{}

func (s *CacheOptStrategy) Name() string { return "cache-optimization" }

func (s *CacheOptStrategy) Analyze(ctx *OptimizationContext) *models.Optimization {
	// Check if COPY . . comes before dependency install
	copyAllLine := -1
	depInstallLine := -1
	depIndicators := []string{"npm install", "npm ci", "pip install", "go mod download", "bundle install", "cargo build"}

	for i, line := range ctx.Lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "COPY") && strings.Contains(trimmed, ". .") {
			if copyAllLine == -1 {
				copyAllLine = i
			}
		}
		for _, dep := range depIndicators {
			if strings.Contains(strings.ToLower(trimmed), dep) {
				depInstallLine = i
				break
			}
		}
	}

	if copyAllLine != -1 && depInstallLine != -1 && copyAllLine < depInstallLine {
		return &models.Optimization{
			ID:          "OPT-CACHE",
			Category:    "cache-optimization",
			Title:       "Reorder COPY for better cache utilization",
			Description: "Copy dependency files (package.json, go.mod, etc.) before source code for better Docker layer caching.",
			Impact:      "Faster rebuilds",
			Priority:    2,
		}
	}
	return nil
}

func (s *CacheOptStrategy) Apply(ctx *OptimizationContext) (string, error) {
	// This is complex and language-specific; return current content for now
	return ctx.CurrentContent, nil
}

// --- NonRootUserStrategy ---

type NonRootUserStrategy struct{}

func (s *NonRootUserStrategy) Name() string { return "non-root-user" }

func (s *NonRootUserStrategy) Analyze(ctx *OptimizationContext) *models.Optimization {
	for _, issue := range ctx.Analysis.Issues {
		if issue.ID == "DIO006" {
			return &models.Optimization{
				ID:          "OPT-USER",
				Category:    "security",
				Title:       "Add non-root user",
				Description: "Container runs as root. Add a non-root user for improved security.",
				Impact:      "Security improvement",
				Priority:    2,
				AutoFixable: true,
			}
		}
	}
	return nil
}

func (s *NonRootUserStrategy) Apply(ctx *OptimizationContext) (string, error) {
	lines := strings.Split(ctx.CurrentContent, "\n")

	// Find the last CMD or ENTRYPOINT
	insertIdx := len(lines) - 1
	for i := len(lines) - 1; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "CMD") || strings.HasPrefix(upper, "ENTRYPOINT") {
			insertIdx = i
			break
		}
	}

	// Check if USER already exists
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "USER") {
			return ctx.CurrentContent, nil
		}
	}

	// Insert USER instruction before CMD/ENTRYPOINT
	var result []string
	for i, line := range lines {
		if i == insertIdx {
			result = append(result,
				"# Run as non-root user for security",
				"RUN addgroup --system --gid 1001 appgroup && \\",
				"    adduser --system --uid 1001 --ingroup appgroup appuser",
				"USER appuser",
				"",
			)
		}
		result = append(result, line)
	}

	return strings.Join(result, "\n"), nil
}

// --- CleanupStrategy ---

type CleanupStrategy struct{}

func (s *CleanupStrategy) Name() string { return "cleanup" }

func (s *CleanupStrategy) Analyze(ctx *OptimizationContext) *models.Optimization {
	for _, issue := range ctx.Analysis.Issues {
		if issue.ID == "DIO005" {
			return &models.Optimization{
				ID:          "OPT-CLEANUP",
				Category:    "cleanup",
				Title:       "Clean package manager caches",
				Description: "Package manager caches are not cleaned, wasting space in the final image.",
				Impact:      "10-30% size reduction",
				Priority:    2,
				AutoFixable: true,
			}
		}
	}
	return nil
}

func (s *CleanupStrategy) Apply(ctx *OptimizationContext) (string, error) {
	content := ctx.CurrentContent

	// Add cleanup to apt-get commands
	aptGetPattern := regexp.MustCompile(`(apt-get install[^\n]+)`)
	content = aptGetPattern.ReplaceAllStringFunc(content, func(match string) string {
		if strings.Contains(match, "rm -rf /var/lib/apt/lists") {
			return match
		}
		return match + " && \\\n    rm -rf /var/lib/apt/lists/*"
	})

	// Add --no-install-recommends
	content = strings.ReplaceAll(content, "apt-get install ", "apt-get install --no-install-recommends ")
	content = strings.ReplaceAll(content, "--no-install-recommends --no-install-recommends", "--no-install-recommends")

	return content, nil
}

// --- WorkdirStrategy ---

type WorkdirStrategy struct{}

func (s *WorkdirStrategy) Name() string { return "workdir" }

func (s *WorkdirStrategy) Analyze(ctx *OptimizationContext) *models.Optimization {
	for _, issue := range ctx.Analysis.Issues {
		if issue.ID == "DIO011" {
			return &models.Optimization{
				ID:          "OPT-WORKDIR",
				Category:    "best-practice",
				Title:       "Set WORKDIR",
				Description: "No WORKDIR set. Files are placed in / by default.",
				Impact:      "Best practice",
				Priority:    4,
				AutoFixable: true,
			}
		}
	}
	return nil
}

func (s *WorkdirStrategy) Apply(ctx *OptimizationContext) (string, error) {
	lines := strings.Split(ctx.CurrentContent, "\n")

	// Check if WORKDIR already exists
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "WORKDIR") {
			return ctx.CurrentContent, nil
		}
	}

	var result []string

	inserted := false
	for _, line := range lines {
		result = append(result, line)
		trimmed := strings.TrimSpace(line)
		if !inserted && strings.HasPrefix(strings.ToUpper(trimmed), "FROM") {
			result = append(result, "WORKDIR /app")
			inserted = true
		}
	}

	return strings.Join(result, "\n"), nil
}

// --- Helpers ---

func detectLanguage(lines []string) string {
	for _, line := range lines {
		lower := strings.ToLower(line)
		switch {
		case strings.Contains(lower, "node") || strings.Contains(lower, "npm"):
			return "node"
		case strings.Contains(lower, "golang") || strings.Contains(lower, "go build"):
			return "go"
		case strings.Contains(lower, "python") || strings.Contains(lower, "pip"):
			return "python"
		case strings.Contains(lower, "ruby") || strings.Contains(lower, "gem"):
			return "ruby"
		case strings.Contains(lower, "java") || strings.Contains(lower, "mvn") || strings.Contains(lower, "gradle"):
			return "java"
		case strings.Contains(lower, "rust") || strings.Contains(lower, "cargo"):
			return "rust"
		case strings.Contains(lower, "dotnet"):
			return "dotnet"
		}
	}
	return ""
}
