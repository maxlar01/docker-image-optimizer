package analyzer

import (
	"regexp"
	"strings"

	"github.com/maxlar/docker-image-optimizer/internal/models"
)

// Rule is an interface for Dockerfile analysis rules.
type Rule interface {
	ID() string
	Check(ctx *AnalysisContext) []models.Issue
}

// DefaultRules returns all built-in analysis rules.
func DefaultRules() []Rule {
	return []Rule{
		&LatestTagRule{},
		&MissingDockerignoreRule{},
		&TooManyLayersRule{},
		&AptGetRule{},
		&CacheNotCleanedRule{},
		&RootUserRule{},
		&CopyAllRule{},
		&NoMultiStageRule{},
		&PinVersionRule{},
		&CombineRunRule{},
		&WorkdirRule{},
		&HealthcheckRule{},
	}
}

// --- LatestTagRule ---

type LatestTagRule struct{}

func (r *LatestTagRule) ID() string { return "DIO001" }

func (r *LatestTagRule) Check(ctx *AnalysisContext) []models.Issue {
	var issues []models.Issue
	for _, img := range ctx.ParsedFile.BaseImages {
		if strings.HasSuffix(img, ":latest") || !strings.Contains(img, ":") {
			if img == "scratch" {
				continue
			}
			for _, inst := range ctx.ParsedFile.Instructions {
				if inst.Command == "FROM" && strings.Contains(strings.ToLower(inst.Args), img) {
					issues = append(issues, models.Issue{
						ID:          r.ID(),
						Severity:    models.SeverityHigh,
						Category:    "base-image",
						Title:       "Unpinned base image tag",
						Description: "Using 'latest' or untagged base image: " + img,
						Line:        inst.Line,
						Suggestion:  "Pin to a specific version, e.g., " + img + ":22.04",
						AutoFixable: false,
					})
					break
				}
			}
		}
	}
	return issues
}

// --- MissingDockerignoreRule ---

type MissingDockerignoreRule struct{}

func (r *MissingDockerignoreRule) ID() string { return "DIO002" }

func (r *MissingDockerignoreRule) Check(ctx *AnalysisContext) []models.Issue {
	if !ctx.MissingDockerignore {
		return nil
	}
	return []models.Issue{
		{
			ID:          r.ID(),
			Severity:    models.SeverityMedium,
			Category:    "best-practice",
			Title:       "Missing .dockerignore",
			Description: "No .dockerignore file found. This may cause unnecessary files to be included in the build context.",
			Suggestion:  "Create a .dockerignore file to exclude node_modules, .git, docs, etc.",
			AutoFixable: true,
		},
	}
}

// --- TooManyLayersRule ---

type TooManyLayersRule struct{}

func (r *TooManyLayersRule) ID() string { return "DIO003" }

func (r *TooManyLayersRule) Check(ctx *AnalysisContext) []models.Issue {
	// Count layer-creating instructions (RUN, COPY, ADD) in the final stage
	if len(ctx.ParsedFile.Stages) == 0 {
		return nil
	}

	finalStage := ctx.ParsedFile.Stages[len(ctx.ParsedFile.Stages)-1]
	layerCount := 0
	for _, inst := range finalStage.Instructions {
		switch inst.Command {
		case "RUN", "COPY", "ADD":
			layerCount++
		}
	}

	if layerCount > 15 {
		return []models.Issue{
			{
				ID:          r.ID(),
				Severity:    models.SeverityMedium,
				Category:    "optimization",
				Title:       "Too many layers",
				Description: "Final stage has " + string(rune(layerCount+'0')) + " layers. Consider combining RUN commands.",
				Suggestion:  "Combine related RUN commands using && to reduce layers.",
				AutoFixable: true,
			},
		}
	}
	return nil
}

// --- AptGetRule ---

type AptGetRule struct{}

func (r *AptGetRule) ID() string { return "DIO004" }

func (r *AptGetRule) Check(ctx *AnalysisContext) []models.Issue {
	var issues []models.Issue
	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command != "RUN" {
			continue
		}
		if strings.Contains(inst.Args, "apt-get install") && !strings.Contains(inst.Args, "--no-install-recommends") {
			issues = append(issues, models.Issue{
				ID:          r.ID(),
				Severity:    models.SeverityMedium,
				Category:    "optimization",
				Title:       "apt-get install without --no-install-recommends",
				Description: "apt-get install should use --no-install-recommends to avoid unnecessary packages.",
				Line:        inst.Line,
				Suggestion:  "Add --no-install-recommends to apt-get install commands.",
				AutoFixable: true,
			})
		}
	}
	return issues
}

// --- CacheNotCleanedRule ---

type CacheNotCleanedRule struct{}

func (r *CacheNotCleanedRule) ID() string { return "DIO005" }

func (r *CacheNotCleanedRule) Check(ctx *AnalysisContext) []models.Issue {
	var issues []models.Issue
	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command != "RUN" {
			continue
		}

		hasAptGet := strings.Contains(inst.Args, "apt-get install") || strings.Contains(inst.Args, "apt-get update")
		hasClean := strings.Contains(inst.Args, "rm -rf /var/lib/apt/lists") ||
			strings.Contains(inst.Args, "apt-get clean") ||
			strings.Contains(inst.Args, "apt-get autoremove")

		if hasAptGet && !hasClean {
			issues = append(issues, models.Issue{
				ID:          r.ID(),
				Severity:    models.SeverityMedium,
				Category:    "optimization",
				Title:       "Package manager cache not cleaned",
				Description: "apt-get commands should clean up cache in the same layer.",
				Line:        inst.Line,
				Suggestion:  "Add '&& rm -rf /var/lib/apt/lists/*' to the same RUN command.",
				AutoFixable: true,
			})
		}

		// Pip cache
		hasPip := strings.Contains(inst.Args, "pip install")
		hasPipNoCache := strings.Contains(inst.Args, "--no-cache-dir")
		if hasPip && !hasPipNoCache {
			issues = append(issues, models.Issue{
				ID:          r.ID() + "-pip",
				Severity:    models.SeverityLow,
				Category:    "optimization",
				Title:       "pip install without --no-cache-dir",
				Description: "pip install should use --no-cache-dir to reduce image size.",
				Line:        inst.Line,
				Suggestion:  "Add --no-cache-dir to pip install commands.",
				AutoFixable: true,
			})
		}
	}
	return issues
}

// --- RootUserRule ---

type RootUserRule struct{}

func (r *RootUserRule) ID() string { return "DIO006" }

func (r *RootUserRule) Check(ctx *AnalysisContext) []models.Issue {
	hasUserInstruction := false
	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command == "USER" {
			user := strings.TrimSpace(inst.Args)
			if user != "root" && user != "0" {
				hasUserInstruction = true
			}
		}
	}

	if !hasUserInstruction {
		return []models.Issue{
			{
				ID:          r.ID(),
				Severity:    models.SeverityHigh,
				Category:    "security",
				Title:       "Container runs as root",
				Description: "No USER instruction found. The container will run as root by default.",
				Suggestion:  "Add 'USER nonroot' or create a dedicated user.",
				AutoFixable: true,
			},
		}
	}
	return nil
}

// --- CopyAllRule ---

type CopyAllRule struct{}

func (r *CopyAllRule) ID() string { return "DIO007" }

func (r *CopyAllRule) Check(ctx *AnalysisContext) []models.Issue {
	var issues []models.Issue
	copyAllRegex := regexp.MustCompile(`^COPY\s+\.\s+\.`)
	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command == "COPY" && copyAllRegex.MatchString(inst.Raw) {
			issues = append(issues, models.Issue{
				ID:          r.ID(),
				Severity:    models.SeverityLow,
				Category:    "optimization",
				Title:       "Copying entire build context",
				Description: "COPY . . copies the entire build context. Consider copying only needed files.",
				Line:        inst.Line,
				Suggestion:  "Copy specific files/directories instead, or ensure .dockerignore is comprehensive.",
				AutoFixable: false,
			})
		}
	}
	return issues
}

// --- NoMultiStageRule ---

type NoMultiStageRule struct{}

func (r *NoMultiStageRule) ID() string { return "DIO008" }

func (r *NoMultiStageRule) Check(ctx *AnalysisContext) []models.Issue {
	if ctx.ParsedFile.HasMultiStage {
		return nil
	}

	// Only suggest multi-stage if there are build commands
	hasBuild := false
	buildIndicators := []string{"npm run build", "go build", "mvn", "gradle", "make", "cargo build", "dotnet publish", "gcc", "g++"}
	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command == "RUN" {
			for _, indicator := range buildIndicators {
				if strings.Contains(strings.ToLower(inst.Args), indicator) {
					hasBuild = true
					break
				}
			}
		}
	}

	if hasBuild {
		return []models.Issue{
			{
				ID:          r.ID(),
				Severity:    models.SeverityHigh,
				Category:    "optimization",
				Title:       "No multi-stage build",
				Description: "Build commands detected but no multi-stage build used. This includes build tools in the final image.",
				Suggestion:  "Use multi-stage builds to separate build and runtime stages.",
				AutoFixable: true,
			},
		}
	}
	return nil
}

// --- PinVersionRule ---

type PinVersionRule struct{}

func (r *PinVersionRule) ID() string { return "DIO009" }

func (r *PinVersionRule) Check(ctx *AnalysisContext) []models.Issue {
	var issues []models.Issue
	unpinnedRegex := regexp.MustCompile(`(apt-get install|apk add).*\s+\w+\s*($|&&)`)
	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command == "RUN" && unpinnedRegex.MatchString(inst.Args) {
			// Check for pinned versions (=, ==, >=)
			if !strings.Contains(inst.Args, "=") {
				issues = append(issues, models.Issue{
					ID:          r.ID(),
					Severity:    models.SeverityLow,
					Category:    "reproducibility",
					Title:       "Unpinned package versions",
					Description: "Package versions are not pinned, which may lead to non-reproducible builds.",
					Line:        inst.Line,
					Suggestion:  "Pin package versions, e.g., curl=7.88.1-10+deb12u5",
					AutoFixable: false,
				})
			}
		}
	}
	return issues
}

// --- CombineRunRule ---

type CombineRunRule struct{}

func (r *CombineRunRule) ID() string { return "DIO010" }

func (r *CombineRunRule) Check(ctx *AnalysisContext) []models.Issue {
	// Check for consecutive RUN commands that could be combined
	var issues []models.Issue
	consecutiveRuns := 0
	firstRunLine := 0

	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command == "RUN" {
			consecutiveRuns++
			if consecutiveRuns == 1 {
				firstRunLine = inst.Line
			}
			if consecutiveRuns >= 3 {
				issues = append(issues, models.Issue{
					ID:          r.ID(),
					Severity:    models.SeverityMedium,
					Category:    "optimization",
					Title:       "Consecutive RUN commands",
					Description: "Multiple consecutive RUN commands can be combined to reduce layers.",
					Line:        firstRunLine,
					Suggestion:  "Combine RUN commands using && to reduce image layers.",
					AutoFixable: true,
				})
				consecutiveRuns = 0
			}
		} else {
			consecutiveRuns = 0
		}
	}
	return issues
}

// --- WorkdirRule ---

type WorkdirRule struct{}

func (r *WorkdirRule) ID() string { return "DIO011" }

func (r *WorkdirRule) Check(ctx *AnalysisContext) []models.Issue {
	hasWorkdir := false
	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command == "WORKDIR" {
			hasWorkdir = true
			break
		}
	}
	if !hasWorkdir {
		return []models.Issue{
			{
				ID:          r.ID(),
				Severity:    models.SeverityLow,
				Category:    "best-practice",
				Title:       "No WORKDIR set",
				Description: "No WORKDIR instruction found. Files will be placed in / by default.",
				Suggestion:  "Add WORKDIR /app or similar to set a proper working directory.",
				AutoFixable: true,
			},
		}
	}
	return nil
}

// --- HealthcheckRule ---

type HealthcheckRule struct{}

func (r *HealthcheckRule) ID() string { return "DIO012" }

func (r *HealthcheckRule) Check(ctx *AnalysisContext) []models.Issue {
	for _, inst := range ctx.ParsedFile.Instructions {
		if inst.Command == "HEALTHCHECK" {
			return nil
		}
	}
	return []models.Issue{
		{
			ID:          r.ID(),
			Severity:    models.SeverityInfo,
			Category:    "best-practice",
			Title:       "No HEALTHCHECK defined",
			Description: "Consider adding a HEALTHCHECK instruction for container orchestration.",
			Suggestion:  "Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
			AutoFixable: false,
		},
	}
}
