package analyzer

import (
	"strings"
	"testing"

	"github.com/maxlar/docker-image-optimizer/internal/models"
)

func TestAnalyzeContent_LatestTag(t *testing.T) {
	content := `FROM ubuntu
RUN apt-get update
`
	a := New()
	result, err := a.AnalyzeContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.ID == "DIO001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DIO001 (unpinned base image) issue")
	}
}

func TestAnalyzeContent_RootUser(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN echo hello
`
	a := New()
	result, err := a.AnalyzeContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.ID == "DIO006" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DIO006 (root user) issue")
	}
}

func TestAnalyzeContent_GoodDockerfile(t *testing.T) {
	content := `FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM gcr.io/distroless/nodejs20
WORKDIR /app
COPY --from=builder /app/dist .
USER nonroot
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["index.js"]
`
	a := New()
	result, err := a.AnalyzeContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Score < 70 {
		t.Errorf("expected score >= 70 for a good Dockerfile, got %d", result.Score)
		for _, issue := range result.Issues {
			t.Logf("  issue: %s - %s", issue.ID, issue.Title)
		}
	}
}

func TestAnalyzeContent_AptGetNoRecommends(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install curl
USER nobody
WORKDIR /app
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
`
	a := New()
	result, err := a.AnalyzeContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.ID == "DIO004" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DIO004 (apt-get --no-install-recommends) issue")
	}
}

func TestAnalyzeContent_CacheNotCleaned(t *testing.T) {
	content := `FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends curl
USER nobody
WORKDIR /app
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
`
	a := New()
	result, err := a.AnalyzeContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.ID == "DIO005" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DIO005 (cache not cleaned) issue")
	}
}

func TestAnalyzeContent_NoMultiStage(t *testing.T) {
	content := `FROM golang:1.22
WORKDIR /app
COPY . .
RUN go build -o main .
USER nobody
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["./main"]
`
	a := New()
	result, err := a.AnalyzeContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, issue := range result.Issues {
		if issue.ID == "DIO008" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected DIO008 (no multi-stage) issue")
	}
}

func TestParseDockerfile(t *testing.T) {
	lines := strings.Split(`FROM node:20-alpine AS builder
WORKDIR /app
COPY . .
RUN npm ci && npm run build

FROM gcr.io/distroless/nodejs20
WORKDIR /app
COPY --from=builder /app/dist .
CMD ["index.js"]
`, "\n")

	pdf := parseDockerfile(lines)

	if !pdf.HasMultiStage {
		t.Error("expected HasMultiStage to be true")
	}
	if len(pdf.Stages) != 2 {
		t.Errorf("expected 2 stages, got %d", len(pdf.Stages))
	}
	if len(pdf.BaseImages) != 2 {
		t.Errorf("expected 2 base images, got %d", len(pdf.BaseImages))
	}
	if pdf.BaseImages[0] != "node:20-alpine" {
		t.Errorf("expected base image 'node:20-alpine', got '%s'", pdf.BaseImages[0])
	}
}

func TestMapHadolintLevel(t *testing.T) {
	tests := []struct {
		level    string
		expected string
	}{
		{"error", "high"},
		{"warning", "medium"},
		{"info", "low"},
		{"style", "info"},
		{"unknown", "low"},
	}
	for _, tt := range tests {
		got := mapHadolintLevel(tt.level)
		if string(got) != tt.expected {
			t.Errorf("mapHadolintLevel(%q) = %q, want %q", tt.level, got, tt.expected)
		}
	}
}

func TestMergeHadolintIssues_Dedup(t *testing.T) {
	dioIssues := []models.Issue{
		{ID: "DIO001", Line: 1, Category: "base-image", Title: "Unpinned tag"},
	}
	hadolintIssues := []models.Issue{
		{ID: "HL-DL3007", Line: 1, Category: "hadolint", Title: "DL3007: Using latest is prone to errors"},
		{ID: "HL-DL3042", Line: 5, Category: "hadolint", Title: "DL3042: Avoid cache directory"},
	}
	merged := mergeHadolintIssues(dioIssues, hadolintIssues)

	// DL3007 on line 1 should be deduplicated (DIO001 already covers base-image on line 1)
	// DL3042 on line 5 should be kept
	if len(merged) != 2 {
		t.Errorf("expected 2 merged issues, got %d", len(merged))
		for _, i := range merged {
			t.Logf("  %s line=%d cat=%s", i.ID, i.Line, i.Category)
		}
	}
}

func TestMergeHadolintIssues_NoOverlap(t *testing.T) {
	dioIssues := []models.Issue{
		{ID: "DIO006", Line: 5, Category: "security", Title: "Root user"},
	}
	hadolintIssues := []models.Issue{
		{ID: "HL-DL3007", Line: 1, Category: "hadolint", Title: "Using latest"},
	}
	merged := mergeHadolintIssues(dioIssues, hadolintIssues)

	if len(merged) != 2 {
		t.Errorf("expected 2 issues (no overlap), got %d", len(merged))
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 80); got != "short" {
		t.Errorf("expected 'short', got %q", got)
	}
	long := strings.Repeat("a", 100)
	got := truncate(long, 20)
	if len(got) != 20 {
		t.Errorf("expected length 20, got %d", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("expected truncated string to end with ...")
	}
}

func TestNewWithOptions_HadolintDisabled(t *testing.T) {
	a := NewWithOptions(false)
	if a.useHadolint {
		t.Error("expected hadolint to be disabled")
	}
}
