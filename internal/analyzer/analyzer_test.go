package analyzer

import (
	"strings"
	"testing"
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
