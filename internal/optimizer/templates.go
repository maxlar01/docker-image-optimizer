package optimizer

import (
	"strings"
)

// getMultiStageTemplate returns a multi-stage Dockerfile template for the given language.
// It extracts relevant information from the original Dockerfile lines.
func getMultiStageTemplate(lang string, originalLines []string) string {
	switch lang {
	case "node":
		return nodeTemplate(originalLines)
	case "go":
		return goTemplate(originalLines)
	case "python":
		return pythonTemplate(originalLines)
	case "rust":
		return rustTemplate(originalLines)
	case "java":
		return javaTemplate(originalLines)
	default:
		return ""
	}
}

func nodeTemplate(lines []string) string {
	nodeVersion := "20"
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FROM") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && strings.Contains(strings.ToLower(parts[1]), "node") {
				img := parts[1]
				if idx := strings.Index(img, ":"); idx != -1 {
					tag := img[idx+1:]
					if tag != "" && tag != "latest" {
						nodeVersion = strings.Split(tag, "-")[0]
					}
				}
			}
		}
	}

	return `# Stage 1: Build
FROM node:` + nodeVersion + `-alpine AS builder
WORKDIR /app

# Copy dependency files first for better caching
COPY package*.json ./
RUN npm ci --only=production

# Copy source and build
COPY . .
RUN npm run build

# Stage 2: Production
FROM node:` + nodeVersion + `-alpine AS production
WORKDIR /app

# Copy built artifacts
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./

# Security: run as non-root
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 --ingroup nodejs nextjs
USER nextjs

EXPOSE 3000
CMD ["node", "dist/index.js"]
`
}

func goTemplate(lines []string) string {
	goVersion := "1.22"
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FROM") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && strings.Contains(strings.ToLower(parts[1]), "golang") {
				img := parts[1]
				if idx := strings.Index(img, ":"); idx != -1 {
					tag := img[idx+1:]
					if tag != "" && tag != "latest" {
						goVersion = strings.Split(tag, "-")[0]
					}
				}
			}
		}
	}

	return `# Stage 1: Build
FROM golang:` + goVersion + `-alpine AS builder
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy dependency files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/server .

# Stage 2: Production (distroless for minimal attack surface)
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /app/server .

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/server"]
`
}

func pythonTemplate(lines []string) string {
	pythonVersion := "3.12"
	for _, line := range lines {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FROM") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && strings.Contains(strings.ToLower(parts[1]), "python") {
				img := parts[1]
				if idx := strings.Index(img, ":"); idx != -1 {
					tag := img[idx+1:]
					if tag != "" && tag != "latest" {
						pythonVersion = strings.Split(tag, "-")[0]
					}
				}
			}
		}
	}

	return `# Stage 1: Build
FROM python:` + pythonVersion + `-slim AS builder
WORKDIR /app

# Install build dependencies
RUN apt-get update && \
    apt-get install --no-install-recommends -y build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Production
FROM python:` + pythonVersion + `-slim AS production
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Security: run as non-root
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser
USER appuser

EXPOSE 8000
CMD ["python", "main.py"]
`
}

func rustTemplate(lines []string) string {
	return `# Stage 1: Build
FROM rust:1.77-alpine AS builder
WORKDIR /app

RUN apk add --no-cache musl-dev

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Build actual application
COPY . .
RUN cargo build --release

# Stage 2: Production
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app

COPY --from=builder /app/target/release/app .

USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/app"]
`
}

func javaTemplate(lines []string) string {
	return `# Stage 1: Build
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN apk add --no-cache maven && \
    mvn clean package -DskipTests

# Stage 2: Production
FROM eclipse-temurin:21-jre-alpine AS production
WORKDIR /app

COPY --from=builder /app/target/*.jar app.jar

# Security: run as non-root
RUN addgroup --system --gid 1001 appgroup && \
    adduser --system --uid 1001 --ingroup appgroup appuser
USER appuser

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
`
}
