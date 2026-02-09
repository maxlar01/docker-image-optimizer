<p align="center">
  <h1 align="center">🐳 Docker Image Optimizer (DIO)</h1>
  <p align="center">
    <em>Lint · Scan · Optimize · Enforce — for Docker images</em>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#commands">Commands</a> •
    <a href="#pipeline">Pipeline</a> •
    <a href="#policy">Policy</a> •
    <a href="#ci-integration">CI Integration</a>
  </p>
</p>

---

Built an automated Docker Image Optimization pipeline that reduced image sizes by up to 85%, eliminated critical CVEs, and enforced security best practices using policy-as-code in CI/CD pipelines.

**DIO** is an automated pipeline that analyzes Docker images, suggests optimizations, reduces image sizes, and enforces security best practices. Think of it as **lint + security scan + optimizer + policy enforcer for Docker images**.

## ✨ Features

| Component | Description |
|-----------|-------------|
| 🔍 **Dockerfile Analyzer** | Static analysis with 12+ built-in rules detecting anti-patterns and inefficiencies |
| ⚡ **Optimizer Engine** | 7 optimization strategies including base image switching, multi-stage builds, layer combining |
| 🔒 **Security Scanner** | Trivy/Grype integration for CVE detection |
| 📋 **Policy Enforcer** | YAML-defined rules for image size, CVE limits, non-root requirements |
| 📊 **Reporter** | Markdown + JSON reports, PR comment integration |
| 🚀 **CI Pipeline** | GitHub Actions workflow with automated analysis on every PR |

## Installation

### From source

```bash
git clone https://github.com/maxlar/docker-image-optimizer.git
cd docker-image-optimizer
make build
```

The binary will be at `bin/dio`.

### Go install

```bash
go install github.com/maxlar/docker-image-optimizer/cmd/dio@latest
```

## Quick Start

```bash
# Analyze a Dockerfile for issues
dio analyze Dockerfile

# Suggest optimizations
dio optimize Dockerfile

# Auto-fix optimizations and write Dockerfile.optimized
dio optimize Dockerfile --mode autofix

# Run the full pipeline
dio run Dockerfile --skip-scan --skip-build

# Check against policy
dio policy Dockerfile --policy policies/default.yaml
```

## Commands

### `dio analyze`

Static analysis of a Dockerfile. Checks for:

- ❌ Unpinned base image tags (`:latest`)
- ❌ Missing `.dockerignore`
- ❌ Too many layers
- ❌ `apt-get` without `--no-install-recommends`
- ❌ Package cache not cleaned
- ❌ Running as root
- ❌ Copying entire build context (`COPY . .`)
- ❌ Missing multi-stage build
- ❌ Unpinned package versions
- ❌ Consecutive RUN commands
- ❌ No WORKDIR set
- ❌ No HEALTHCHECK defined

```bash
dio analyze Dockerfile
dio analyze Dockerfile --format json
```

### `dio optimize`

Analyzes and optimizes Dockerfiles using 7 strategies:

| Strategy | Description | Impact |
|----------|-------------|--------|
| Base Image | Switch to alpine/slim/distroless variants | 50-80% size reduction |
| Combine Layers | Merge consecutive RUN commands | 10-20% reduction |
| Multi-Stage Build | Separate build and runtime stages | 40-70% reduction |
| Cache Optimization | Reorder COPY for better cache hits | Faster rebuilds |
| Non-Root User | Add USER instruction | Security improvement |
| Cleanup | Clean package manager caches | 10-30% reduction |
| WORKDIR | Set proper working directory | Best practice |

**Modes:**

- `suggest` (default) — shows recommendations only
- `autofix` — applies changes and writes `Dockerfile.optimized`

```bash
dio optimize Dockerfile --mode suggest
dio optimize Dockerfile --mode autofix --output Dockerfile.prod
```

### `dio scan`

Security vulnerability scanning (requires [Trivy](https://aquasecurity.github.io/trivy/) or [Grype](https://github.com/anchore/grype)):

```bash
dio scan myapp:latest
dio scan myapp:latest --scanner trivy
```

### `dio policy`

Enforce policy rules against a Dockerfile:

```bash
dio policy Dockerfile
dio policy Dockerfile --policy my-policy.yaml
```

### `dio run`

Full pipeline — analyze → optimize → build → scan → policy → report:

```bash
dio run Dockerfile
dio run Dockerfile --mode autofix --policy policies/default.yaml
dio run Dockerfile --skip-scan --skip-build --output reports
```

## Pipeline

```
Git Repo
  │
  ▼
CI Pipeline (GitHub Actions)
  │
  ├──▶ Dockerfile Analyzer (static analysis)
  │
  ├──▶ Image Build (baseline metrics)
  │
  ├──▶ Security Scanner (Trivy/Grype)
  │
  ├──▶ Optimizer Engine (7 strategies)
  │
  ├──▶ Rebuild Optimized Image
  │
  ├──▶ Policy Gate (pass/fail)
  │
  ▼
Report + Artifacts (Markdown/JSON)
```

## Policy

Define rules in YAML:

```yaml
# policies/default.yaml
max_image_size: "500MB"
forbid_latest_tag: true
require_non_root: true
max_critical_cves: 0
max_high_cves: 5
max_layers: 20
min_score: 50
```

The pipeline **fails** if any rule is violated — perfect for CI gate enforcement.

## CI Integration

DIO ships with a GitHub Actions workflow (`.github/workflows/dio.yml`) that:

1. Builds and tests DIO
2. Analyzes your Dockerfile
3. Runs the optimization pipeline
4. Posts a report as a PR comment
5. Fails the pipeline on policy violations

### Example PR Comment

```
✅ Image optimized successfully

Size reduced: 1.2GB → 180MB (-85%)
Critical CVEs: 42 → 0
Recommendations applied:
✔ Multi-stage build
✔ Distroless base
✔ Non-root user
```

## Project Structure

```
docker-image-optimizer/
├── cmd/dio/              # CLI entrypoint
│   └── main.go
├── internal/
│   ├── analyzer/         # Dockerfile static analysis + rules
│   ├── builder/          # Docker build + metrics collection
│   ├── scanner/          # Trivy/Grype security scanning
│   ├── optimizer/        # Core optimization engine + strategies
│   ├── policy/           # Policy enforcement (YAML rules)
│   ├── reporter/         # Markdown + JSON report generation
│   └── models/           # Shared types
├── pkg/docker/           # Docker CLI wrapper
├── policies/             # Default policy config
├── testdata/             # Sample Dockerfiles
├── .github/workflows/    # CI pipeline
├── Makefile              # Build automation
└── go.mod
```

## Tech Stack

| Area | Technology |
|------|-----------|
| Language | Go |
| CLI | Cobra |
| CI | GitHub Actions |
| Image Build | Docker / BuildKit |
| Analysis | Custom rules engine + Hadolint |
| Security | Trivy / Grype |
| Policy | YAML-based rules engine |
| Output | Markdown + JSON |

## Development

```bash
# Build
make build

# Run tests
make test

# Run with sample Dockerfile
make run-analyze
make run-optimize
make run-pipeline

# Cross-compile for all platforms
make build-all
```

## Author

**Moustafa Rakha (Maxlar)**

## License

MIT License — see [LICENSE](LICENSE) for details.
