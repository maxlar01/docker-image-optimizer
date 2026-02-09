.PHONY: build test lint clean install run-analyze run-optimize run-pipeline

# Variables
BINARY_NAME=dio
BUILD_DIR=bin
VERSION?=0.1.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)"

# Build
build:
	@echo "🔨 Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/dio
	@echo "✅ Built: $(BUILD_DIR)/$(BINARY_NAME)"

# Install globally
install:
	go install $(LDFLAGS) ./cmd/dio

# Test
test:
	@echo "🧪 Running tests..."
	go test -v -race -coverprofile=coverage.out ./...
	@echo "✅ Tests passed"

# Test with coverage report
test-cover: test
	go tool cover -html=coverage.out -o coverage.html
	@echo "📊 Coverage report: coverage.html"

# Lint
lint:
	@echo "🔍 Linting..."
	@which golangci-lint > /dev/null 2>&1 || (echo "Install golangci-lint: https://golangci-lint.run/welcome/install/" && exit 1)
	golangci-lint run ./...
	@echo "✅ Lint passed"

# Clean
clean:
	@echo "🧹 Cleaning..."
	rm -rf $(BUILD_DIR) coverage.out coverage.html reports/
	@echo "✅ Clean"

# Run examples
run-analyze: build
	@echo ""
	$(BUILD_DIR)/$(BINARY_NAME) analyze testdata/Dockerfile.sample

run-optimize: build
	@echo ""
	$(BUILD_DIR)/$(BINARY_NAME) optimize testdata/Dockerfile.sample --mode autofix

run-pipeline: build
	@echo ""
	$(BUILD_DIR)/$(BINARY_NAME) run testdata/Dockerfile.sample --skip-scan --skip-build

# Cross-compile
build-all:
	@echo "🔨 Cross-compiling..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/dio
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/dio
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/dio
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/dio
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/dio
	@echo "✅ Cross-compiled to $(BUILD_DIR)/"

# Help
help:
	@echo "Docker Image Optimizer (DIO) - Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  build          Build the binary"
	@echo "  install        Install globally via go install"
	@echo "  test           Run tests with race detection"
	@echo "  test-cover     Run tests and generate HTML coverage report"
	@echo "  lint           Run golangci-lint"
	@echo "  clean          Remove build artifacts"
	@echo "  run-analyze    Build and analyze sample Dockerfile"
	@echo "  run-optimize   Build and optimize sample Dockerfile"
	@echo "  run-pipeline   Build and run full pipeline on sample"
	@echo "  build-all      Cross-compile for all platforms"
	@echo "  help           Show this help"
