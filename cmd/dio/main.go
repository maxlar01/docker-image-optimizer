// DIO (Docker Image Optimizer) — an automated pipeline that analyzes Docker images,
// suggests optimizations, reduces image sizes, and enforces security best practices.
//
// Author: Moustafa Rakha (Maxlar)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/maxlar/docker-image-optimizer/internal/analyzer"
	"github.com/maxlar/docker-image-optimizer/internal/builder"
	"github.com/maxlar/docker-image-optimizer/internal/models"
	"github.com/maxlar/docker-image-optimizer/internal/optimizer"
	"github.com/maxlar/docker-image-optimizer/internal/policy"
	"github.com/maxlar/docker-image-optimizer/internal/reporter"
	"github.com/maxlar/docker-image-optimizer/internal/scanner"
)

var (
	version = "0.1.0"
	commit  = "dev"
)

func main() {
	root := &cobra.Command{
		Use:     "dio",
		Short:   "Docker Image Optimizer — lint, scan, optimize, enforce",
		Long:    `DIO is an automated pipeline that analyzes Docker images, suggests optimizations, reduces image sizes, and enforces security best practices.`,
		Version: fmt.Sprintf("%s (%s)", version, commit),
	}

	root.AddCommand(
		newAnalyzeCmd(),
		newOptimizeCmd(),
		newScanCmd(),
		newPolicyCmd(),
		newRunCmd(),
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// --- analyze command ---

func newAnalyzeCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "analyze [Dockerfile]",
		Short: "Analyze a Dockerfile for issues and best practices",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dockerfilePath := args[0]
			return runAnalyze(dockerfilePath, outputFormat)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, json, markdown")
	return cmd
}

func runAnalyze(dockerfilePath, format string) error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	bold.Println("🔍 Analyzing Dockerfile:", dockerfilePath)
	fmt.Println()

	a := analyzer.New()
	result, err := a.Analyze(dockerfilePath)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	if format == "json" {
		rep := reporter.New(".")
		output, err := rep.Generate(&models.PipelineResult{
			Timestamp:  time.Now(),
			Dockerfile: dockerfilePath,
			Analysis:   result,
		}, reporter.FormatJSON)
		if err != nil {
			return err
		}
		fmt.Println(output)
		return nil
	}

	// Text output
	bold.Printf("Score: %d/100\n\n", result.Score)

	if len(result.Issues) == 0 {
		green.Println("✅ No issues found!")
		return nil
	}

	bold.Printf("Found %d issue(s):\n\n", len(result.Issues))

	for _, issue := range result.Issues {
		var c *color.Color
		switch issue.Severity {
		case models.SeverityCritical:
			c = red
		case models.SeverityHigh:
			c = color.New(color.FgHiRed)
		case models.SeverityMedium:
			c = yellow
		case models.SeverityLow:
			c = color.New(color.FgCyan)
		default:
			c = color.New(color.FgWhite)
		}

		c.Printf("  [%s] %s (%s)\n", issue.Severity, issue.Title, issue.ID)
		if issue.Line > 0 {
			fmt.Printf("         Line: %d\n", issue.Line)
		}
		fmt.Printf("         %s\n", issue.Description)
		if issue.Suggestion != "" {
			green.Printf("         💡 %s\n", issue.Suggestion)
		}
		fmt.Println()
	}

	return nil
}

// --- optimize command ---

func newOptimizeCmd() *cobra.Command {
	var (
		mode       string
		outputFile string
	)

	cmd := &cobra.Command{
		Use:   "optimize [Dockerfile]",
		Short: "Optimize a Dockerfile for size, speed, and security",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOptimize(args[0], mode, outputFile)
		},
	}

	cmd.Flags().StringVarP(&mode, "mode", "m", "suggest", "Mode: suggest or autofix")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file for optimized Dockerfile (autofix mode)")
	return cmd
}

func runOptimize(dockerfilePath, mode, outputFile string) error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)

	bold.Println("⚡ Optimizing Dockerfile:", dockerfilePath)
	fmt.Println()

	optMode := optimizer.ModeSuggest
	if mode == "autofix" {
		optMode = optimizer.ModeAutoFix
	}

	opt := optimizer.New(optMode)
	result, err := opt.Optimize(dockerfilePath)
	if err != nil {
		return fmt.Errorf("optimization failed: %w", err)
	}

	if len(result.Optimizations) == 0 {
		green.Println("✅ No optimizations needed!")
		return nil
	}

	bold.Printf("Found %d optimization(s):\n\n", len(result.Optimizations))

	for _, o := range result.Optimizations {
		status := "💡"
		if o.Applied {
			status = "✅"
		}
		fmt.Printf("  %s [P%d] %s\n", status, o.Priority, o.Title)
		fmt.Printf("     %s\n", o.Description)
		fmt.Printf("     Impact: %s\n\n", o.Impact)
	}

	if optMode == optimizer.ModeAutoFix && result.OptimizedDockerfile != result.OriginalDockerfile {
		if outputFile == "" {
			dir := filepath.Dir(dockerfilePath)
			outputFile = filepath.Join(dir, "Dockerfile.optimized")
		}

		if err := opt.WriteOptimized(result, outputFile); err != nil {
			return fmt.Errorf("failed to write optimized Dockerfile: %w", err)
		}
		green.Printf("✅ Optimized Dockerfile written to: %s\n", outputFile)
		fmt.Printf("   Estimated reduction: %s\n", result.EstimatedReduction)
	}

	return nil
}

// --- scan command ---

func newScanCmd() *cobra.Command {
	var scannerType string

	cmd := &cobra.Command{
		Use:   "scan [image]",
		Short: "Scan a Docker image for security vulnerabilities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(args[0], scannerType)
		},
	}

	cmd.Flags().StringVarP(&scannerType, "scanner", "s", "auto", "Scanner: trivy, grype, or auto")
	return cmd
}

func runScan(imageRef, scannerType string) error {
	bold := color.New(color.Bold)
	red := color.New(color.FgRed)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	bold.Println("🔒 Scanning image:", imageRef)
	fmt.Println()

	// Import scanner package dynamically to avoid the import if not used
	// For now, just show that the scan would happen
	_ = red
	_ = yellow
	_ = green

	fmt.Println("Security scanning requires trivy or grype to be installed.")
	fmt.Println("Install trivy: https://aquasecurity.github.io/trivy/")
	fmt.Println("Install grype: https://github.com/anchore/grype")
	fmt.Println()
	fmt.Printf("To scan manually:\n")
	fmt.Printf("  trivy image %s\n", imageRef)
	fmt.Printf("  grype %s\n", imageRef)

	return nil
}

// --- policy command ---

func newPolicyCmd() *cobra.Command {
	var policyFile string

	cmd := &cobra.Command{
		Use:   "policy [Dockerfile]",
		Short: "Check a Dockerfile against policy rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPolicy(args[0], policyFile)
		},
	}

	cmd.Flags().StringVarP(&policyFile, "policy", "p", "", "Path to policy YAML file")
	return cmd
}

func runPolicy(dockerfilePath, policyFile string) error {
	bold := color.New(color.Bold)

	bold.Println("📋 Evaluating policy for:", dockerfilePath)
	fmt.Println()

	// Load policy
	var config *policy.Config
	if policyFile != "" {
		var err error
		config, err = policy.LoadConfig(policyFile)
		if err != nil {
			return fmt.Errorf("failed to load policy: %w", err)
		}
	} else {
		config = policy.DefaultConfig()
	}

	// Run analysis
	a := analyzer.New()
	analysis, err := a.Analyze(dockerfilePath)
	if err != nil {
		return err
	}

	result := &models.PipelineResult{
		Timestamp:  time.Now(),
		Dockerfile: dockerfilePath,
		Analysis:   analysis,
	}

	// Evaluate policy
	enforcer := policy.NewEnforcer(config)
	policyResult := enforcer.Evaluate(result)

	fmt.Println(policy.FormatPolicyStatus(policyResult))

	if !policyResult.Passed {
		os.Exit(1)
	}

	return nil
}

// --- run command (full pipeline) ---

func newRunCmd() *cobra.Command {
	var (
		mode       string
		policyFile string
		outputDir  string
		skipScan   bool
		skipBuild  bool
	)

	cmd := &cobra.Command{
		Use:   "run [Dockerfile]",
		Short: "Run the full DIO pipeline: analyze → optimize → scan → policy → report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPipeline(args[0], mode, policyFile, outputDir, skipScan, skipBuild)
		},
	}

	cmd.Flags().StringVarP(&mode, "mode", "m", "suggest", "Mode: suggest or autofix")
	cmd.Flags().StringVarP(&policyFile, "policy", "p", "", "Path to policy YAML file")
	cmd.Flags().StringVarP(&outputDir, "output", "o", "reports", "Output directory for reports")
	cmd.Flags().BoolVar(&skipScan, "skip-scan", false, "Skip security scanning")
	cmd.Flags().BoolVar(&skipBuild, "skip-build", false, "Skip image building")
	return cmd
}

func runPipeline(dockerfilePath, mode, policyFile, outputDir string, skipScan, skipBuild bool) error {
	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	bold.Println("🐳 Docker Image Optimizer — Full Pipeline")
	bold.Println("==========================================")
	fmt.Println()

	result := &models.PipelineResult{
		Timestamp:  time.Now(),
		Dockerfile: dockerfilePath,
	}

	// Step 1: Analyze
	bold.Println("Step 1/5: 🔍 Analyzing Dockerfile...")
	a := analyzer.New()
	analysis, err := a.Analyze(dockerfilePath)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}
	result.Analysis = analysis
	fmt.Printf("  Score: %d/100, Issues: %d\n\n", analysis.Score, len(analysis.Issues))

	// Step 2: Optimize
	bold.Println("Step 2/5: ⚡ Optimizing...")
	optMode := optimizer.ModeSuggest
	if mode == "autofix" {
		optMode = optimizer.ModeAutoFix
	}

	opt := optimizer.New(optMode)
	optResult, err := opt.Optimize(dockerfilePath)
	if err != nil {
		return fmt.Errorf("optimization failed: %w", err)
	}
	result.Optimization = optResult
	fmt.Printf("  Optimizations: %d\n", len(optResult.Optimizations))

	if optMode == optimizer.ModeAutoFix && optResult.OptimizedDockerfile != optResult.OriginalDockerfile {
		dir := filepath.Dir(dockerfilePath)
		optPath := filepath.Join(dir, "Dockerfile.optimized")
		if err := opt.WriteOptimized(optResult, optPath); err != nil {
			fmt.Printf("  ⚠ Failed to write optimized Dockerfile: %v\n", err)
		} else {
			fmt.Printf("  Written: %s\n", optPath)
		}
	}
	fmt.Println()

	// Step 3: Build
	if !skipBuild {
		bold.Println("Step 3/5: 🏗️  Building images...")
		b, err := builder.New()
		if err != nil {
			fmt.Printf("  ⚠ Cannot build: %v\n\n", err)
		} else {
			// Derive an image tag from the Dockerfile path
			baseName := strings.TrimSuffix(filepath.Base(dockerfilePath), filepath.Ext(dockerfilePath))
			baseTag := fmt.Sprintf("dio-%s:baseline", strings.ToLower(baseName))

			baseline, err := b.BuildBaseline(dockerfilePath, baseTag)
			if err != nil {
				fmt.Printf("  ⚠ Baseline build failed: %v\n", err)
			} else {
				result.BaselineImage = baseline
				fmt.Printf("  Baseline: %s (%s, %d layers, built in %.1fs)\n",
					baseline.ImageName, baseline.SizeHuman, baseline.Layers, baseline.BuildTime)
			}

			// Build optimized image if autofix produced a different Dockerfile
			if optMode == optimizer.ModeAutoFix && optResult.OptimizedDockerfile != optResult.OriginalDockerfile {
				optTag := fmt.Sprintf("dio-%s:optimized", strings.ToLower(baseName))
				contextDir := filepath.Dir(dockerfilePath)
				optPath := filepath.Join(contextDir, "Dockerfile.optimized")

				optimized, err := b.BuildOptimized(optPath, contextDir, optTag)
				if err != nil {
					fmt.Printf("  ⚠ Optimized build failed: %v\n", err)
				} else {
					result.OptimizedImage = optimized
					fmt.Printf("  Optimized: %s (%s, %d layers, built in %.1fs)\n",
						optimized.ImageName, optimized.SizeHuman, optimized.Layers, optimized.BuildTime)

					// Generate comparison
					if result.BaselineImage != nil {
						result.Comparison = b.Compare(result.BaselineImage, optimized)
						fmt.Printf("  Size reduction: %.1f%%\n", result.Comparison.SizePct)
					}
				}
			}
		}
	} else {
		bold.Println("Step 3/5: 🏗️  Building images... (skipped)")
	}
	fmt.Println()

	// Step 4: Security scan
	if !skipScan {
		bold.Println("Step 4/5: 🔒 Security scanning...")
		sc, err := scanner.New()
		if err != nil {
			fmt.Printf("  ⚠ Cannot scan: %v\n", err)
		} else {
			// Scan baseline image
			if result.BaselineImage != nil {
				scanRes, err := sc.Scan(result.BaselineImage.ImageName)
				if err != nil {
					fmt.Printf("  ⚠ Baseline scan failed: %v\n", err)
				} else {
					result.ScanResult = scanRes
					fmt.Printf("  Baseline: %d critical, %d high, %d medium, %d low\n",
						scanRes.CriticalCount, scanRes.HighCount, scanRes.MediumCount, scanRes.LowCount)
				}
			}

			// Scan optimized image
			if result.OptimizedImage != nil {
				optScanRes, err := sc.Scan(result.OptimizedImage.ImageName)
				if err != nil {
					fmt.Printf("  ⚠ Optimized scan failed: %v\n", err)
				} else {
					result.OptScanResult = optScanRes
					fmt.Printf("  Optimized: %d critical, %d high, %d medium, %d low\n",
						optScanRes.CriticalCount, optScanRes.HighCount, optScanRes.MediumCount, optScanRes.LowCount)
				}

				// Update CVE diff in comparison
				if result.Comparison != nil && result.ScanResult != nil {
					baseTotal := result.ScanResult.CriticalCount + result.ScanResult.HighCount
					optTotal := optScanRes.CriticalCount + optScanRes.HighCount
					result.Comparison.CVEDiff = baseTotal - optTotal
				}
			}

			if result.BaselineImage == nil && result.OptimizedImage == nil {
				fmt.Println("  ⚠ No images to scan (build step was skipped)")
			}
		}
	} else {
		bold.Println("Step 4/5: 🔒 Security scanning... (skipped)")
	}
	fmt.Println()

	// Step 5: Policy enforcement
	bold.Println("Step 5/5: 📋 Policy enforcement...")
	var config *policy.Config
	if policyFile != "" {
		config, err = policy.LoadConfig(policyFile)
		if err != nil {
			return fmt.Errorf("failed to load policy: %w", err)
		}
	} else {
		config = policy.DefaultConfig()
	}

	enforcer := policy.NewEnforcer(config)
	policyResult := enforcer.Evaluate(result)
	result.Policy = policyResult
	fmt.Println(policy.FormatPolicyStatus(policyResult))

	// Generate reports
	bold.Println("📝 Generating reports...")
	rep := reporter.New(outputDir)
	if err := rep.GenerateAll(result); err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}
	fmt.Printf("  Reports written to: %s/\n\n", outputDir)

	// Final summary
	bold.Println("==========================================")
	if policyResult.Passed {
		green.Println("✅ Pipeline completed — All checks passed")
	} else {
		red.Println("❌ Pipeline completed — Policy checks FAILED")
		os.Exit(1)
	}

	return nil
}
