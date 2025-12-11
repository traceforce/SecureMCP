package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	configscan "SecureMCP/internal/configscan"
	"SecureMCP/internal/report"
	reposcan "SecureMCP/internal/reposcan"
	"SecureMCP/proto"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "securemcp",
	Short: "SecureMCP - Security auditing tool for MCP applications",
	Long:  `A comprehensive security auditing tool designed to detect vulnerabilities and misconfigurations in applications using the Model Context Protocol (MCP).`,
}

func NewConfigScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config-scan",
		Short: "Scan the configuration of the MCP server",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Scanning the configuration of the MCP server")
			configPath := "."
			if len(args) > 0 {
				configPath = args[0]
			}

			llmModel, _ := cmd.Flags().GetString("llm-model")
			scanner, err := configscan.NewConfigScanner(configPath, llmModel)
			if err != nil {
				fmt.Println("Error creating config scanner:", err)
				os.Exit(1)
			}
			findings, err := scanner.Scan(context.Background())
			if err != nil {
				fmt.Println("Error scanning configuration:", err)
				os.Exit(1)
			}

			outputPath, _ := cmd.Flags().GetString("output")
			if err := writeFindings(findings, outputPath, "config-scan"); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringP("output", "o", "", "Output file path for SARIF report (default: findings.sarif.json)")
	cmd.Flags().String("llm-model", "", "LLM model to use for analysis (required)")
	cmd.MarkFlagRequired("llm-model")
	return cmd
}

func NewRepoScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo-scan [repo-path]",
		Short: "Scan the repository of the MCP server",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Scanning the repository of the MCP server")
			repoPath := "."
			if len(args) > 0 {
				repoPath = args[0]
			}

			var scanner *reposcan.RepoScanner
			maxFileSize, _ := cmd.Flags().GetInt64("max-file-size")
			excludedPaths, _ := cmd.Flags().GetStringArray("exclude-paths")
			useDefaultExcludes, _ := cmd.Flags().GetBool("use-default-excludes")

			// Build config - by default scan everything (no excludes)
			config := &reposcan.Config{
				MaxFileSize:   10 * 1024 * 1024, // 10MB default
				ExcludedPaths: []string{},       // Empty by default - scan everything
			}

			// Apply max file size if specified
			if maxFileSize > 0 {
				config.MaxFileSize = maxFileSize
			}

			// Apply excluded paths
			defaultConfig := reposcan.DefaultConfig()
			if useDefaultExcludes {
				// Use default excluded paths
				config.ExcludedPaths = defaultConfig.ExcludedPaths
			}
			if len(excludedPaths) > 0 {
				// User-provided excludes override or extend
				config.ExcludedPaths = append(defaultConfig.ExcludedPaths, excludedPaths...)
			}

			scanner = reposcan.NewRepoScannerWithConfig(repoPath, config)

			findings, err := scanner.Scan(context.Background())
			if err != nil {
				fmt.Println("Error scanning repository:", err)
				os.Exit(1)
			}

			outputPath, _ := cmd.Flags().GetString("output")
			if err := writeFindings(findings, outputPath, "repo-scan"); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
	cmd.Flags().StringP("output", "o", "", "Output file path for SARIF report (default: findings.sarif.json)")
	cmd.Flags().Int64("max-file-size", 0, "Maximum file size in bytes to scan (0 uses default: 10MB)")
	cmd.Flags().StringArrayP("exclude-paths", "e", []string{}, "Path pattern to exclude from scanning (can be specified multiple times)")
	cmd.Flags().Bool("use-default-excludes", true, "Use default exclude paths (e.g., node_modules, .git, etc.). By default, certain files and directories are excluded from scanning.")
	return cmd
}

func init() {
	rootCmd.AddCommand(NewConfigScanCommand())
	rootCmd.AddCommand(NewRepoScanCommand())
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func writeFindings(findings []proto.Finding, outputPath string, commandName string) error {
	sarifBytes, err := report.GenerateSarif(findings)
	if err != nil {
		return fmt.Errorf("error generating SARIF report: %w", err)
	}

	if outputPath == "" {
		timestamp := time.Now().Format(time.RFC3339)
		// Make RFC3339 filename-safe by replacing colons with hyphens
		timestamp = strings.ReplaceAll(timestamp, ":", "-")
		outputPath = fmt.Sprintf("findings-%s-%s.sarif.json", commandName, timestamp)
	}

	err = os.WriteFile(outputPath, sarifBytes, 0644)
	if err != nil {
		return fmt.Errorf("error writing to output file %s: %w", outputPath, err)
	}

	fmt.Printf("SARIF report written to %s\n", outputPath)
	return nil
}
