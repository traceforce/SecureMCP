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

			scanner := configscan.NewConfigScanner(configPath)
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
			scanner := reposcan.NewDefaultRepoScanner(repoPath)
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
