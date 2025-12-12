package configscan

import (
	"context"
	"strings"

	"SecureMCP/internal/configscan/tokenanalyzer"
	"SecureMCP/proto"
)

type TokenAnalyzer struct {
	rules []tokenanalyzer.Rule
}

var _ ToolsAnalyzer = (*TokenAnalyzer)(nil)

func NewTokenAnalyzer() (*TokenAnalyzer, error) {
	rules, err := tokenanalyzer.LoadDefaultRuleSet()
	if err != nil {
		return nil, err
	}
	return &TokenAnalyzer{rules: rules}, nil
}

// mapSeverity maps rule severity string -> proto.RiskSeverity.
func mapSeverity(s string) proto.RiskSeverity {
	switch strings.ToLower(s) {
	case "low":
		return proto.RiskSeverity_RISK_SEVERITY_LOW
	case "medium":
		return proto.RiskSeverity_RISK_SEVERITY_MEDIUM
	case "high":
		return proto.RiskSeverity_RISK_SEVERITY_HIGH
	case "critical":
		return proto.RiskSeverity_RISK_SEVERITY_CRITICAL
	default:
		return proto.RiskSeverity_RISK_SEVERITY_UNKNOWN
	}
}

func (a *TokenAnalyzer) AnalyzeTools(ctx context.Context, tools []Tool, mcpServerName string, configPath string) ([]proto.Finding, error) {
	allFindings := []proto.Finding{}
	for _, tool := range tools {
		findings, err := a.AnalyzeTool(ctx, tool.Description, tool.Name, mcpServerName, configPath)
		if err != nil {
			return nil, err
		}
		allFindings = append(allFindings, findings...)
	}
	return allFindings, nil
}

func (a *TokenAnalyzer) AnalyzeTool(ctx context.Context, description string, name string,
	mcpServerName string, configPath string) ([]proto.Finding, error) {
	internalFindings := tokenanalyzer.Analyze(description, a.rules)

	findings := []proto.Finding{}
	for _, finding := range internalFindings {
		findings = append(findings, proto.Finding{
			Tool:          "token_analyzer",
			Type:          proto.FindingType_FINDING_TYPE_TOOL_ANALYSIS,
			Severity:      mapSeverity(finding.Severity),
			RuleId:        finding.RuleID,
			Title:         finding.Meta["category"] + " - " + finding.RuleID,
			McpServerName: mcpServerName,
			McpToolName:   name,
			File:          configPath,
			Message:       finding.Meta["reason"],
		})
	}
	return findings, nil
}
