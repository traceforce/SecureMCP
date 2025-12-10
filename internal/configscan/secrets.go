package configscan

import (
	"context"
	"fmt"
	"strings"

	configparser "SecureMCP/internal/configparser"
	"SecureMCP/proto"

	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

type SecretsScanner struct {
	configPath string
}

func NewSecretsScanner(configPath string) *SecretsScanner {
	return &SecretsScanner{
		configPath: configPath,
	}
}

func (s *SecretsScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	servers, err := configparser.NewConfigParser(s.configPath).Parse()
	if err != nil {
		return nil, err
	}

	findings := []proto.Finding{}

	for _, server := range servers {
		findings = append(findings, DetectSecrets(server)...)
	}

	return findings, nil
}

func DetectSecrets(cfg configparser.MCPServerConfig) []proto.Finding {
	fmt.Printf("Scanning secrets for server %s\n", cfg.Name)

	if strings.TrimSpace(cfg.RawJSON) == "" {
		return []proto.Finding{}
	}

	detector, err := detect.NewDetectorDefaultConfig()
	if err != nil {
		return nil
	}

	results := detector.DetectString(cfg.RawJSON)

	return FromGitleaks(cfg, results)
}

func FromGitleaks(cfg configparser.MCPServerConfig, findings []report.Finding) []proto.Finding {
	out := make([]proto.Finding, 0, len(findings))

	for _, f := range findings {
		out = append(out, proto.Finding{
			Tool:          "gitleaks",
			McpServerName: cfg.Name,
			Type:          proto.FindingType_FINDING_TYPE_SECRETS,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH, // treat all secrets as high/error
			RuleId:        f.RuleID,
			Title:         f.Description,
			Message:       f.Description, // avoid empty message
		})
	}

	return out
}
