package configscan

import (
	"context"

	"SecureMCP/proto"
)

type ConfigScanner struct {
	configPath     string
	secretsScanner *SecretsScanner
	sslScanner     *SSLScanner
	toolsScanner   *ToolsScanner
}

func NewConfigScanner(configPath string) *ConfigScanner {
	return &ConfigScanner{
		configPath:     configPath,
		secretsScanner: NewSecretsScanner(configPath),
		sslScanner:     NewSSLScanner(configPath),
		toolsScanner:   NewToolsScanner(configPath),
	}
}

func (s *ConfigScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	findings := []proto.Finding{}

	secretsFindings, err := s.secretsScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, secretsFindings...)

	sslFindings, err := s.sslScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, sslFindings...)

	toolsFindings, err := s.toolsScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, toolsFindings...)

	return findings, nil
}
