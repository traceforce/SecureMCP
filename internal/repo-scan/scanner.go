package reposcan

import (
	"context"
)

type RepoScanner struct {
	repoPath       string
	scaScanner     *SCAScanner
	secretsScanner *SecretsScanner
	sastScanner    *SASTScanner
}

func NewRepoScanner(repoPath string) *RepoScanner {
	return &RepoScanner{
		repoPath:       repoPath,
		scaScanner:     NewSCAScanner(repoPath),
		secretsScanner: NewSecretsScanner(repoPath),
		sastScanner:    NewSASTScanner(repoPath),
	}
}

func (s *RepoScanner) Scan(ctx context.Context) ([]Finding, error) {
	findings := []Finding{}
	scaFindings, err := s.scaScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, scaFindings...)

	// Scan for secrets
	secretsFindings, err := s.secretsScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, secretsFindings...)

	sastFindings, err := s.sastScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}
	findings = append(findings, sastFindings...)

	return findings, nil
}
