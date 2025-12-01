package reposcan

import (
	"context"
)

type RepoScanner struct {
	repoPath       string
	scaScanner     *SCAScanner
	secretsScanner *SecretsScanner
}

func NewRepoScanner(repoPath string) *RepoScanner {
	return &RepoScanner{
		repoPath:       repoPath,
		scaScanner:     NewSCAScanner(repoPath),
		secretsScanner: NewSecretsScanner(repoPath),
	}
}

func (s *RepoScanner) Scan(ctx context.Context) ([]string, error) {
	scaFindings, err := s.scaScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}

	// Scan for secrets
	secretsFindings, err := s.secretsScanner.Scan(ctx)
	if err != nil {
		return nil, err
	}

	return append(scaFindings, secretsFindings...), nil
}
