package reposcan

import (
	"context"
)

type SASTScanner struct {
	repoPath string
}

func NewSASTScanner(repoPath string) *SASTScanner {
	return &SASTScanner{
		repoPath: repoPath,
	}
}

func (s *SASTScanner) Scan(ctx context.Context) ([]Finding, error) {
	return nil, nil
}
