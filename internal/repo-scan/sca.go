package reposcan

import (
	"context"
	"fmt"
	"log"

	"github.com/google/osv-scanner/v2/pkg/osvscanner"
)

type SCAScanner struct {
	repoPath string
}

func NewSCAScanner(repoPath string) *SCAScanner {
	return &SCAScanner{
		repoPath: repoPath,
	}
}

func (s *SCAScanner) Scan(ctx context.Context) ([]string, error) {
	actions := osvscanner.ScannerActions{
		// Scan this directory as "project source"
		DirectoryPaths: []string{s.repoPath},
		Recursive:      true,

		// Optional: enable call/reachability analysis per ecosystem
		// Example keys include "npm", "pypi", "go" (see osv-scanner docs)
		// CallAnalysisStates: map[string]bool{"go": true, "npm": true, "pypi": true},
	}

	results, err := osvscanner.DoScan(actions)
	if err != nil {
		// Note: DoScan may return a "vulnerabilities found" error in some configs,
		// so you might want to treat that as non-fatal and just read results.
		log.Printf("scan error: %v", err)
	}

	// results is a models.VulnerabilityResults struct
	// Print a quick summary:
	totalVulns := 0
	var vulnerabilityIDs []string

	for _, r := range results.Results {
		for _, pkg := range r.Packages {
			totalVulns += len(pkg.Vulnerabilities)
			for _, v := range pkg.Vulnerabilities {
				vulnerabilityIDs = append(vulnerabilityIDs, v.Id)
				fmt.Printf(
					"[%s] %s in %s@%s\n",
					v.Severity,
					v.Id, // often CVE/GHSA/OSV ID
					pkg.Package.Name,
					pkg.Package.Version,
				)
			}
		}
	}
	fmt.Printf("Found %d vulnerabilities\n", totalVulns)

	return vulnerabilityIDs, nil
}
