package configscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	configparser "SecureMCP/internal/configparser"
	"SecureMCP/proto"
)

type SSLScanner struct {
	MCPconfigPath string
}

func NewSSLScanner(configPath string) *SSLScanner {
	return &SSLScanner{
		MCPconfigPath: configPath,
	}
}

// For HTTP MCP servers, scan for authentication vulnerabilities.
// For STDIO MCP servers, this part will be skipped.
func (s *SSLScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
	// Parse configPath
	servers, err := configparser.NewConfigParser(s.MCPconfigPath).Parse()
	if err != nil {
		return nil, err
	}

	findings := []proto.Finding{}
	for _, server := range servers {
		fmt.Printf("MCP Server %+v\n", server.RawJSON)
		classification := ClassifyTransport(server)
		if classification == proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP {
			results, err := s.ScanSSL(ctx, server)
			if err != nil {
				return nil, err
			}
			findings = append(findings, results...)
		}
	}

	// Return findings
	return findings, nil
}

// isLocalhostOrLoopback checks if the given URL points to localhost or loopback address
func isLocalhostOrLoopback(urlStr string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	host := parsedURL.Hostname()
	if host == "" {
		return false
	}

	// Check for localhost
	if host == "localhost" {
		return true
	}

	// Check for IPv4 loopback (127.0.0.x)
	if strings.HasPrefix(host, "127.0.0.") {
		return true
	}

	// Check for exact IPv4 loopback
	if host == "127.0.0.1" {
		return true
	}

	// Check for IPv6 loopback
	if host == "::1" || host == "[::1]" {
		return true
	}

	// Check if hostname resolves to loopback
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if ip.IsLoopback() {
				return true
			}
		}
	}

	return false
}

func (s *SSLScanner) ScanSSL(ctx context.Context, cfg configparser.MCPServerConfig) ([]proto.Finding, error) {
	if cfg.URL == nil {
		return nil, fmt.Errorf("URL is not set")
	}
	urlStr := *cfg.URL

	// Report localhost/loopback addresses as medium risk
	if isLocalhostOrLoopback(urlStr) {
		return []proto.Finding{
			{
				Title:    "MCP server URL points to localhost or loopback address. A local service can potentially be exploited by a remote attacker.",
				Severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
			},
		}, nil
	}

	var findings []proto.Finding

	// Create custom transport for SSL checks
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS11,
			MaxVersion: tls.VersionTLS13,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Make request to check SSL
	resp, err := client.Get(urlStr)
	if err != nil {
		fmt.Printf("Http error: %s\n", err.Error())
		if strings.Contains(err.Error(), "certificate") {
			findings = append(findings, proto.Finding{
				Title:    "Invalid SSL certificate",
				Severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
			})
		}
		return findings, nil
	}
	defer resp.Body.Close()

	// Check TLS version
	fmt.Printf("response %+v\n", resp.Header.Get("WWW-Authenticate"))
	if resp.TLS != nil {
		fmt.Printf("resp.TLS type: %T, value: %+v\n", resp.TLS, resp.TLS.Version)
		if resp.TLS.Version < tls.VersionTLS13 {
			findings = append(findings, proto.Finding{
				Title:    "TLS version 1.3 or higher is recommended",
				Severity: proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
			})
		} else if resp.TLS.Version < tls.VersionTLS12 {
			findings = append(findings, proto.Finding{
				Title:    "TLS version 1.2 or higher is recommended",
				Severity: proto.RiskSeverity_RISK_SEVERITY_HIGH,
			})
		}
	} else {
		findings = append(findings, proto.Finding{
			Title:    "No TLS certificate",
			Severity: proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
		})
	}

	return findings, nil
}
