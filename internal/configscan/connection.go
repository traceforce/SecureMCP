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

type ConnectionScanner struct {
	MCPconfigPath string
}

func NewConnectionScanner(configPath string) *ConnectionScanner {
	return &ConnectionScanner{
		MCPconfigPath: configPath,
	}
}

// For HTTP MCP servers, scan for authentication vulnerabilities.
// For STDIO MCP servers, this part will be skipped.
func (s *ConnectionScanner) Scan(ctx context.Context) ([]proto.Finding, error) {
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
			results, err := s.ScanConnection(ctx, server)
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

func (s *ConnectionScanner) ScanConnection(ctx context.Context, cfg configparser.MCPServerConfig) ([]proto.Finding, error) {
	if cfg.URL == nil {
		return nil, fmt.Errorf("URL is not set")
	}
	urlStr := *cfg.URL

	// Report localhost/loopback addresses as medium risk
	if isLocalhostOrLoopback(urlStr) {
		return []proto.Finding{
			{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "localhost-loopback-detection",
				Title:         "MCP server URL points to localhost or loopback address. A local service can potentially be exploited by a remote attacker.",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' is configured with a URL pointing to localhost or a loopback address (%s). This configuration exposes the service to potential exploitation by remote attackers who may gain access to the local system. Consider using a properly secured remote endpoint with authentication and encryption instead.", cfg.Name, urlStr),
			},
		}, nil
	}

	var findings []proto.Finding

	// Create custom transport for Connection checks
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

	// Make request to check Connection
	resp, err := client.Get(urlStr)
	if err != nil {
		fmt.Printf("Http error: %s\n", err.Error())
		if strings.Contains(strings.ToLower(err.Error()), "certificate") {
			findings = append(findings, proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
				RuleId:        "invalid-certificate",
				Title:         "Invalid Connection certificate",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' is configured with an invalid or untrusted TLS certificate. Connection to %s failed with certificate error: %s. This may indicate a man-in-the-middle attack or misconfigured server.", cfg.Name, urlStr, err.Error()),
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
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "tls-version-below-1.3",
				Title:         "TLS version 1.3 or higher is recommended",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' at %s is using a TLS version below 1.3. While TLS 1.2 is still secure, TLS 1.3 provides improved security and performance. Consider upgrading to TLS 1.3.", cfg.Name, urlStr),
			})
		} else if resp.TLS.Version < tls.VersionTLS12 {
			findings = append(findings, proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
				RuleId:        "tls-version-below-1.2",
				Title:         "TLS version 1.2 or higher is recommended",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' at %s is using a TLS version below 1.2, which is considered insecure. TLS versions below 1.2 are vulnerable to various attacks and should not be used. Please upgrade to TLS 1.2 or higher immediately.", cfg.Name, urlStr),
			})
		}
	} else {
		findings = append(findings, proto.Finding{
			Tool:          "connection-scanner",
			Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
			RuleId:        "no-tls-certificate",
			Title:         "No TLS certificate found in connection response",
			McpServerName: cfg.Name,
			File:          s.MCPconfigPath,
			Message:       fmt.Sprintf("The MCP server '%s' at %s is not using TLS encryption. All communication is unencrypted and vulnerable to interception and man-in-the-middle attacks. This is a critical security issue. Please configure the server to use HTTPS with a valid TLS certificate.", cfg.Name, urlStr),
		})
	}

	return findings, nil
}
