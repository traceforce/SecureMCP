package configscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	configparser "mcpxray/internal/configparser"
	"mcpxray/proto"
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

	fmt.Printf("Connection scanner scanning %d MCP servers\n", len(servers))

	findings := []proto.Finding{}
	for _, server := range servers {
		fmt.Printf("Scanning MCP Server %+v\n", server.RawJSON)
		classification := ClassifyTransport(server)
		if classification == proto.MCPTransportType_MCP_TRANSPORT_TYPE_HTTP {
			results, err := s.ScanConnection(ctx, server)
			if err != nil {
				return nil, err
			}
			findings = append(findings, results...)
		}
	}

	fmt.Printf("Connection scanner found %d findings\n", len(findings))
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

	return isLoopbackHost(host)
}

// isLoopbackHost returns true for localhost/127.x.x.x/[::1] and common loopback cases.
// Handles Docker hosts, .localhost domains, and unspecified addresses.
func isLoopbackHost(h string) bool {
	h = strings.ToLower(h)
	if h == "localhost" || h == "ip6-localhost" || h == "host.docker.internal" || h == "gateway.docker.internal" {
		return true
	}
	if strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && (ip.IsLoopback() || ip.IsUnspecified()) {
		return true
	}
	return false
}

// isCertificateError checks if error is a TLS certificate validation error
func isCertificateError(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for x509 certificate errors (remote cert problems, not local system issues)
	var x509UnknownAuthErr x509.UnknownAuthorityError
	var x509CertInvalidErr x509.CertificateInvalidError
	var x509HostnameErr x509.HostnameError
	var x509InsecureAlgErr x509.InsecureAlgorithmError
	var x509ConstraintErr x509.ConstraintViolationError
	var x509UnhandledExtErr x509.UnhandledCriticalExtension
	
	return errors.As(err, &x509UnknownAuthErr) ||
		errors.As(err, &x509CertInvalidErr) ||
		errors.As(err, &x509HostnameErr) ||
		errors.As(err, &x509InsecureAlgErr) ||
		errors.As(err, &x509ConstraintErr) ||
		errors.As(err, &x509UnhandledExtErr)
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
	// First attempt: strict certificate validation
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS11,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: false, // Validate certificates strictly
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Make request to check Connection
	resp, err := client.Get(urlStr)

	// Handle certificate errors with two-pass approach
	if err != nil && isCertificateError(err) {
		fmt.Printf("Certificate validation failed: %s\n", err.Error())
		
		// Report the certificate error
		findings = append(findings, proto.Finding{
			Tool:          "connection-scanner",
			Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
			Severity:      proto.RiskSeverity_RISK_SEVERITY_CRITICAL,
			RuleId:        "invalid-certificate",
			Title:         "Invalid TLS certificate",
			McpServerName: cfg.Name,
			File:          s.MCPconfigPath,
			Message:       fmt.Sprintf("The MCP server '%s' has an invalid or untrusted TLS certificate. Connection to %s failed with certificate error: %s.", cfg.Name, urlStr, err.Error()),
		})
		
		// Retry with InsecureSkipVerify to get TLS version despite certificate error
		// This allows us to report BOTH cert issues AND old TLS versions
		transport.TLSClientConfig.InsecureSkipVerify = true
		resp, err = client.Get(urlStr)
		if err != nil {
			// Still failed - connection issue beyond certificate
			return findings, nil
		}
	} else if err != nil {
		// Non-certificate error (network, timeout, DNS, etc.)
		return findings, nil
	}
	
	defer resp.Body.Close()

	// Check TLS version
	fmt.Printf("Response authentication header: %+v\n", resp.Header.Get("WWW-Authenticate"))
	if resp.TLS != nil {
		fmt.Printf("resp.TLS type: %T, value: %+v\n", resp.TLS, resp.TLS.Version)
		// Check TLS version - order matters! Check worst case first
		if resp.TLS.Version < tls.VersionTLS12 {
			findings = append(findings, proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_HIGH,
				RuleId:        "tls-version-below-1.2",
				Title:         "TLS version 1.2 or higher is required",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' at %s is using a TLS version below 1.2 (detected: TLS 1.%d), which is considered insecure. TLS versions below 1.2 are vulnerable to various attacks and should not be used. Please upgrade to TLS 1.2 or higher immediately.", cfg.Name, urlStr, resp.TLS.Version-tls.VersionTLS10),
			})
		} else if resp.TLS.Version < tls.VersionTLS13 {
			findings = append(findings, proto.Finding{
				Tool:          "connection-scanner",
				Type:          proto.FindingType_FINDING_TYPE_CONNECTION,
				Severity:      proto.RiskSeverity_RISK_SEVERITY_MEDIUM,
				RuleId:        "tls-version-below-1.3",
				Title:         "TLS version 1.3 or higher is recommended",
				McpServerName: cfg.Name,
				File:          s.MCPconfigPath,
				Message:       fmt.Sprintf("The MCP server '%s' at %s is using TLS 1.2. While TLS 1.2 is still secure, TLS 1.3 provides improved security and performance. Consider upgrading to TLS 1.3.", cfg.Name, urlStr),
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
