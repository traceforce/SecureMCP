# SecureMCP

A comprehensive security auditing tool for Model Context Protocol (MCP) servers. Generates production-ready [SARIF reports](https://sarifweb.azurewebsites.net/) for seamless integration with security tooling and CI/CD pipelines.

## Overview

SecureMCP performs security analysis on MCP (Model Context Protocol) servers and their codebases. It scans for security issues across multiple dimensions including configuration vulnerabilities, exposed secrets, unsafe tool definitions, and code-level security problems.

## Features

### Configuration Scanning (`config-scan`)

Analyzes MCP server configurations for security issues:

- **Connection Security**: Validates HTTP/HTTPS connections, TLS configuration, and authentication mechanisms
- **Tool Analysis**: Uses LLM-based analysis to detect potentially dangerous tool definitions that could lead to:
  - Arbitrary tool execution without validation
  - Insufficient input validation on tool arguments
  - Missing authorization or permission checks
  - Code injection and repository modification
  - Privilege escalation and access control bypass
  - Credential exposure and connection hijacking
  - Information disclosure and reconnaissance
- **Secrets Detection**: Scans configuration files for exposed credentials, API keys, and other sensitive information

### Repository Scanning (`repo-scan`)

Performs comprehensive security analysis of the codebase:

- **SCA (Software Composition Analysis)**: Detects vulnerable dependencies using OSV Scanner
- **SAST (Static Application Security Testing)**: Identifies unsafe command patterns and security anti-patterns in code
- **Secrets Detection**: Scans source code for hardcoded secrets and credentials using Gitleaks

## Installation

### Prerequisites

- [Go 1.25.4 or later](https://go.dev/dl/)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/traceforce/SecureMCP
cd SecureMCP

# Install required dependencies (buf, etc.)
make install-dependencies

# Build everything (generates protobuf code and builds the binary)
# The binary will be created as `securemcp` in the current directory
make all

```

Alternatively, you can build individual components:

```bash
# Generate protocol buffers only
make proto

# Build the binary only (requires proto to be generated first)
make build
```

## Usage

### Configuration Scan

Scan MCP server configurations for security issues:

```bash
# Scan current directory for MCP config files
securemcp config-scan

# Scan a specific directory
securemcp config-scan /path/to/mcp/config

# Specify custom output file
securemcp config-scan --output custom-report.sarif.json
```

The configuration scanner will:
1. Parse MCP server configuration files
2. Analyze connection security (HTTP/HTTPS, TLS, authentication)
3. Discover and analyze available tools from MCP servers
4. Scan for exposed secrets in configuration files

### Repository Scan

Scan the codebase for security vulnerabilities:

```bash
# Scan current directory
securemcp repo-scan

# Scan a specific repository
securemcp repo-scan /path/to/repository

# Specify custom output file
securemcp repo-scan --output custom-report.sarif.json
```

The repository scanner will:
1. Perform SCA analysis to detect vulnerable dependencies
2. Run SAST analysis to find unsafe code patterns
3. Scan for hardcoded secrets in source code

## Output Format

SecureMCP generates reports in [SARIF (Static Analysis Results Interchange Format)](https://sarifweb.azurewebsites.net/) format, which is widely supported by security tools and CI/CD platforms.

## Examples

Example scan outputs are available in `examples/findings/`:

- `config-scan-risky-tools.sarif.json`: Configuration scan findings for tools with high security risks
- `config-scan-secrets.sarif.json`: Configuration scan findings for secrets exposed in configurations
- `repo-scan-cve-secrets.sarif.json`: Repository scan findings for CVE vulnerabilities and secrets
- `repo-scan-dangerous-commands.sarif.json`: Repository scan findings for dangerous command patterns

Example MCP configuration files are available in the `examples/mcp_configs/` directory:

- `local_mcp.json`: Local STDIO-based MCP server
- `remote_mcp_token.json`: Remote HTTP server with token authentication
- `remote_mcp_oauth.json`: Remote HTTP server with OAuth authentication
- `mcp_with_env.json`: Configuration using environment variables
- `mcp_with_proxy.json`: Configuration with proxy settings

An example MCP Server is available in the `examples/mcp_server/` directory:
- `mcp_server.py`: FastMCP server using streamable-http transport
- `mcp.json`: Configuration file for connecting to the server
- `README.md`: Instructions for setting up and scanning the server

## Configuration

### Environment Variables

For LLM-based tool analysis, configure your LLM API credentials:

```bash
export OPENAI_API_KEY=your-api-key
# or
export ANTHROPIC_API_KEY=your-api-key
```

## Contributing

Contributions are welcome! Please ensure that:

1. Code follows Go best practices
2. Tests are included for new features
3. Protocol buffers are regenerated after changes
4. Documentation is updated

## License

[Specify your license here]

## References

- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)
- [OSV Scanner](https://google.github.io/osv-scanner/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
