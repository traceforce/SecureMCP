# Example MCP Server

This directory contains an example MCP (Model Context Protocol) server built with FastMCP that demonstrates how to set up and scan an MCP server with SecureMCP.

## Overview

The example server (`mcp_server.py`) is a simple FastMCP server that provides:
- **Tools**: `add` (arithmetic) and `summarize_json` (JSON analysis)
- **Resources**: A readme resource accessible via URI
- **Prompts**: An explain_server prompt template

The server uses the `streamable-http` transport, making it accessible over HTTP for scanning.

## Prerequisites

- Python 3.8 or later
- pip (Python package manager)
- SecureMCP binary (see main [README.md](../../README.md) for installation instructions)

## Setup

### 1. Install Python Dependencies

```bash
cd examples/mcp_server
pip install -r requirements.txt
```

This will install `fastmcp` and its dependencies.

### 2. Start the MCP Server

Run the server in a terminal:

```bash
python mcp_server.py
```

The server will start on `http://localhost:8000/mcp/` by default. You should see output indicating the server is running.

**Note**: Keep this terminal open while scanning, as SecureMCP needs the server to be running to discover and analyze its tools.

### 3. Verify the Server is Running

You can verify the server is accessible by checking the endpoint:

```bash
curl http://localhost:8000/mcp/
```
## Scanning with SecureMCP

### Configuration Scan

Once the server is running, you can scan it using SecureMCP's configuration scanner. The `mcp.json` file in this directory is already configured to point to the local server.

### Example Workflow

Complete workflow from start to finish:

```bash
# Terminal 1: Start the MCP server
cd examples/mcp_server
pip install -r requirements.txt
python mcp_server.py

# Terminal 2: Run the security scan
cd /path/to/securemcp
./securemcp config-scan examples/mcp_server/mcp.json --output examples/findings/mcp-server-example-scan.sarif.json

# View the results
# Option 1: Open in SARIF Web Viewer
# Option 2: Review the JSON file directly
cat examples/findings/cp-server-example-scan.sarif.json
```

## Troubleshooting

### Server Won't Start

- **Port Already in Use**: If port 8000 is occupied, modify `mcp_server.py` to use a different port, and update `mcp.json` accordingly
- **Missing Dependencies**: Ensure `fastmcp` is installed: `pip install fastmcp`

### Scanner Can't Connect

- **Server Not Running**: Ensure the MCP server is running before scanning
- **Wrong URL**: Verify the URL in `mcp.json` matches the server's actual address
- **Network Issues**: Check that `localhost:8000` is accessible

## See Also

- [SecureMCP Main README](../README.md) - Full documentation
- [FastMCP Documentation](https://github.com/jlowin/fastmcp) - FastMCP framework docs
- [MCP Specification](https://modelcontextprotocol.io/) - Model Context Protocol specification
