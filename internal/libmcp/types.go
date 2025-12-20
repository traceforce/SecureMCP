package libmcp

import "github.com/modelcontextprotocol/go-sdk/mcp"

// MCPServerConfig is the normalized representation returned by all parsers
type MCPServerConfig struct {
	Name        string
	Command     *string
	Args        []string
	URL         *string
	Env         map[string]string
	Headers     map[string]string
	Type        *string // Transport type from config (e.g., "stdio", "http", "sse")
	ProjectPath *string // Project path for project-scoped servers (e.g., "/Users/user1/src")
	RawJSON     string
}

// ServerToolsData represents tools data for a single server
type ServerToolsData struct {
	Server string      `json:"server"`
	Tools  []*mcp.Tool `json:"tools"`
}
