// Package plugin provides the interface and registry for enterprise plugins.
// Plugins are compiled into the binary at build time using build tags.
package plugin

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/mcp"
)

// Plugin defines the interface all plugins must implement.
type Plugin interface {
	// Name returns the plugin identifier (e.g., "mysql", "redis")
	Name() string

	// Version returns the plugin version (e.g., "1.0.0")
	Version() string

	// Scope returns the permission scope for this plugin's tools.
	// This is used for access control (e.g., "mysql", "redis", "security")
	Scope() string

	// Description returns a human-readable description of the plugin
	Description() string

	// Register registers the plugin's tools with the MCP server.
	// This is called during server initialization.
	Register(server *mcp.Server) error
}

// PluginInfo contains metadata about a registered plugin.
type PluginInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Scope       string `json:"scope"`
	Description string `json:"description"`
	ToolCount   int    `json:"tool_count"`
}
