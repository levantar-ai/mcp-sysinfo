//go:build enterprise

// Package plugins provides the plugin registration hook for enterprise plugins.
// This file is only compiled when the enterprise build tag is set.
package plugins

import (
	"log"

	"github.com/levantar-ai/mcp-sysinfo/internal/mcp"
	"github.com/levantar-ai/mcp-sysinfo/pkg/plugin"
)

// RegisterPlugins registers all enterprise plugins with the MCP server.
// Returns the number of successfully registered plugins and any errors.
func RegisterPlugins(server *mcp.Server) (int, []error) {
	count, errs := plugin.DefaultRegistry.RegisterAllPlugins(server)

	if count > 0 {
		log.Printf("[enterprise] Registered %d plugin(s)", count)
	}

	for _, err := range errs {
		log.Printf("[enterprise] Plugin registration error: %v", err)
	}

	return count, errs
}
