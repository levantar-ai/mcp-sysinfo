//go:build !enterprise

// Package plugins provides the plugin registration hook for enterprise plugins.
// In the OSS build (without the enterprise tag), this is a no-op.
package plugins

import (
	"github.com/levantar-ai/mcp-sysinfo/internal/mcp"
)

// RegisterPlugins is a no-op in the OSS build.
// In enterprise builds, this registers all enterprise plugins.
func RegisterPlugins(_ *mcp.Server) (int, []error) {
	return 0, nil
}
