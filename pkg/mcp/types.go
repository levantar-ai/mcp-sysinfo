// Package mcp provides public types for MCP plugin development.
// This package exposes the necessary types from internal/mcp for
// enterprise plugins to register tools with the server.
package mcp

import (
	"context"

	"github.com/levantar-ai/mcp-sysinfo/internal/mcp"
)

// Re-export types needed by plugins

// Server is the MCP server that handles JSON-RPC requests.
type Server = mcp.Server

// NewServer creates a new MCP server.
func NewServer(name, version string) *Server {
	return mcp.NewServer(name, version)
}

// Tool describes a tool that can be called.
type Tool = mcp.Tool

// InputSchema defines the JSON schema for tool inputs.
type InputSchema = mcp.InputSchema

// Property defines a property in an input schema.
type Property = mcp.Property

// Content represents a piece of content in a tool result.
type Content = mcp.Content

// CallToolResult is returned by tool handlers.
type CallToolResult = mcp.CallToolResult

// ToolHandler is the function signature for tool handlers.
type ToolHandler = mcp.ToolHandler

// NewJSONContent creates a JSON content response from any value.
func NewJSONContent(v interface{}) Content {
	return mcp.NewJSONContent(v)
}

// NewTextContent creates a text content response.
func NewTextContent(text string) Content {
	return mcp.NewTextContent(text)
}

// PluginToolHandler is a simplified handler for plugins that returns
// interface{} and error instead of *CallToolResult.
type PluginToolHandler func(ctx context.Context, args map[string]interface{}) (interface{}, error)

// WrapHandler wraps a PluginToolHandler into a standard ToolHandler.
func WrapHandler(h PluginToolHandler) ToolHandler {
	return func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		result, err := h(ctx, args)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	}
}
