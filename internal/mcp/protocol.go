// Package mcp implements the Model Context Protocol (JSON-RPC 2.0).
package mcp

import (
	"encoding/json"
)

// JSON-RPC 2.0 structures

// Request is a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"` // string, number, or null
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
}

// Notification is a JSON-RPC 2.0 notification (no ID, no response expected).
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Error is a JSON-RPC 2.0 error.
type Error struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC error codes
const (
	ErrCodeParse          = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
)

// MCP Protocol Messages

// InitializeParams is sent by the client to initialize the connection.
type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    Capabilities   `json:"capabilities"`
	ClientInfo      Implementation `json:"clientInfo"`
}

// InitializeResult is the server's response to initialize.
type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    Capabilities   `json:"capabilities"`
	ServerInfo      Implementation `json:"serverInfo"`
}

// Implementation identifies a client or server.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Capabilities describes what the client/server supports.
type Capabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
}

// ToolsCapability indicates tool support.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability indicates resource support.
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability indicates prompt support.
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// Tool represents an MCP tool.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema is a JSON Schema for tool parameters.
type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

// Property describes a parameter in the schema.
type Property struct {
	Type        string      `json:"type"`
	Description string      `json:"description,omitempty"`
	Enum        []string    `json:"enum,omitempty"`
	Default     interface{} `json:"default,omitempty"`
	Minimum     *int        `json:"minimum,omitempty"`
	Maximum     *int        `json:"maximum,omitempty"`
}

// ListToolsResult is the response to tools/list.
type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolParams is the request to tools/call.
type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// CallToolResult is the response to tools/call.
type CallToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// Content is a piece of content in a tool result.
type Content struct {
	Type     string `json:"type"` // "text", "image", "resource"
	Text     string `json:"text,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Data     string `json:"data,omitempty"` // base64 for images
}

// NewTextContent creates a text content item.
func NewTextContent(text string) Content {
	return Content{Type: "text", Text: text}
}

// NewJSONContent creates a JSON text content item.
func NewJSONContent(v interface{}) Content {
	data, _ := json.MarshalIndent(v, "", "  ")
	return Content{Type: "text", Text: string(data)}
}

// NewResponse creates a successful response.
func NewResponse(id interface{}, result interface{}) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

// NewErrorResponse creates an error response.
func NewErrorResponse(id interface{}, code int, message string, data interface{}) *Response {
	return &Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &Error{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
}

// MCP Protocol Version
const ProtocolVersion = "2024-11-05"
