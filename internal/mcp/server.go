package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/audit"
)

// Server is the MCP server that handles JSON-RPC requests.
type Server struct {
	name    string
	version string

	mu       sync.RWMutex
	tools    map[string]*registeredTool
	toolList []Tool

	initialized bool
}

// ToolHandler is the function that executes a tool.
type ToolHandler func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error)

type registeredTool struct {
	Tool    Tool
	Handler ToolHandler
	Scope   string // Required MCP scope (e.g., "core", "logs", "sensitive")
}

// Context keys for audit information
type auditContextKey string

const (
	// ContextKeyIdentity stores the authenticated identity
	ContextKeyIdentity auditContextKey = "audit.identity"
	// ContextKeyClientIP stores the client IP address
	ContextKeyClientIP auditContextKey = "audit.client_ip"
)

// NewServer creates a new MCP server.
func NewServer(name, version string) *Server {
	return &Server{
		name:    name,
		version: version,
		tools:   make(map[string]*registeredTool),
	}
}

// RegisterTool adds a tool to the server.
func (s *Server) RegisterTool(tool Tool, scope string, handler ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tools[tool.Name] = &registeredTool{
		Tool:    tool,
		Handler: handler,
		Scope:   scope,
	}
	s.toolList = append(s.toolList, tool)
}

// ServeStdio runs the server over stdio (standard MCP transport).
func (s *Server) ServeStdio(ctx context.Context) error {
	return s.serve(ctx, os.Stdin, os.Stdout)
}

// serve handles JSON-RPC messages from reader and writes responses to writer.
func (s *Server) serve(ctx context.Context, r io.Reader, w io.Writer) error {
	scanner := bufio.NewScanner(r)
	// Increase buffer size for large messages
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	encoder := json.NewEncoder(w)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		response := s.handleMessage(ctx, line)
		if response != nil {
			if err := encoder.Encode(response); err != nil {
				log.Printf("Error encoding response: %v", err)
			}
		}
	}

	return scanner.Err()
}

// handleMessage processes a single JSON-RPC message.
func (s *Server) handleMessage(ctx context.Context, data []byte) *Response {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return NewErrorResponse(nil, ErrCodeParse, "Parse error", err.Error())
	}

	if req.JSONRPC != "2.0" {
		return NewErrorResponse(req.ID, ErrCodeInvalidRequest, "Invalid Request", "jsonrpc must be 2.0")
	}

	// Handle notifications (no ID = no response)
	if req.ID == nil {
		s.handleNotification(ctx, req.Method, req.Params)
		return nil
	}

	// Handle request methods
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req.ID, req.Params)
	case "initialized":
		// Notification, but might come with ID
		return NewResponse(req.ID, nil)
	case "tools/list":
		return s.handleToolsList(req.ID)
	case "tools/call":
		return s.handleToolsCall(ctx, req.ID, req.Params)
	case "ping":
		return NewResponse(req.ID, map[string]interface{}{})
	default:
		return NewErrorResponse(req.ID, ErrCodeMethodNotFound, "Method not found", req.Method)
	}
}

// handleNotification processes notifications (no response expected).
func (s *Server) handleNotification(ctx context.Context, method string, params json.RawMessage) {
	switch method {
	case "initialized":
		s.mu.Lock()
		s.initialized = true
		s.mu.Unlock()
	case "notifications/cancelled":
		// Client cancelled a request - we could track pending requests
	}
}

// handleInitialize processes the initialize request.
func (s *Server) handleInitialize(id interface{}, params json.RawMessage) *Response {
	var initParams InitializeParams
	if params != nil {
		if err := json.Unmarshal(params, &initParams); err != nil {
			return NewErrorResponse(id, ErrCodeInvalidParams, "Invalid params", err.Error())
		}
	}

	result := InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities: Capabilities{
			Tools: &ToolsCapability{},
		},
		ServerInfo: Implementation{
			Name:    s.name,
			Version: s.version,
		},
	}

	return NewResponse(id, result)
}

// handleToolsList returns the list of available tools.
func (s *Server) handleToolsList(id interface{}) *Response {
	s.mu.RLock()
	tools := make([]Tool, len(s.toolList))
	copy(tools, s.toolList)
	s.mu.RUnlock()

	return NewResponse(id, ListToolsResult{Tools: tools})
}

// handleToolsCall executes a tool.
func (s *Server) handleToolsCall(ctx context.Context, id interface{}, params json.RawMessage) *Response {
	var callParams CallToolParams
	if err := json.Unmarshal(params, &callParams); err != nil {
		return NewErrorResponse(id, ErrCodeInvalidParams, "Invalid params", err.Error())
	}

	s.mu.RLock()
	tool, ok := s.tools[callParams.Name]
	s.mu.RUnlock()

	if !ok {
		// Audit the failed tool lookup
		s.auditToolCall(ctx, callParams.Name, callParams.Arguments, 0, audit.ResultError, "tool not found")
		return NewErrorResponse(id, ErrCodeInvalidParams, "Tool not found", callParams.Name)
	}

	// Execute the tool with timing
	start := time.Now()
	result, err := tool.Handler(ctx, callParams.Arguments)
	duration := time.Since(start)

	if err != nil {
		// Audit the error
		s.auditToolCall(ctx, callParams.Name, callParams.Arguments, duration, audit.ResultError, err.Error())
		// Return error as tool result, not JSON-RPC error
		return NewResponse(id, &CallToolResult{
			Content: []Content{NewTextContent(fmt.Sprintf("Error: %v", err))},
			IsError: true,
		})
	}

	// Audit success
	s.auditToolCall(ctx, callParams.Name, callParams.Arguments, duration, audit.ResultSuccess, "")

	return NewResponse(id, result)
}

// auditToolCall logs a tool invocation to the audit log.
func (s *Server) auditToolCall(ctx context.Context, toolName string, params map[string]interface{}, duration time.Duration, result audit.EventResult, errMsg string) {
	// Extract identity and client IP from context
	identity := ""
	if id, ok := ctx.Value(ContextKeyIdentity).(string); ok {
		identity = id
	}

	clientIP := ""
	if ip, ok := ctx.Value(ContextKeyClientIP).(string); ok {
		clientIP = ip
	}

	// Log the tool call (no-op if audit is disabled)
	_ = audit.LogToolCall(toolName, params, identity, clientIP, duration, result, errMsg)
}

// GetToolScope returns the required scope for a tool.
func (s *Server) GetToolScope(toolName string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if tool, ok := s.tools[toolName]; ok {
		return tool.Scope
	}
	return ""
}
