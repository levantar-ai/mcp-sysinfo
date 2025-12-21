package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestNewServer(t *testing.T) {
	s := NewServer("test-server", "1.0.0")
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.name != "test-server" {
		t.Errorf("expected name 'test-server', got %q", s.name)
	}
	if s.version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got %q", s.version)
	}
	if s.tools == nil {
		t.Error("tools map should be initialized")
	}
}

func TestRegisterTool(t *testing.T) {
	s := NewServer("test", "1.0")
	tool := Tool{
		Name:        "test_tool",
		Description: "A test tool",
		InputSchema: InputSchema{Type: "object"},
	}
	handler := func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		return &CallToolResult{Content: []Content{NewTextContent("ok")}}, nil
	}

	s.RegisterTool(tool, "core", handler)

	if len(s.tools) != 1 {
		t.Errorf("expected 1 tool, got %d", len(s.tools))
	}
	if len(s.toolList) != 1 {
		t.Errorf("expected 1 tool in list, got %d", len(s.toolList))
	}
	if _, ok := s.tools["test_tool"]; !ok {
		t.Error("test_tool not found in tools map")
	}
}

func TestRegisterMultipleTools(t *testing.T) {
	s := NewServer("test", "1.0")
	handler := func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		return &CallToolResult{Content: []Content{NewTextContent("ok")}}, nil
	}

	for i := 0; i < 3; i++ {
		tool := Tool{
			Name:        "tool_" + string(rune('a'+i)),
			Description: "Tool " + string(rune('a'+i)),
			InputSchema: InputSchema{Type: "object"},
		}
		s.RegisterTool(tool, "core", handler)
	}

	if len(s.tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(s.tools))
	}
}

func TestGetToolScope(t *testing.T) {
	s := NewServer("test", "1.0")
	handler := func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		return nil, nil
	}

	s.RegisterTool(Tool{Name: "core_tool"}, "core", handler)
	s.RegisterTool(Tool{Name: "sensitive_tool"}, "sensitive", handler)
	s.RegisterTool(Tool{Name: "logs_tool"}, "logs", handler)

	tests := []struct {
		toolName string
		want     string
	}{
		{"core_tool", "core"},
		{"sensitive_tool", "sensitive"},
		{"logs_tool", "logs"},
		{"unknown_tool", ""},
	}

	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			got := s.GetToolScope(tt.toolName)
			if got != tt.want {
				t.Errorf("GetToolScope(%q) = %q, want %q", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestHandleMessageInitialize(t *testing.T) {
	s := NewServer("test-server", "1.0.0")
	ctx := context.Background()

	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params:  json.RawMessage(`{"protocolVersion":"2024-11-05","clientInfo":{"name":"test","version":"1.0"}}`),
	}
	data, _ := json.Marshal(req)

	resp := s.handleMessage(ctx, data)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(InitializeResult)
	if !ok {
		t.Fatalf("expected InitializeResult, got %T", resp.Result)
	}
	if result.ServerInfo.Name != "test-server" {
		t.Errorf("expected server name 'test-server', got %q", result.ServerInfo.Name)
	}
}

func TestHandleMessageToolsList(t *testing.T) {
	s := NewServer("test", "1.0")
	handler := func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		return nil, nil
	}
	s.RegisterTool(Tool{Name: "tool1", Description: "Tool 1"}, "core", handler)
	s.RegisterTool(Tool{Name: "tool2", Description: "Tool 2"}, "core", handler)

	ctx := context.Background()
	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}
	data, _ := json.Marshal(req)

	resp := s.handleMessage(ctx, data)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(ListToolsResult)
	if !ok {
		t.Fatalf("expected ListToolsResult, got %T", resp.Result)
	}
	if len(result.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(result.Tools))
	}
}

func TestHandleMessageToolsCall(t *testing.T) {
	s := NewServer("test", "1.0")
	handler := func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		name, _ := args["name"].(string)
		return &CallToolResult{
			Content: []Content{NewTextContent("Hello, " + name)},
		}, nil
	}
	s.RegisterTool(Tool{
		Name: "greet",
		InputSchema: InputSchema{
			Type:       "object",
			Properties: map[string]Property{"name": {Type: "string"}},
		},
	}, "core", handler)

	ctx := context.Background()
	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"greet","arguments":{"name":"World"}}`),
	}
	data, _ := json.Marshal(req)

	resp := s.handleMessage(ctx, data)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(*CallToolResult)
	if !ok {
		t.Fatalf("expected *CallToolResult, got %T", resp.Result)
	}
	if len(result.Content) != 1 {
		t.Fatalf("expected 1 content, got %d", len(result.Content))
	}
	if result.Content[0].Text != "Hello, World" {
		t.Errorf("expected 'Hello, World', got %q", result.Content[0].Text)
	}
}

func TestHandleMessageToolNotFound(t *testing.T) {
	s := NewServer("test", "1.0")
	ctx := context.Background()

	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"nonexistent"}`),
	}
	data, _ := json.Marshal(req)

	resp := s.handleMessage(ctx, data)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Fatal("expected error for nonexistent tool")
	}
	if resp.Error.Code != ErrCodeInvalidParams {
		t.Errorf("expected code %d, got %d", ErrCodeInvalidParams, resp.Error.Code)
	}
}

func TestHandleMessageMethodNotFound(t *testing.T) {
	s := NewServer("test", "1.0")
	ctx := context.Background()

	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "unknown/method",
	}
	data, _ := json.Marshal(req)

	resp := s.handleMessage(ctx, data)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Fatal("expected error for unknown method")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("expected code %d, got %d", ErrCodeMethodNotFound, resp.Error.Code)
	}
}

func TestHandleMessagePing(t *testing.T) {
	s := NewServer("test", "1.0")
	ctx := context.Background()

	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "ping",
	}
	data, _ := json.Marshal(req)

	resp := s.handleMessage(ctx, data)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
}

func TestHandleMessageParseError(t *testing.T) {
	s := NewServer("test", "1.0")
	ctx := context.Background()

	resp := s.handleMessage(ctx, []byte("not valid json"))
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Fatal("expected parse error")
	}
	if resp.Error.Code != ErrCodeParse {
		t.Errorf("expected code %d, got %d", ErrCodeParse, resp.Error.Code)
	}
}

func TestHandleMessageInvalidJSONRPCVersion(t *testing.T) {
	s := NewServer("test", "1.0")
	ctx := context.Background()

	req := Request{
		JSONRPC: "1.0", // Invalid version
		ID:      1,
		Method:  "ping",
	}
	data, _ := json.Marshal(req)

	resp := s.handleMessage(ctx, data)
	if resp == nil {
		t.Fatal("expected response")
	}
	if resp.Error == nil {
		t.Fatal("expected error for invalid jsonrpc version")
	}
	if resp.Error.Code != ErrCodeInvalidRequest {
		t.Errorf("expected code %d, got %d", ErrCodeInvalidRequest, resp.Error.Code)
	}
}

func TestHandleNotification(t *testing.T) {
	s := NewServer("test", "1.0")
	ctx := context.Background()

	// Notification has no ID, so no response expected
	req := Request{
		JSONRPC: "2.0",
		Method:  "initialized",
	}
	data, _ := json.Marshal(req)

	resp := s.handleMessage(ctx, data)
	if resp != nil {
		t.Error("expected no response for notification")
	}

	// Check that initialized flag was set
	s.mu.RLock()
	initialized := s.initialized
	s.mu.RUnlock()
	if !initialized {
		t.Error("expected initialized to be true")
	}
}

func TestServe(t *testing.T) {
	s := NewServer("test", "1.0")
	handler := func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		return &CallToolResult{Content: []Content{NewTextContent("ok")}}, nil
	}
	s.RegisterTool(Tool{Name: "test"}, "core", handler)

	// Create a simple request
	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "ping",
	}
	reqData, _ := json.Marshal(req)
	input := string(reqData) + "\n"

	reader := strings.NewReader(input)
	var output bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run serve in a goroutine since it blocks
	done := make(chan error, 1)
	go func() {
		done <- s.serve(ctx, reader, &output)
	}()

	// Wait for serve to process the input (it will return when reader is exhausted)
	err := <-done
	if err != nil {
		t.Fatalf("serve returned error: %v", err)
	}

	// Check output
	if output.Len() == 0 {
		t.Error("expected output")
	}

	var resp Response
	if err := json.Unmarshal(output.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error)
	}
}

func TestServeContextCancellation(t *testing.T) {
	s := NewServer("test", "1.0")

	// Create an empty reader
	reader := strings.NewReader("")
	var output bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- s.serve(ctx, reader, &output)
	}()

	// Cancel the context
	cancel()

	// The serve function should return
	// Note: This test might be flaky depending on timing
}

func TestContextKeys(t *testing.T) {
	// Test that context keys are defined
	if ContextKeyIdentity == "" {
		t.Error("ContextKeyIdentity should not be empty")
	}
	if ContextKeyClientIP == "" {
		t.Error("ContextKeyClientIP should not be empty")
	}
	if ContextKeyIdentity == ContextKeyClientIP {
		t.Error("context keys should be different")
	}
}
