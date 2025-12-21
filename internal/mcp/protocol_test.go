package mcp

import (
	"encoding/json"
	"testing"
)

func TestNewTextContent(t *testing.T) {
	content := NewTextContent("hello world")
	if content.Type != "text" {
		t.Errorf("expected type 'text', got %q", content.Type)
	}
	if content.Text != "hello world" {
		t.Errorf("expected text 'hello world', got %q", content.Text)
	}
}

func TestNewJSONContent(t *testing.T) {
	data := map[string]interface{}{
		"key": "value",
		"num": 42,
	}
	content := NewJSONContent(data)
	if content.Type != "text" {
		t.Errorf("expected type 'text', got %q", content.Type)
	}
	// Verify it's valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(content.Text), &parsed); err != nil {
		t.Errorf("content.Text is not valid JSON: %v", err)
	}
	if parsed["key"] != "value" {
		t.Errorf("expected key='value', got %v", parsed["key"])
	}
}

func TestNewResponse(t *testing.T) {
	result := map[string]string{"status": "ok"}
	resp := NewResponse(1, result)

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc '2.0', got %q", resp.JSONRPC)
	}
	if resp.ID != 1 {
		t.Errorf("expected id 1, got %v", resp.ID)
	}
	if resp.Error != nil {
		t.Error("expected no error")
	}
	if resp.Result == nil {
		t.Error("expected result to be set")
	}
}

func TestNewResponseWithStringID(t *testing.T) {
	resp := NewResponse("req-123", "success")
	if resp.ID != "req-123" {
		t.Errorf("expected id 'req-123', got %v", resp.ID)
	}
}

func TestNewResponseWithNilID(t *testing.T) {
	resp := NewResponse(nil, "result")
	if resp.ID != nil {
		t.Errorf("expected nil id, got %v", resp.ID)
	}
}

func TestNewErrorResponse(t *testing.T) {
	resp := NewErrorResponse(1, ErrCodeMethodNotFound, "Method not found", "unknown_method")

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc '2.0', got %q", resp.JSONRPC)
	}
	if resp.ID != 1 {
		t.Errorf("expected id 1, got %v", resp.ID)
	}
	if resp.Result != nil {
		t.Error("expected no result")
	}
	if resp.Error == nil {
		t.Fatal("expected error to be set")
	}
	if resp.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("expected code %d, got %d", ErrCodeMethodNotFound, resp.Error.Code)
	}
	if resp.Error.Message != "Method not found" {
		t.Errorf("expected message 'Method not found', got %q", resp.Error.Message)
	}
	if resp.Error.Data != "unknown_method" {
		t.Errorf("expected data 'unknown_method', got %v", resp.Error.Data)
	}
}

func TestNewErrorResponseWithNilData(t *testing.T) {
	resp := NewErrorResponse(1, ErrCodeParse, "Parse error", nil)
	if resp.Error.Data != nil {
		t.Errorf("expected nil data, got %v", resp.Error.Data)
	}
}

func TestErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		code int
		want int
	}{
		{"parse error", ErrCodeParse, -32700},
		{"invalid request", ErrCodeInvalidRequest, -32600},
		{"method not found", ErrCodeMethodNotFound, -32601},
		{"invalid params", ErrCodeInvalidParams, -32602},
		{"internal error", ErrCodeInternal, -32603},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.code != tt.want {
				t.Errorf("expected %d, got %d", tt.want, tt.code)
			}
		})
	}
}

func TestProtocolVersion(t *testing.T) {
	if ProtocolVersion == "" {
		t.Error("ProtocolVersion should not be empty")
	}
	if ProtocolVersion != "2024-11-05" {
		t.Errorf("expected ProtocolVersion '2024-11-05', got %q", ProtocolVersion)
	}
}

func TestRequestSerialization(t *testing.T) {
	req := Request{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	var parsed Request
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}
	if parsed.Method != "tools/list" {
		t.Errorf("expected method 'tools/list', got %q", parsed.Method)
	}
}

func TestResponseSerialization(t *testing.T) {
	resp := NewResponse(1, map[string]string{"status": "ok"})
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}
	var parsed Response
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if parsed.ID != float64(1) { // JSON numbers are float64
		t.Errorf("expected id 1, got %v", parsed.ID)
	}
}

func TestToolSerialization(t *testing.T) {
	tool := Tool{
		Name:        "test_tool",
		Description: "A test tool",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"param1": {Type: "string", Description: "A parameter"},
			},
			Required: []string{"param1"},
		},
	}
	data, err := json.Marshal(tool)
	if err != nil {
		t.Fatalf("failed to marshal tool: %v", err)
	}
	var parsed Tool
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal tool: %v", err)
	}
	if parsed.Name != "test_tool" {
		t.Errorf("expected name 'test_tool', got %q", parsed.Name)
	}
	if len(parsed.InputSchema.Properties) != 1 {
		t.Errorf("expected 1 property, got %d", len(parsed.InputSchema.Properties))
	}
}

func TestCallToolResultSerialization(t *testing.T) {
	result := CallToolResult{
		Content: []Content{
			NewTextContent("result text"),
		},
		IsError: false,
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal result: %v", err)
	}
	var parsed CallToolResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal result: %v", err)
	}
	if len(parsed.Content) != 1 {
		t.Errorf("expected 1 content item, got %d", len(parsed.Content))
	}
	if parsed.Content[0].Text != "result text" {
		t.Errorf("expected text 'result text', got %q", parsed.Content[0].Text)
	}
}
