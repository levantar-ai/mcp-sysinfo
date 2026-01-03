// Example Go client for MCP System Info
//
// This example demonstrates how to interact with mcp-sysinfo via HTTP.
//
// Usage:
//
//	go run main.go                    # Uses default http://localhost:8080
//	go run main.go -url http://host:8080 -token mytoken
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

// JSON-RPC 2.0 types
type Request struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP types
type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type CallToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// Client wraps HTTP communication with mcp-sysinfo
type Client struct {
	baseURL string
	token   string
	http    *http.Client
	id      int
}

// NewClient creates a new MCP client
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		http:    &http.Client{},
	}
}

// call sends a JSON-RPC request and returns the response
func (c *Client) call(method string, params interface{}) (*Response, error) {
	c.id++
	req := Request{
		JSONRPC: "2.0",
		ID:      c.id,
		Method:  method,
		Params:  params,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp Response
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w (body: %s)", err, string(respBody))
	}

	if resp.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}

	return &resp, nil
}

// ListTools returns all available tools
func (c *Client) ListTools() ([]Tool, error) {
	resp, err := c.call("tools/list", nil)
	if err != nil {
		return nil, err
	}

	var result ListToolsResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("unmarshal tools: %w", err)
	}

	return result.Tools, nil
}

// CallTool invokes a tool and returns the result
func (c *Client) CallTool(name string, args map[string]interface{}) (*CallToolResult, error) {
	params := CallToolParams{
		Name:      name,
		Arguments: args,
	}

	resp, err := c.call("tools/call", params)
	if err != nil {
		return nil, err
	}

	var result CallToolResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("unmarshal tool result: %w", err)
	}

	return &result, nil
}

func main() {
	url := flag.String("url", "http://localhost:8080", "MCP server URL")
	token := flag.String("token", "", "Bearer token for authentication")
	query := flag.String("query", "", "Query to run (e.g., get_cpu_info)")
	list := flag.Bool("list", false, "List all available tools")
	flag.Parse()

	client := NewClient(*url, *token)

	if *list {
		tools, err := client.ListTools()
		if err != nil {
			log.Fatalf("Failed to list tools: %v", err)
		}

		fmt.Printf("Available tools (%d):\n", len(tools))
		for _, tool := range tools {
			fmt.Printf("  - %s: %s\n", tool.Name, tool.Description)
		}
		return
	}

	if *query == "" {
		// Run a few example queries
		queries := []string{"get_uptime", "get_cpu_info", "get_memory_info"}
		for _, q := range queries {
			fmt.Printf("\n=== %s ===\n", q)
			result, err := client.CallTool(q, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				continue
			}

			if result.IsError {
				fmt.Fprintf(os.Stderr, "Tool returned error\n")
			}

			for _, content := range result.Content {
				if content.Type == "text" {
					// Pretty print JSON
					var parsed interface{}
					if err := json.Unmarshal([]byte(content.Text), &parsed); err == nil {
						pretty, _ := json.MarshalIndent(parsed, "", "  ")
						fmt.Println(string(pretty))
					} else {
						fmt.Println(content.Text)
					}
				}
			}
		}
		return
	}

	// Run specified query
	result, err := client.CallTool(*query, nil)
	if err != nil {
		log.Fatalf("Failed to call %s: %v", *query, err)
	}

	for _, content := range result.Content {
		if content.Type == "text" {
			var parsed interface{}
			if err := json.Unmarshal([]byte(content.Text), &parsed); err == nil {
				pretty, _ := json.MarshalIndent(parsed, "", "  ")
				fmt.Println(string(pretty))
			} else {
				fmt.Println(content.Text)
			}
		}
	}
}
