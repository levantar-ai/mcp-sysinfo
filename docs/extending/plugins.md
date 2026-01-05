# Building Plugins for MCP System Info

This guide explains how to extend MCP System Info with custom plugins that add new diagnostic queries.

## Overview

MCP System Info uses a **build-time plugin architecture**. Plugins are compiled into the binary—there's no runtime plugin loading. This design provides:

- **Security**: No dynamic code execution
- **Performance**: Zero plugin loading overhead
- **Simplicity**: Standard Go build process
- **Type safety**: Compile-time interface validation

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Your Plugin                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   ┌──────────────────┐         ┌────────────────────────────────┐   │
│   │  mcp-sysinfo     │         │  your-plugin/                  │   │
│   │  (Core)          │         │                                │   │
│   │                  │         │  ├── plugin.go    (init)       │   │
│   │  - MCP Server    │ ◄────── │  ├── collector.go (logic)      │   │
│   │  - RegisterTool  │         │  └── types.go     (structs)    │   │
│   │  - Scope system  │         │                                │   │
│   └──────────────────┘         └────────────────────────────────┘   │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Create Your Plugin Package

```go
// plugins/myservice/plugin.go
package myservice

import (
    "context"

    "github.com/levantar-ai/mcp-sysinfo/internal/mcp"
    "github.com/levantar-ai/mcp-sysinfo/pkg/plugin"
)

// Register plugin at import time
func init() {
    plugin.DefaultRegistry.Register(&MyServicePlugin{})
}

type MyServicePlugin struct{}

func (p *MyServicePlugin) Name() string    { return "myservice" }
func (p *MyServicePlugin) Version() string { return "1.0.0" }
func (p *MyServicePlugin) Scope() string   { return "myservice" }

func (p *MyServicePlugin) Register(server *mcp.Server) error {
    server.RegisterTool(mcp.Tool{
        Name:        "get_myservice_status",
        Description: "Get MyService health and metrics",
        InputSchema: mcp.InputSchema{
            Type: "object",
            Properties: map[string]mcp.Property{
                "endpoint": {
                    Type:        "string",
                    Description: "Service endpoint URL",
                },
            },
        },
    }, p.Scope(), p.handleGetStatus)

    return nil
}

func (p *MyServicePlugin) handleGetStatus(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
    endpoint, _ := args["endpoint"].(string)

    collector := NewCollector()
    result, err := collector.GetStatus(endpoint)
    if err != nil {
        return nil, err
    }

    return &mcp.CallToolResult{
        Content: []mcp.Content{mcp.NewJSONContent(result)},
    }, nil
}
```

### 2. Implement the Collector

```go
// plugins/myservice/collector.go
package myservice

import (
    "net/http"
    "time"
)

type Collector struct {
    client *http.Client
}

func NewCollector() *Collector {
    return &Collector{
        client: &http.Client{Timeout: 10 * time.Second},
    }
}

type StatusResult struct {
    Endpoint  string    `json:"endpoint"`
    Healthy   bool      `json:"healthy"`
    Latency   string    `json:"latency_ms"`
    Timestamp time.Time `json:"timestamp"`
}

func (c *Collector) GetStatus(endpoint string) (*StatusResult, error) {
    start := time.Now()

    resp, err := c.client.Get(endpoint + "/health")
    if err != nil {
        return &StatusResult{
            Endpoint:  endpoint,
            Healthy:   false,
            Timestamp: time.Now(),
        }, nil // Return result, not error - let AI interpret
    }
    defer resp.Body.Close()

    return &StatusResult{
        Endpoint:  endpoint,
        Healthy:   resp.StatusCode == 200,
        Latency:   time.Since(start).String(),
        Timestamp: time.Now(),
    }, nil
}
```

### 3. Register Your Plugin

Create a registry file that imports your plugin:

```go
// plugins/registry.go
//go:build myplugins

package plugins

import (
    _ "your-module/plugins/myservice"
)
```

### 4. Build with Your Plugin

```bash
go build -tags=myplugins -o mcp-sysinfo ./cmd/mcp-sysinfo
```

## Core Interfaces

### Plugin Interface

Every plugin must implement this interface:

```go
// pkg/plugin/plugin.go

type Plugin interface {
    // Name returns a unique identifier for this plugin
    Name() string

    // Version returns the semantic version (e.g., "1.2.3")
    Version() string

    // Scope returns the permission scope for this plugin's tools
    // Users must enable this scope to use the plugin's queries
    Scope() string

    // Register adds the plugin's tools to the MCP server
    Register(server *mcp.Server) error
}
```

### Registry

Plugins register themselves with the global registry:

```go
// In your plugin's init() function:
plugin.DefaultRegistry.Register(&YourPlugin{})
```

The core server iterates the registry at startup:

```go
for _, p := range plugin.DefaultRegistry.GetAll() {
    if err := p.Register(server); err != nil {
        log.Printf("Failed to register plugin %s: %v", p.Name(), err)
    }
}
```

## Registering Tools

Use `server.RegisterTool()` to add MCP-callable tools:

```go
server.RegisterTool(
    mcp.Tool{
        Name:        "get_database_connections",
        Description: "Get active database connection count and details",
        InputSchema: mcp.InputSchema{
            Type: "object",
            Properties: map[string]mcp.Property{
                "database": {
                    Type:        "string",
                    Description: "Database name filter",
                },
                "limit": {
                    Type:        "integer",
                    Description: "Max connections to return",
                    Default:     100,
                },
            },
            Required: []string{"database"},
        },
    },
    "database",  // scope name
    handlerFunc, // func(ctx, args) (*CallToolResult, error)
)
```

### InputSchema Properties

| Field | Type | Description |
|-------|------|-------------|
| `Type` | string | JSON Schema type: `string`, `integer`, `boolean`, `object`, `array` |
| `Description` | string | Help text shown to AI and users |
| `Default` | any | Default value if not provided |
| `Enum` | []string | List of allowed values |

### Handler Function

```go
func handler(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
    // Extract parameters with type assertions
    database, _ := args["database"].(string)
    limit := 100
    if l, ok := args["limit"].(float64); ok { // JSON numbers are float64
        limit = int(l)
    }

    // Do your collection logic
    result, err := collect(database, limit)
    if err != nil {
        return nil, err
    }

    // Return JSON-serializable result
    return &mcp.CallToolResult{
        Content: []mcp.Content{mcp.NewJSONContent(result)},
    }, nil
}
```

## Build Tags

Use Go build tags to control which plugins are included:

```go
//go:build database

package database
```

Build with specific tags:

```bash
# Include only database plugins
go build -tags=database ./cmd/mcp-sysinfo

# Include multiple plugin categories
go build -tags="database,monitoring" ./cmd/mcp-sysinfo

# Include all plugins
go build -tags=allplugins ./cmd/mcp-sysinfo
```

## Cross-Platform Plugins

For platform-specific functionality, use build constraints:

```go
// collector_linux.go
//go:build linux

package myservice

func (c *Collector) GetSystemMetrics() (*Metrics, error) {
    // Linux-specific implementation using /proc, /sys, etc.
}
```

```go
// collector_darwin.go
//go:build darwin

package myservice

func (c *Collector) GetSystemMetrics() (*Metrics, error) {
    // macOS-specific implementation
}
```

```go
// collector_windows.go
//go:build windows

package myservice

func (c *Collector) GetSystemMetrics() (*Metrics, error) {
    // Windows-specific implementation
}
```

For unsupported platforms, return empty results rather than errors:

```go
// collector_other.go
//go:build !linux && !darwin && !windows

package myservice

func (c *Collector) GetSystemMetrics() (*Metrics, error) {
    return &Metrics{
        Supported: false,
        Message:   "Platform not supported",
    }, nil
}
```

## Security Considerations

### 1. Never Return Credentials

```go
// BAD - exposes secrets
type Config struct {
    Host     string `json:"host"`
    Password string `json:"password"` // NEVER!
}

// GOOD - redact sensitive data
type Config struct {
    Host         string `json:"host"`
    PasswordSet  bool   `json:"password_configured"` // Just indicate presence
}
```

### 2. Use the Redaction System

```go
import "github.com/levantar-ai/mcp-sysinfo/internal/redact"

func (c *Collector) GetConfig() (*ConfigResult, error) {
    rawConfig := readConfigFile()

    // Automatically redact passwords, API keys, tokens
    safeConfig := redact.SensitiveData(rawConfig)

    return &ConfigResult{Config: safeConfig}, nil
}
```

### 3. Respect Scope Boundaries

Each plugin should declare its scope. Users must explicitly enable scopes:

```bash
./mcp-sysinfo --scopes=core,logs,myservice
```

### 4. Validate Input

```go
func handler(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
    path, ok := args["path"].(string)
    if !ok || path == "" {
        return nil, fmt.Errorf("path parameter is required")
    }

    // Validate path is within allowed directories
    if !isAllowedPath(path) {
        return nil, fmt.Errorf("access denied: %s", path)
    }

    // Continue...
}
```

## Testing Plugins

### Unit Tests

```go
// plugin_test.go
package myservice

import (
    "context"
    "testing"

    "github.com/levantar-ai/mcp-sysinfo/internal/mcp"
)

func TestGetStatus(t *testing.T) {
    plugin := &MyServicePlugin{}

    server := mcp.NewServer("test", "1.0.0")
    if err := plugin.Register(server); err != nil {
        t.Fatalf("Failed to register: %v", err)
    }

    // Test the collector directly
    collector := NewCollector()
    result, err := collector.GetStatus("http://localhost:8080")
    if err != nil {
        t.Fatalf("GetStatus failed: %v", err)
    }

    if result.Endpoint != "http://localhost:8080" {
        t.Errorf("Expected endpoint in result")
    }
}
```

### Integration Tests

```go
//go:build integration

package myservice

func TestLiveService(t *testing.T) {
    // Test against real service in CI
}
```

Run with:

```bash
go test -tags=integration ./plugins/myservice/...
```

## Example: Database Metrics Plugin

Complete example of a plugin that monitors database connections:

```go
// plugins/dbmetrics/plugin.go
package dbmetrics

import (
    "context"
    "database/sql"
    "time"

    "github.com/levantar-ai/mcp-sysinfo/internal/mcp"
    "github.com/levantar-ai/mcp-sysinfo/pkg/plugin"
)

func init() {
    plugin.DefaultRegistry.Register(&DBMetricsPlugin{})
}

type DBMetricsPlugin struct{}

func (p *DBMetricsPlugin) Name() string    { return "dbmetrics" }
func (p *DBMetricsPlugin) Version() string { return "1.0.0" }
func (p *DBMetricsPlugin) Scope() string   { return "database" }

func (p *DBMetricsPlugin) Register(server *mcp.Server) error {
    // Connection pool stats
    server.RegisterTool(mcp.Tool{
        Name:        "get_db_pool_stats",
        Description: "Get database connection pool statistics",
        InputSchema: mcp.InputSchema{
            Type: "object",
            Properties: map[string]mcp.Property{
                "dsn": {Type: "string", Description: "Database connection string"},
            },
            Required: []string{"dsn"},
        },
    }, p.Scope(), p.handlePoolStats)

    // Slow query log
    server.RegisterTool(mcp.Tool{
        Name:        "get_slow_queries",
        Description: "Get slow query log entries",
        InputSchema: mcp.InputSchema{
            Type: "object",
            Properties: map[string]mcp.Property{
                "dsn":       {Type: "string", Description: "Database connection string"},
                "threshold": {Type: "integer", Description: "Minimum query time in ms", Default: 1000},
                "limit":     {Type: "integer", Description: "Max entries to return", Default: 50},
            },
            Required: []string{"dsn"},
        },
    }, p.Scope(), p.handleSlowQueries)

    return nil
}

type PoolStats struct {
    MaxOpen     int           `json:"max_open_connections"`
    Open        int           `json:"open_connections"`
    InUse       int           `json:"in_use"`
    Idle        int           `json:"idle"`
    WaitCount   int64         `json:"wait_count"`
    WaitTime    time.Duration `json:"wait_duration"`
    Timestamp   time.Time     `json:"timestamp"`
}

func (p *DBMetricsPlugin) handlePoolStats(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
    dsn, _ := args["dsn"].(string)

    db, err := sql.Open("postgres", dsn)
    if err != nil {
        return nil, err
    }
    defer db.Close()

    stats := db.Stats()
    result := &PoolStats{
        MaxOpen:   stats.MaxOpenConnections,
        Open:      stats.OpenConnections,
        InUse:     stats.InUse,
        Idle:      stats.Idle,
        WaitCount: stats.WaitCount,
        WaitTime:  stats.WaitDuration,
        Timestamp: time.Now(),
    }

    return &mcp.CallToolResult{
        Content: []mcp.Content{mcp.NewJSONContent(result)},
    }, nil
}

func (p *DBMetricsPlugin) handleSlowQueries(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
    // Implementation...
    return nil, nil
}
```

## Plugin Directory Structure

Recommended layout for a plugin repository:

```
your-plugins/
├── plugins/
│   ├── database/
│   │   ├── plugin.go           # Plugin registration
│   │   ├── collector.go        # Core logic
│   │   ├── collector_test.go   # Unit tests
│   │   ├── types.go            # Result structs
│   │   └── README.md           # Plugin docs
│   ├── monitoring/
│   │   └── ...
│   └── registry.go             # Imports all plugins
├── go.mod
├── go.sum
└── README.md
```

## Best Practices

1. **Return data, not errors**: Let the AI interpret failures. Return empty results or status fields instead of errors when possible.

2. **Use JSON-serializable types**: All result structs must serialize to JSON cleanly.

3. **Include timestamps**: Add collection timestamps to help AI understand data freshness.

4. **Document tool descriptions**: Write clear descriptions—they're shown to the AI model.

5. **Test cross-platform**: If your plugin has platform-specific code, test on all supported platforms.

6. **Version your plugin**: Use semantic versioning and document breaking changes.

7. **Keep scope names consistent**: Use lowercase, single-word scope names.

## Next Steps

- [Tool Registration Reference](../api/schemas.md) - Full InputSchema specification
- [Security Scopes](../security/scopes.md) - Understanding the scope system
- [Cross-Platform Development](../architecture/cross-platform.md) - Platform-specific patterns
