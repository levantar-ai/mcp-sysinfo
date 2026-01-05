# Plugin Architecture Design

## Overview

MCP System Info supports a plugin architecture that allows external plugin repositories to extend the core functionality. Plugins are compiled into the binary at build time, not loaded dynamically at runtime.

## Design Goals

1. **Clean separation**: Core functionality in OSS, premium plugins in separate repos
2. **Build-time integration**: Plugins compiled in, no runtime plugin loading
3. **Interface-driven**: Plugins implement well-defined interfaces from the core
4. **Zero duplication**: Plugin repos contain only plugin code, not core code

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Build Time                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐         ┌──────────────────────────────┐  │
│  │  mcp-sysinfo     │         │  mcp-sysinfo-pro             │  │
│  │  (OSS Core)      │         │  (Plugin Source Only)        │  │
│  │                  │         │                              │  │
│  │  - Core queries  │ ◄────── │  - Plugin implementations    │  │
│  │  - Interfaces    │         │  - Plugin registration       │  │
│  │  - MCP server    │         │  - Enterprise configs        │  │
│  │  - Build system  │         │                              │  │
│  └──────────────────┘         └──────────────────────────────┘  │
│           │                              │                       │
│           └──────────────┬───────────────┘                       │
│                          ▼                                       │
│                 ┌─────────────────┐                              │
│                 │  Combined Build │                              │
│                 │  (go build)     │                              │
│                 └────────┬────────┘                              │
│                          ▼                                       │
│                 ┌─────────────────┐                              │
│                 │ mcp-sysinfo-pro │                              │
│                 │    (binary)     │                              │
│                 └─────────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### Plugin Interface

```go
// pkg/plugin/plugin.go

package plugin

import "github.com/levantar-ai/mcp-sysinfo/internal/mcp"

// Plugin defines the interface all plugins must implement
type Plugin interface {
    // Name returns the plugin identifier
    Name() string

    // Version returns the plugin version
    Version() string

    // Scope returns the permission scope for this plugin
    Scope() string

    // Register registers the plugin's tools with the MCP server
    Register(server *mcp.Server) error
}

// Registry holds all registered plugins
type Registry struct {
    plugins map[string]Plugin
}

// Global registry instance
var DefaultRegistry = &Registry{
    plugins: make(map[string]Plugin),
}

// Register adds a plugin to the registry
func (r *Registry) Register(p Plugin) {
    r.plugins[p.Name()] = p
}

// GetAll returns all registered plugins
func (r *Registry) GetAll() []Plugin {
    result := make([]Plugin, 0, len(r.plugins))
    for _, p := range r.plugins {
        result = append(result, p)
    }
    return result
}
```

### Collector Interface

```go
// pkg/plugin/collector.go

package plugin

import "context"

// Collector defines the interface for data collection
type Collector interface {
    // Collect gathers data and returns JSON-serializable result
    Collect(ctx context.Context, params map[string]interface{}) (interface{}, error)
}

// CollectorFunc is a function adapter for Collector
type CollectorFunc func(ctx context.Context, params map[string]interface{}) (interface{}, error)

func (f CollectorFunc) Collect(ctx context.Context, params map[string]interface{}) (interface{}, error) {
    return f(ctx, params)
}
```

### Connection Interface

```go
// pkg/plugin/connection.go

package plugin

import "context"

// ConnectionConfig holds connection parameters (credentials redacted in output)
type ConnectionConfig struct {
    Host     string
    Port     int
    Username string
    Password string // Never logged or returned
    Database string
    Options  map[string]string
}

// Connector defines interface for plugins that connect to external systems
type Connector interface {
    // Connect establishes connection using config
    Connect(ctx context.Context, config ConnectionConfig) error

    // Close closes the connection
    Close() error

    // IsConnected returns connection status
    IsConnected() bool
}
```

## Plugin Structure

Plugins in the pro repo follow this structure:

```
mcp-sysinfo-pro/
├── plugins/
│   ├── databases/
│   │   ├── mysql/
│   │   │   ├── mysql.go           # Plugin registration
│   │   │   ├── collector.go       # Query implementations
│   │   │   ├── mysql_linux.go     # Platform-specific
│   │   │   ├── mysql_darwin.go
│   │   │   ├── mysql_windows.go
│   │   │   └── mysql_test.go
│   │   ├── postgresql/
│   │   ├── mongodb/
│   │   └── ...
│   ├── security/
│   │   ├── crowdstrike/
│   │   ├── sentinelone/
│   │   └── ...
│   └── registry.go                # Auto-registers all plugins
├── docs/
│   └── ENTERPRISE_PLUGINS.md
├── go.mod                         # References mcp-sysinfo as dependency
└── .github/
    └── workflows/
        └── build.yml              # Clones OSS, builds with plugins
```

## Plugin Implementation Example

```go
// plugins/databases/mysql/mysql.go

package mysql

import (
    "github.com/levantar-ai/mcp-sysinfo/internal/mcp"
    "github.com/levantar-ai/mcp-sysinfo/pkg/plugin"
)

func init() {
    plugin.DefaultRegistry.Register(&MySQLPlugin{})
}

type MySQLPlugin struct{}

func (p *MySQLPlugin) Name() string    { return "mysql" }
func (p *MySQLPlugin) Version() string { return "1.0.0" }
func (p *MySQLPlugin) Scope() string   { return "mysql" }

func (p *MySQLPlugin) Register(server *mcp.Server) error {
    server.RegisterTool(mcp.Tool{
        Name:        "get_mysql_status",
        Description: "Get MySQL server status variables",
        InputSchema: mcp.InputSchema{
            Type: "object",
            Properties: map[string]mcp.Property{
                "host": {Type: "string", Description: "MySQL host"},
                "port": {Type: "integer", Description: "MySQL port", Default: 3306},
            },
        },
    }, p.Scope(), p.handleGetStatus)

    // Register more tools...
    return nil
}

func (p *MySQLPlugin) handleGetStatus(params map[string]interface{}) (interface{}, error) {
    collector := NewStatusCollector()
    return collector.Collect(context.Background(), params)
}
```

## Build Process

The pro repo CI builds as follows:

```yaml
# In mcp-sysinfo-pro/.github/workflows/build.yml

jobs:
  build:
    steps:
      - name: Checkout plugin repo
        uses: actions/checkout@v4

      - name: Checkout OSS core
        uses: actions/checkout@v4
        with:
          repository: levantar-ai/mcp-sysinfo
          path: core

      - name: Setup build directory
        run: |
          # Create combined module
          mkdir -p build
          cp -r core/* build/
          cp -r plugins build/internal/plugins

          # Update imports to use local plugins
          cd build
          go mod edit -replace github.com/levantar-ai/mcp-sysinfo-pro/plugins=./internal/plugins

      - name: Build with plugins
        run: |
          cd build
          go build -tags enterprise -o ../mcp-sysinfo-pro ./cmd/mcp-sysinfo
```

## Registration in Core

The OSS core has a plugin initialization hook:

```go
// cmd/mcp-sysinfo/main.go

package main

import (
    "github.com/levantar-ai/mcp-sysinfo/internal/mcp"
    "github.com/levantar-ai/mcp-sysinfo/pkg/plugin"

    // Enterprise plugins imported via build tag
    _ "github.com/levantar-ai/mcp-sysinfo/internal/plugins" // +build enterprise
)

func main() {
    server := mcp.NewServer()

    // Register core tools
    mcp.RegisterAllTools(server)

    // Register plugins from registry
    for _, p := range plugin.DefaultRegistry.GetAll() {
        if err := p.Register(server); err != nil {
            log.Printf("Failed to register plugin %s: %v", p.Name(), err)
        }
    }

    server.Run()
}
```

## Build Tags

- `enterprise` - Include enterprise plugin registration
- `mysql` - Include MySQL plugin only
- `security` - Include security plugins only
- Individual plugin tags for granular builds

## Security Considerations

1. **Credential handling**: All connection configs use the core redaction system
2. **No secrets in output**: Plugin collectors must never return credentials
3. **Scope enforcement**: Each plugin declares its scope, enforced by core
4. **Audit logging**: All plugin queries logged through core audit system

## Versioning

- Plugins specify minimum core version compatibility
- Core maintains stable plugin interfaces with semantic versioning
- Breaking interface changes require major version bump

## Future Considerations

1. **Plugin marketplace**: Registry of available plugins
2. **License validation**: Enterprise license checking at runtime
3. **Plugin updates**: Version checking and update notifications
4. **Custom plugins**: Documentation for third-party plugin development
