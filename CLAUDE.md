# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP System Info is a read-only MCP (Model Context Protocol) server that provides structured, auditable access to system state for AI diagnostics. It's designed for production environments where AI-assisted diagnostics are needed without shell access risks.

## Build & Development Commands

```bash
# Build
go build -o mcp-sysinfo ./cmd/mcp-sysinfo
go build -o mcp-token-server ./cmd/mcp-token-server

# Run tests
go test -v ./...                                           # Unit tests
go test -v -race -coverprofile=coverage.out ./...         # With race detection
INTEGRATION_TEST=true go test -v -tags=integration ./test/integration/...  # Integration tests

# Run a single test
go test -v -run TestFunctionName ./internal/cpu/...

# Lint and security
golangci-lint run ./...
gosec -quiet ./...
gofmt -w .

# Test a query directly (bypasses MCP protocol)
./mcp-sysinfo --query get_cpu_info --json
./mcp-sysinfo --query get_capabilities --pid 1 --json
```

## Architecture

### MCP Server Layer (`internal/mcp/`)
- `server.go` - JSON-RPC 2.0 server over stdio, handles MCP protocol
- `tools.go` - Registers all tools with the server, maps tool names to collectors
- `http.go` - HTTP transport with OAuth/OIDC authentication
- `protocol.go` - MCP protocol types and constants

### Collector Pattern
Each system metric category has its own collector in `internal/`:
- Collectors implement platform-specific data gathering (`*_linux.go`, `*_darwin.go`, `*_windows.go`)
- Common interface defined in the base file (e.g., `cpu.go`)
- Build tags control platform compilation

**Key collectors:**
- `cpu`, `memory`, `disk`, `network`, `process`, `uptime`, `temperature` - Core metrics
- `logs` - System/app log access
- `scheduled`, `kernel`, `netconfig`, `filesystem`, `security` - System hooks
- `hardware`, `resources`, `state` - Hardware and state info

### Tool Registration Flow
1. `cmd/mcp-sysinfo/main.go` creates server and calls `mcp.RegisterAllTools()`
2. `internal/mcp/tools.go` registers each tool with name, scope, and handler
3. Handler instantiates the appropriate collector and returns JSON results
4. Tools are organized by scope: `core`, `logs`, `hooks`, `sensitive`, `hardware`, `resources`, `state`

### Types (`pkg/types/`)
Shared types for log queries and other cross-package structures.

## Git Workflow

Use conventional commits for semantic-release:
- `fix:` - Patch release
- `feat:` - Minor release
- `BREAKING CHANGE:` - Major release

Lefthook runs pre-commit (gofmt, go-vet, golangci-lint, gosec) and pre-push (tests, full lint, security scan).

## Cross-Platform Development

Platform-specific code uses build constraints:
```go
//go:build linux
// +build linux
```

When adding a new query:
1. Add collector methods for each platform
2. Return empty results (not errors) for unsupported platforms
3. Register the tool in `internal/mcp/tools.go`
4. Add CLI support in `cmd/mcp-sysinfo/main.go` runQuery()

## CI/CD

- CI runs on push to main/develop and PRs
- `semantic-release` creates GitHub releases on main
- SLSA release workflow triggers on `release: [published]` events
- Builds for linux/darwin/windows on amd64/arm64
