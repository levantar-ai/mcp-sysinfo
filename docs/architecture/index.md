# Architecture

MCP System Info is designed as a secure, cross-platform diagnostics server that provides structured access to system state.

## Design Principles

### 1. Read-Only Operations

All queries are strictly read-only. The server has no ability to modify system state, write files, or execute arbitrary commands.

### 2. Zero Dependencies

Uses only native OS APIs:

- **Linux**: procfs, sysfs, system calls
- **macOS**: sysctl, IOKit, FSEvents
- **Windows**: WMI, Registry, native APIs

No external binaries or libraries required.

### 3. Structured Output

All responses are JSON with consistent schemas. No parsing of human-readable text output.

### 4. Defense in Depth

Multiple layers of security:

- Scope-based access control
- Automatic credential redaction
- Resource limits (CPU, memory, time)
- Audit logging

## Component Overview

```
┌─────────────────────────────────────────────────────────┐
│                    MCP Clients                          │
│         (Claude Desktop, HTTP clients, etc.)            │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                  Transport Layer                         │
│              (stdio / HTTP / future)                     │
├─────────────────────────────────────────────────────────┤
│                  Protocol Layer                          │
│              (JSON-RPC 2.0 / MCP)                        │
├─────────────────────────────────────────────────────────┤
│                  Query Router                            │
│         (Scope validation, rate limiting)                │
├─────────────────────────────────────────────────────────┤
│                  Query Handlers                          │
│      (Core, Logs, Hooks, SBOM, Sensitive)               │
├─────────────────────────────────────────────────────────┤
│                Platform Abstraction                      │
│           (Linux / macOS / Windows)                      │
├─────────────────────────────────────────────────────────┤
│                  Native APIs                             │
│     (procfs, sysctl, WMI, Registry, etc.)               │
└─────────────────────────────────────────────────────────┘
```

## Query Lifecycle

1. **Request**: Client sends JSON-RPC request
2. **Authentication**: Token validated (HTTP mode)
3. **Scope Check**: Query scope verified against enabled scopes
4. **Resource Limits**: Goroutine spawned with CPU/memory/time limits
5. **Execution**: Platform-specific handler executes
6. **Redaction**: Sensitive values stripped from response
7. **Audit**: Query logged with duration and outcome
8. **Response**: JSON result returned to client

## Package Structure

```
mcp-sysinfo/
├── cmd/
│   ├── mcp-sysinfo/    # Main binary
│   └── docgen/         # Documentation generator
├── internal/
│   ├── mcp/            # MCP protocol implementation
│   ├── transport/      # Stdio and HTTP transports
│   ├── queries/        # Query router and handlers
│   ├── core/           # Core metrics (CPU, memory, etc.)
│   ├── logs/           # Log access queries
│   ├── hooks/          # System hooks queries
│   ├── software/       # SBOM queries
│   └── redact/         # Credential redaction
└── docs/               # Documentation source
```

## Further Reading

- [Cross-Platform](cross-platform.md) - Platform-specific implementations
- [JSON-RPC API](../api/jsonrpc.md) - Protocol specification
- [Schemas](../api/schemas.md) - Response schemas
