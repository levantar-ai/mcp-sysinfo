# MCP System Info

**Read-only AI diagnostics plane for secure incident triage and evidence capture.**

A security-first MCP server that provides structured, auditable access to system state without granting shell access to AI agents. Designed for production environments where you need AI-assisted diagnostics without the risks of arbitrary command execution.

## Why This Exists

| Traditional AI Shell Access | MCP System Info |
|----------------------------|-----------------|
| AI can run arbitrary commands | Constrained to vetted read-only queries |
| Output parsing is fragile | Structured JSON with consistent schemas |
| No audit trail | Every query logged with identity |
| Secrets leak via env/history | Automatic redaction of credentials |
| Resource impact unbounded | Hard limits on CPU, memory, time |

## Quick Start

```bash
# Build
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Run (stdio mode - for MCP clients)
./mcp-sysinfo

# Query directly
./mcp-sysinfo --query get_cpu_info --json
```

## Current Status

| Phase | Focus | Queries |
|-------|-------|---------|
| **1.0** | Core Metrics | 7/7 |
| **1.5** | Log Access | 6/6 |
| **1.6** | System Hooks | 31/31 |
| **1.7** | SBOM & Inventory | 13/31 |
| **1.9** | Triage & Summary | 5/25 |

**62 queries implemented** across Linux, macOS, and Windows.

## Features

- **Zero Dependencies** - Uses only native OS APIs
- **Cross-Platform** - Linux, macOS, Windows support
- **Secure by Default** - Sensitive queries disabled by default
- **Automatic Redaction** - AWS keys, passwords, tokens stripped
- **Audit Logging** - JSON Lines format with client identity
- **Resource Limits** - Hard caps on CPU, memory, time per query

## Next Steps

- [Installation](getting-started/installation.md) - Build and install
- [Quick Start](getting-started/quickstart.md) - First queries
- [Query Reference](queries/index.md) - All available queries
- [Security](security/index.md) - Authentication and deployment
- [SaaS Agent Mode](deployment/saas-agent.md) - Run as a managed SaaS agent
- [Building Plugins](extending/plugins.md) - Extend with custom queries
