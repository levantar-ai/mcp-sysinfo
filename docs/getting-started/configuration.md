# Configuration

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--query` | Run a specific query and exit | - |
| `--json` | Output JSON format | false |
| `--http` | Start HTTP server on address | - |
| `--token` | Bearer token for HTTP auth | - |
| `--scopes` | Comma-separated list of enabled scopes | `core,logs,hooks,sbom` |
| `--enable-sensitive` | Enable sensitive scope queries | false |
| `--audit-log` | Path to audit log file | - |
| `--list` | List available queries | false |
| `--version` | Print version and exit | false |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MCP_SYSINFO_TOKEN` | Default bearer token for HTTP mode |
| `MCP_SYSINFO_SCOPES` | Default enabled scopes |
| `MCP_SYSINFO_AUDIT_LOG` | Default audit log path |

## Query Scopes

Queries are organized into security scopes:

| Scope | Risk Level | Default | Description |
|-------|------------|---------|-------------|
| `core` | Low | Enabled | CPU, memory, disk, network, processes |
| `logs` | Medium | Enabled | System logs, journals, event logs |
| `hooks` | Medium | Enabled | Services, kernel modules, network config |
| `sbom` | Medium | Enabled | Package inventory, executables |
| `sensitive` | **High** | **Disabled** | Auth logs, SSH config, sudoers |

### Enabling Sensitive Queries

```bash
# Via command line
./mcp-sysinfo --enable-sensitive

# Via environment variable
export MCP_SYSINFO_SCOPES=core,logs,hooks,sbom,sensitive
./mcp-sysinfo
```

!!! warning "Security Risk"
    Sensitive queries can expose credentials and security configuration.
    Only enable in trusted environments.

## Audit Logging

Enable audit logging to track all queries:

```bash
./mcp-sysinfo --audit-log /var/log/mcp-sysinfo/audit.jsonl
```

Audit log format (JSON Lines):

```json
{"timestamp":"2024-01-15T10:30:00Z","query":"get_cpu_info","client":"claude-desktop","duration_ms":45}
```

## Resource Limits

Built-in resource limits prevent runaway queries:

| Resource | Limit |
|----------|-------|
| CPU | 10% per query |
| Memory | 100MB per query |
| Time | 30 seconds per query |

These limits are not configurable and are enforced at the OS level.

## Next Steps

- [Security Scopes](../security/scopes.md) - Detailed scope documentation
- [Deployment](../security/deployment.md) - Production deployment patterns
