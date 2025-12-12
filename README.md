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

## Security Model

See **[SECURITY.md](SECURITY.md)** for the complete security architecture.

### Key Principles

| Principle | Implementation |
|-----------|----------------|
| **Defense in depth** | Transport security + auth + scopes + redaction + limits |
| **Localhost by default** | No network listener unless explicitly configured |
| **Sensitive queries disabled** | Auth logs, env vars, user accounts require opt-in |
| **Automatic redaction** | AWS keys, passwords, tokens stripped from output |
| **Audit everything** | JSON Lines audit log with client identity |

### Query Classification

| Scope | Risk | Default |
|-------|------|---------|
| `core` - CPU, memory, disk, network, processes | Low | Enabled |
| `logs` - System and application logs | Medium | Enabled |
| `hooks` - Scheduled tasks, kernel modules, network config | Medium | Enabled |
| `sbom` - Package inventory, container images | Medium | Enabled |
| `sensitive` - Auth logs, env vars, SSH/sudo config | **High** | **Disabled** |

### Deployment Options

| Model | Use Case |
|-------|----------|
| **stdio** (default) | Local MCP client (Claude Desktop) |
| **SSH tunnel** | Remote access with existing SSH infrastructure |
| **Teleport MCP** | Enterprise SSO + RBAC + session recording |
| **mTLS** | Service-to-service automation |

---

## What Works Today

**Status: Phase 1 MVP Complete (7/7 queries)**

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_cpu_info` | Usage, frequency, load average, cores | Yes | Yes | Yes |
| `get_memory_info` | Total, used, available, swap | Yes | Yes | Yes |
| `get_disk_info` | Partitions, usage, I/O stats | Yes | Yes | Yes |
| `get_network_info` | Interfaces, I/O, connections | Yes | Yes | Yes |
| `get_processes` | Process list, top by CPU/memory | Yes | Yes | Yes |
| `get_uptime` | Boot time, uptime duration | Yes | Yes | Yes |
| `get_temperature` | Hardware temperature sensors | Yes | Limited | Limited |

### What You Can Do Now

```bash
# Build
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Run (stdio mode - for MCP clients)
./mcp-sysinfo

# Run via SSH (remote host)
ssh user@server "mcp-sysinfo"
```

### Resource Impact

Every query respects strict budgets:

| Impact | CPU | Memory | Time | Behavior |
|--------|-----|--------|------|----------|
| Minimal | <1% | <1MB | <100ms | Always allowed |
| Low | <5% | <10MB | <1s | Default allowed |
| Medium | <10% | <50MB | <5s | Requires opt-in |
| High | - | - | - | **Blocked** |

---

## Roadmap

### Phase 1.5: Log Access (Next)

Without logs, AI can only see symptoms. With logs, AI can diagnose root causes.

| Query | Description |
|-------|-------------|
| `get_journal_logs` | Systemd journal |
| `get_syslog` | Traditional syslog |
| `get_app_logs` | Application-specific logs |
| `get_kernel_logs` | dmesg, boot, hardware |
| `get_auth_logs` | Login/sudo/SSH (sensitive scope) |
| `get_event_log` | Windows Event Viewer |

### Phase 1.6: System Hooks (37 queries)

Deep introspection: scheduled tasks, kernel modules, network config, mounts, cgroups.

See [docs/08-system-hooks.md](docs/08-system-hooks.md)

### Phase 1.7: SBOM & Inventory (31 queries)

Software Bill of Materials for vulnerability detection.

See [docs/09-sbom-inventory.md](docs/09-sbom-inventory.md)

### Future Phases

| Phase | Focus |
|-------|-------|
| 2 | GPU, containers, services |
| 3 | Analytics, trends, anomaly detection |
| 4 | Compliance scoring, forensics |
| 5 | Prometheus export, plugins |
| 6 | Natural language queries |

---

## Installation

### Prerequisites

- Go 1.22+
- No external dependencies (uses only OS built-in tools)

### Build

```bash
# Clone
git clone https://github.com/yourorg/mcp-sysinfo
cd mcp-sysinfo

# Build for current platform
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o mcp-sysinfo-linux ./cmd/mcp-sysinfo
GOOS=darwin GOARCH=arm64 go build -o mcp-sysinfo-darwin ./cmd/mcp-sysinfo
GOOS=windows GOARCH=amd64 go build -o mcp-sysinfo.exe ./cmd/mcp-sysinfo
```

### Configure for Remote Access

See [SECURITY.md](SECURITY.md) for complete configuration reference.

```yaml
# /etc/mcp-sysinfo/config.yaml

# Transport: stdio (default), unix, pipe, https
transport: unix
socket:
  path: /var/run/mcp-sysinfo.sock
  mode: 0600

# Authentication (required for https)
auth:
  enabled: true
  jwt:
    issuer: "https://auth.example.com"
    audience: "mcp-sysinfo"
    jwks_uri: "https://auth.example.com/.well-known/jwks.json"

# Scopes
queries:
  sensitive:
    enabled: false  # Explicit opt-in required

# Audit
audit:
  enabled: true
  path: /var/log/mcp-sysinfo/audit.jsonl
```

---

## Teleport Integration

MCP System Info is designed to work with [Teleport's MCP support](https://goteleport.com/docs/machine-id/access-guides/mcp/):

```yaml
# Teleport role for MCP access
kind: role
metadata:
  name: mcp-diagnostics
spec:
  allow:
    mcp_servers:
      - labels:
          app: mcp-sysinfo
        commands:
          - get_cpu_info
          - get_memory_info
          - get_disk_info
          - get_processes
```

Teleport provides:
- SSO authentication (OIDC, SAML, GitHub)
- Role-based access control per query
- Session recording and audit
- Certificate-based host identity

---

## SSH Access

For ad-hoc remote access without additional infrastructure:

```bash
# Direct execution over SSH
ssh user@server "mcp-sysinfo --query get_cpu_info"

# Persistent session for MCP client
ssh -tt user@server "mcp-sysinfo --transport stdio"
```

SSH provides authentication. The server runs in stdio mode with no network listener.

---

## Testing

```bash
# Unit tests
go test -v ./...

# Integration tests (real OS calls)
INTEGRATION_TEST=true go test -v -tags=integration ./test/integration/...
```

---

## Documentation

| Document | Description |
|----------|-------------|
| **[SECURITY.md](SECURITY.md)** | Security architecture, auth, deployment |
| [docs/00-overview.md](docs/00-overview.md) | Architecture and design rationale |
| [docs/08-system-hooks.md](docs/08-system-hooks.md) | Phase 1.6: 37 deep introspection queries |
| [docs/09-sbom-inventory.md](docs/09-sbom-inventory.md) | Phase 1.7: Software inventory |

---

## Project Status

```
Phase 1 (MVP)       ████████████████████  100%  (7/7 queries)
Phase 1.5 (Logs)    ░░░░░░░░░░░░░░░░░░░░    0%  (0/6 queries)
Phase 1.6 (Hooks)   ░░░░░░░░░░░░░░░░░░░░    0%  (0/37 queries)
Phase 1.7 (SBOM)    ░░░░░░░░░░░░░░░░░░░░    0%  (0/31 queries)
```

See [TODO.md](TODO.md) for implementation details.

---

## License

MIT
