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
| **HTTP + OIDC** | Enterprise IdP (Okta, Azure AD, Auth0) |
| **HTTP + OAuth** | Custom auth server with token introspection |
| **SSH tunnel** | Remote access with existing SSH infrastructure |
| **Teleport MCP** | Enterprise SSO + RBAC + session recording |

---

## What Works Today

**Status: Phase 1.7 In Progress (51 queries implemented)**

### Phase 1: Core Metrics (7/7)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_cpu_info` | Usage, frequency, load average, cores | ✅ | ✅ | ✅ |
| `get_memory_info` | Total, used, available, swap | ✅ | ✅ | ✅ |
| `get_disk_info` | Partitions, usage, I/O stats | ✅ | ✅ | ✅ |
| `get_network_info` | Interfaces, I/O, connections | ✅ | ✅ | ✅ |
| `get_processes` | Process list, top by CPU/memory | ✅ | ✅ | ✅ |
| `get_uptime` | Boot time, uptime duration | ✅ | ✅ | ✅ |
| `get_temperature` | Hardware temperature sensors | ✅ | ⚠️ | ⚠️ |

### Phase 1.5: Log Access (6/6)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_journal_logs` | Systemd journal | ✅ | - | - |
| `get_syslog` | Traditional syslog | ✅ | ✅ | - |
| `get_kernel_logs` | Kernel/dmesg logs | ✅ | ✅ | - |
| `get_auth_logs` | Authentication logs (sensitive) | ✅ | ✅ | - |
| `get_app_logs` | Application-specific logs | ✅ | ✅ | ✅ |
| `get_event_log` | Windows Event Log | - | - | ✅ |

### Phase 1.6: System Hooks (31/31)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_scheduled_tasks` | Task Scheduler / at jobs / launchd | ✅ | ✅ | ✅ |
| `get_cron_jobs` | Cron entries | ✅ | ✅ | - |
| `get_startup_items` | Startup programs and services | ✅ | ✅ | ✅ |
| `get_systemd_services` | Systemd service status | ✅ | - | - |
| `get_kernel_modules` | Loaded kernel modules | ✅ | ✅ | - |
| `get_loaded_drivers` | Device drivers | ✅ | ✅ | ✅ |
| `get_dns_servers` | Configured DNS servers | ✅ | ✅ | ✅ |
| `get_routes` | Routing table | ✅ | ✅ | ✅ |
| `get_firewall_rules` | Firewall rules | ✅ | ✅ | ✅ |
| `get_listening_ports` | Listening network ports | ✅ | ✅ | ✅ |
| `get_arp_table` | ARP table entries | ✅ | ✅ | ✅ |
| `get_network_stats` | Network stack statistics | ✅ | ✅ | ✅ |
| `get_mounts` | Mounted filesystems | ✅ | ✅ | ✅ |
| `get_disk_io` | Disk I/O statistics | ✅ | ✅ | ✅ |
| `get_open_files` | Open file descriptors | ✅ | ✅ | ✅ |
| `get_inode_usage` | Inode usage | ✅ | ✅ | - |
| `get_hardware_info` | System/BIOS/motherboard info | ✅ | ✅ | ✅ |
| `get_usb_devices` | Connected USB devices | ✅ | ✅ | ✅ |
| `get_pci_devices` | PCI devices | ✅ | ✅ | ✅ |
| `get_block_devices` | Block device topology | ✅ | ✅ | ✅ |
| `get_process_environ` | Process environment variables | ✅ | - | - |
| `get_ipc_resources` | IPC resources (shm, sem, msg) | ✅ | - | - |
| `get_namespaces` | Linux namespaces | ✅ | - | - |
| `get_cgroups` | Cgroup limits and usage | ✅ | - | - |
| `get_capabilities` | Process capabilities | ✅ | - | - |
| `get_vm_info` | VM/container detection | ✅ | ✅ | ✅ |
| `get_timezone` | Timezone and locale info | ✅ | ✅ | ✅ |
| `get_ntp_status` | NTP synchronization status | ✅ | ✅ | ✅ |
| `get_core_dumps` | Core dump information | ✅ | ✅ | ✅ |
| `get_power_state` | Power/battery state | ✅ | ✅ | ✅ |
| `get_numa_topology` | NUMA topology | ✅ | - | - |

### Phase 1.7: Software Inventory (7/31)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_path_executables` | Executables in PATH directories | ✅ | ✅ | ✅ |
| `get_system_packages` | Installed system packages | ✅ | ✅ | ✅ |
| `get_python_packages` | Python packages from site-packages | ✅ | ✅ | ✅ |
| `get_node_packages` | Global Node.js packages | ✅ | ✅ | ✅ |
| `get_go_modules` | Go modules from GOPATH/pkg/mod | ✅ | ✅ | ✅ |
| `get_rust_packages` | Rust crates from .cargo/registry | ✅ | ✅ | ✅ |
| `get_ruby_gems` | Ruby gems from specifications | ✅ | ✅ | ✅ |

**Package managers supported:**
- System: dpkg, rpm, apk, pacman, Homebrew, pkgutil, Chocolatey, winget
- Language: pip (Python), npm (Node.js), go modules, Cargo (Rust), RubyGems

> ⚠️ **Note:** `get_path_executables` only scans PATH directories, not the entire filesystem. For complete software inventory, use `get_system_packages`.

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

### Phase 1.6: System Hooks ✅ Complete (24 queries)

Deep introspection: scheduled tasks, kernel modules, network config, mounts, cgroups.

See [docs/08-system-hooks.md](docs/08-system-hooks.md)

### Phase 1.7: SBOM & Inventory (In Progress - 7/31 queries)

Software Bill of Materials for vulnerability detection.

**Implemented:**
- PATH executables discovery
- System package managers (dpkg, rpm, apk, pacman, brew, choco, winget)
- Language package managers (pip, npm, go modules, Cargo, RubyGems)

**Remaining queries:**
- Additional language package managers (Maven, Composer, NuGet)
- Container images (Docker API)
- SBOM export (CycloneDX, SPDX)
- Vulnerability lookup (OSV, NVD)

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

## HTTP Transport with Authentication

For remote access with OAuth 2.1 / OIDC authentication:

### Option 1: OIDC (Enterprise IdP)

Integrate with your existing identity provider (Okta, Azure AD, Auth0, Keycloak):

```bash
# Run with OIDC authentication
mcp-sysinfo --transport http \
    --listen 0.0.0.0:8443 \
    --tls-cert /etc/mcp/cert.pem \
    --tls-key /etc/mcp/key.pem \
    --oidc-issuer https://enterprise.okta.com \
    --oidc-audience mcp-sysinfo
```

The MCP server fetches JWKS from the IdP and validates tokens locally.

### Option 2: OAuth Token Introspection

Use the built-in token server or any OAuth 2.1 authorization server:

```bash
# Start the built-in token server
mcp-token-server serve \
    --listen 127.0.0.1:8444 \
    --issuer http://localhost:8444 \
    --audience mcp-sysinfo \
    --clients /etc/mcp/clients.json

# Start MCP server with OAuth introspection
mcp-sysinfo --transport http \
    --listen 127.0.0.1:8080 \
    --auth-server http://127.0.0.1:8444 \
    --client-id mcp-sysinfo \
    --client-secret $SECRET
```

### Get a Token and Call the API

```bash
# Get access token (client credentials flow)
TOKEN=$(curl -s -X POST http://localhost:8444/token \
    -d "grant_type=client_credentials" \
    -d "client_id=myapp" \
    -d "client_secret=mysecret" \
    | jq -r '.access_token')

# Call MCP server with token
curl -X POST http://localhost:8080/ \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_uptime"}}'
```

### CLI Flags Reference

| Flag | Description |
|------|-------------|
| `--transport http` | Enable HTTP transport (default: stdio) |
| `--listen <addr>` | Listen address (default: 127.0.0.1:8080) |
| `--server-url <url>` | Public server URL for OAuth metadata |
| `--tls-cert <file>` | TLS certificate file |
| `--tls-key <file>` | TLS key file |
| `--oidc-issuer <url>` | OIDC issuer URL (e.g., https://okta.com) |
| `--oidc-audience <str>` | Expected JWT audience claim |
| `--auth-server <url>` | OAuth auth server for introspection |
| `--client-id <id>` | Client ID for introspection |
| `--client-secret <str>` | Client secret for introspection |

See [SECURITY.md](SECURITY.md) for complete authentication documentation.

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
| [docs/08-system-hooks.md](docs/08-system-hooks.md) | Phase 1.6: 31 deep introspection queries |
| [docs/09-sbom-inventory.md](docs/09-sbom-inventory.md) | Phase 1.7: Software inventory |
| [docs/10-query-profiles.md](docs/10-query-profiles.md) | Query profiles for efficient investigations |
| [docs/11-platform-native-features.md](docs/11-platform-native-features.md) | Platform-specific native APIs (WMI, procfs, IOKit) |

---

## Project Status

| Phase | Focus | Progress | Queries |
|-------|-------|----------|---------|
| **1.0** | Core Metrics | ✅ Complete | 7/7 |
| **1.5** | Log Access | ✅ Complete | 6/6 |
| **1.6** | System Hooks | ✅ Complete | 31/31 |
| **1.7** | SBOM & Inventory | 🚧 In Progress | 7/31 |
| **1.8** | App Discovery & Config | 📋 Planned | 0/2 |
| **1.9** | Triage & Summary | 📋 Planned | 0/25 |
| **1.10** | Windows Enterprise | 📋 Planned | 0/15 |
| 2 | GPU, Containers, Services | 📋 Planned | 0/6 |
| 3 | Storage Deep Dive | 📋 Planned | 0/5 |
| 4 | Network Intelligence | 📋 Planned | 0/5 |
| 5 | Analytics & Trends | 📋 Planned | 0/4 |
| 6 | Automation & Alerting | 📋 Planned | 0/5 |
| 7 | Security & Compliance | 📋 Planned | 0/5 |
| 8 | Integration & Plugins | 📋 Planned | 0/4 |
| 9 | LLM Features | 📋 Planned | 0/3 |

**Implemented: 51/149 queries (34%)**

**Phase 1.10 Windows Enterprise Features:**
- Registry queries (read keys, enumerate, security descriptors)
- DCOM/COM security (applications, permissions, identities)
- IIS web server (sites, app pools, bindings, SSL, handlers)

### Cross-Platform Architecture

All queries are cross-platform (Linux, macOS, Windows) using only native OS APIs:

| Category | Linux | macOS | Windows |
|----------|-------|-------|---------|
| System Info | `/proc`, sysctl | sysctl, IOKit | WMI, Registry |
| Services | systemd, sysvinit | launchd | SCM, Event Log |
| Logs | journald, syslog | unified logs | Event Log |
| Firewall | iptables/nftables | pfctl | NetFirewallRule |

**No external dependencies required.** See [TODO.md](TODO.md) for full implementation details.

---

## License

MIT
