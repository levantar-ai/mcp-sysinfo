# MCP System Info

[![CI](https://github.com/levantar-ai/mcp-sysinfo/actions/workflows/ci.yml/badge.svg)](https://github.com/levantar-ai/mcp-sysinfo/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Read-only AI diagnostics plane for secure incident triage and evidence capture.**

A security-first MCP server that provides structured, auditable access to system state without granting shell access to AI agents. Designed for production environments where you need AI-assisted di[...] 

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

**Status: Phase 2.3 Complete (123 queries implemented)**

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

### Phase 1.7: Software Inventory ✅ (31/31)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_path_executables` | Executables in PATH directories | ✅ | ✅ | ✅ |
| `get_system_packages` | Installed system packages | ✅ | ✅ | ✅ |
| `get_python_packages` | Python packages from site-packages | ✅ | ✅ | ✅ |
| `get_node_packages` | Global Node.js packages | ✅ | ✅ | ✅ |
| `get_go_modules` | Go modules from GOPATH/pkg/mod | ✅ | ✅ | ✅ |
| `get_rust_packages` | Rust crates from .cargo/registry | ✅ | ✅ | ✅ |
| `get_ruby_gems` | Ruby gems from specifications | ✅ | ✅ | ✅ |
| `get_maven_packages` | Java/Maven packages from ~/.m2 | ✅ | ✅ | ✅ |
| `get_php_packages` | PHP packages from Composer | ✅ | ✅ | ✅ |
| `get_dotnet_packages` | .NET/NuGet packages | ✅ | ✅ | ✅ |
| `get_macos_applications` | Installed macOS applications | - | ✅ | - |
| `get_windows_hotfixes` | Windows hotfixes/updates | - | - | ✅ |
| `get_snap_packages` | Snap packages | ✅ | - | - |
| `get_flatpak_packages` | Flatpak packages | ✅ | - | - |
| `get_homebrew_casks` | Homebrew Casks (macOS GUI apps) | - | ✅ | - |
| `get_scoop_packages` | Scoop packages | - | - | ✅ |
| `get_windows_programs` | Windows programs from registry | - | - | ✅ |
| `get_windows_features` | Windows optional features | - | - | ✅ |
| `get_sbom_cyclonedx` | SBOM export (CycloneDX format) | ✅ | ✅ | ✅ |
| `get_sbom_spdx` | SBOM export (SPDX format) | ✅ | ✅ | ✅ |
| `get_vulnerabilities_osv` | Query OSV for vulnerabilities | ✅ | ✅ | ✅ |
| `get_vulnerabilities_debian` | Query Debian Security Tracker | ✅ | - | - |
| `get_vulnerabilities_nvd` | Query NVD for vulnerabilities | ✅ | ✅ | ✅ |
| `get_docker_images` | Docker images list | ✅ | ✅ | ✅ |
| `get_docker_containers` | Docker containers list | ✅ | ✅ | ✅ |
| `get_docker_image_history` | Docker image layer history | ✅ | ✅ | ✅ |
| `get_npm_lock` | Parse package-lock.json | ✅ | ✅ | ✅ |
| `get_pip_lock` | Parse requirements.txt/Pipfile.lock | ✅ | ✅ | ✅ |
| `get_cargo_lock` | Parse Cargo.lock | ✅ | ✅ | ✅ |
| `get_go_sum` | Parse go.sum | ✅ | ✅ | ✅ |
| `get_gemfile_lock` | Parse Gemfile.lock | ✅ | ✅ | ✅ |

**Package managers supported:**
- System: dpkg, rpm, apk, pacman, Homebrew, pkgutil, Chocolatey, winget, Snap, Flatpak, Scoop
- Language: pip (Python), npm (Node.js), go modules, Cargo (Rust), RubyGems, Maven, Composer (PHP), NuGet (.NET)
- Lock files: package-lock.json, requirements.txt, Pipfile.lock, Cargo.lock, go.sum, Gemfile.lock

> ⚠️ **Note:** `get_path_executables` only scans PATH directories, not the entire filesystem. For complete software inventory, use `get_system_packages`.

### Phase 1.8: Application Discovery ✅ (2/2)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_applications` | Discover installed/running apps (web servers, databases, etc.) | ✅ | ✅ | ✅ |
| `get_app_config` | Read config files with sensitive data redaction | ✅ | ✅ | ✅ |

**Applications detected:**
- Web servers: nginx, Apache, Caddy, Tomcat
- Databases: MySQL/MariaDB, PostgreSQL, MongoDB, Redis, Elasticsearch
- Message queues: RabbitMQ, Kafka
- Caching: Memcached, Varnish
- Runtimes: PHP-FPM, Node.js
- Containers: Docker, Podman
- Mail: Postfix
- Security: fail2ban
- Directory: OpenLDAP

**Config formats supported:**
- INI, XML, JSON, YAML, TOML
- nginx conf, Apache conf
- Environment files (.env)

**Sensitive data redaction:**
- Passwords, secrets, tokens, API keys
- Connection strings (MongoDB, MySQL, PostgreSQL, Redis)
- AWS credentials, Azure keys
- JWT tokens, PEM private keys

### Phase 1.9: Triage & Summary ✅ (25/25)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_os_info` | OS version, build, kernel, platform | ✅ | ✅ | ✅ |
| `get_system_profile` | CPU/RAM/disk/network summary | ✅ | ✅ | ✅ |
| `get_service_manager_info` | Service manager status | ✅ | ✅ | ✅ |
| `get_cloud_environment` | Cloud provider detection (AWS/GCP/Azure) | ✅ | ✅ | ✅ |
| `get_language_runtime_versions` | Python/Node/Go/Ruby/Java/etc versions | ✅ | ✅ | ✅ |
| `get_recent_reboots` | Recent reboot/shutdown events | ✅ | ✅ | ✅ |
| `get_service_failures_24h` | Failed services in last 24 hours | ✅ | ✅ | ✅ |
| `get_kernel_errors_24h` | Kernel errors in last 24 hours | ✅ | ✅ | ✅ |
| `get_oom_events` | Out-of-memory events | ✅ | ✅ | ✅ |
| `get_resource_incidents` | CPU/memory/disk resource spikes | ✅ | ✅ | ✅ |
| `get_config_changes_24h` | Package/config changes in 24h | ✅ | ✅ | ✅ |
| `get_failed_units` | Failed systemd/launchd/services | ✅ | ✅ | ✅ |
| `get_pending_timers` | Pending scheduled jobs | ✅ | ✅ | ✅ |
| `get_enabled_services` | All enabled/auto-start services | ✅ | ✅ | ✅ |
| `get_pending_updates` | Available system updates | ✅ | ✅ | ✅ |
| `get_security_basics` | Firewall, AV, updates status | ✅ | ✅ | ✅ |
| `get_admin_account_summary` | Users with admin/sudo privileges | ✅ | ✅ | ✅ |
| `get_exposed_services_summary` | Services listening on external interfaces | ✅ | ✅ | ✅ |
| `get_ssh_security_summary` | SSH configuration security | ✅ | ✅ | ✅ |
| `get_resource_limits` | System resource limits (ulimits) | ✅ | ✅ | ✅ |
| `get_installed_package_summary` | Package counts by manager | ✅ | ✅ | ✅ |
| `get_fs_health_summary` | Filesystem health and usage | ✅ | ✅ | ✅ |
| `get_incident_triage_snapshot` | Combined triage summary | ✅ | ✅ | ✅ |
| `get_security_posture_snapshot` | Security posture summary | ✅ | ✅ | ✅ |
| `get_full_system_snapshot` | Complete system snapshot | ✅ | ✅ | ✅ |

**Cloud providers detected:**
- AWS EC2 (IMDSv2), Google Cloud, Microsoft Azure, DigitalOcean, Oracle Cloud

**Language runtimes detected:**
- Python, Node.js, Go, Ruby, Java, PHP, Rust, .NET, Perl

**Triage categories:**
- Recent events: reboots, service failures, kernel errors, OOM, resource incidents
- Security: firewall status, updates, admin accounts, exposed services, SSH config
- Services: failed units, pending timers, enabled services
- System health: filesystem status, resource limits, package inventory

### Phase 1.10: Windows Enterprise Features ✅ (15/15)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_registry_key` | Read registry key and values | - | - | ✅ |
| `get_registry_tree` | Enumerate subkeys recursively | - | - | ✅ |
| `get_registry_security` | Key permissions and ownership | - | - | ✅ |
| `get_dcom_applications` | List registered DCOM apps | - | - | ✅ |
| `get_dcom_permissions` | DCOM launch/access permissions | - | - | ✅ |
| `get_dcom_identities` | DCOM RunAs identities per app | - | - | ✅ |
| `get_com_security_defaults` | Machine-wide COM security | - | - | ✅ |
| `get_iis_sites` | List all IIS websites | - | - | ✅ |
| `get_iis_app_pools` | Application pool configuration | - | - | ✅ |
| `get_iis_bindings` | Site bindings (ports, SSL, hostnames) | - | - | ✅ |
| `get_iis_virtual_dirs` | Virtual directories and applications | - | - | ✅ |
| `get_iis_handlers` | Handler mappings | - | - | ✅ |
| `get_iis_modules` | Installed IIS modules | - | - | ✅ |
| `get_iis_ssl_certs` | SSL certificate bindings | - | - | ✅ |
| `get_iis_auth_config` | Authentication settings per site | - | - | ✅ |

**Registry queries:**
- Read keys, values, and subkeys from any hive (HKLM, HKCU, HKCR, HKU, HKCC)
- Recursive tree enumeration with depth limits
- Security descriptor parsing (owner, group, DACL)

**DCOM/COM security:**
- Enumerate registered DCOM applications
- Parse launch and access permissions
- Identify RunAs identities and security defaults

**IIS web server:**
- Complete site and application pool inventory
- SSL certificate bindings with certificate details
- Handler mappings and module configuration
- Authentication settings (Anonymous, Basic, Windows, Digest)

### Phase 2.1-2.2: GPU & Container Metrics ✅ (3/3)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_gpu_info` | GPU details (memory, utilization, temp) | ✅ | ✅ | ✅ |
| `get_container_stats` | Real-time container resource stats | ✅ | ✅ | ✅ |
| `get_container_logs` | Container stdout/stderr logs | ✅ | ✅ | ✅ |

**GPU support:**
- NVIDIA GPUs via nvidia-smi (memory, utilization, temperature, power, clocks, processes)
- AMD GPUs via sysfs/ROCm (memory, utilization, temperature, clocks)
- Intel GPUs via sysfs (Arc, Xe, UHD graphics)
- Apple Silicon GPUs via system_profiler

**Container support:**
- Docker and Podman containers
- Real-time CPU, memory, network, and block I/O statistics
- Log streaming with timestamp parsing and stdout/stderr separation

### What You Can Do Now

```bash
# Build
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Run (stdio mode - for MCP clients)
./mcp-sysinfo

# Run via SSH (remote host)
ssh user@server "mcp-sysinfo"
```

### Quick Start with Docker

```bash
# Clone and start HTTP server
git clone https://github.com/levantar-ai/mcp-sysinfo
cd mcp-sysinfo
docker compose up mcp-sysinfo-http

# Test it
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_uptime"}}'
```

For privileged access (all system queries):

```bash
docker compose --profile privileged up mcp-sysinfo-privileged
```

See [examples/](examples/) for Go and Python client examples.

### Claude Code Integration

Add mcp-sysinfo to [Claude Code](https://claude.ai/code) for AI-powered system diagnostics:

**Local machine (stdio):**

```bash
# Linux/macOS
claude mcp add --transport stdio sysinfo -- /path/to/mcp-sysinfo

# Windows
claude mcp add --transport stdio sysinfo -- C:\path\to\mcp-sysinfo-windows-amd64.exe
```

**Remote Windows VM (HTTP):**

```powershell
# 1. On Windows VM: Download and start server with token auth
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://github.com/levantar-ai/mcp-sysinfo/releases/latest/download/mcp-sysinfo-windows-amd64" -OutFile "mcp-sysinfo.exe"
.\mcp-sysinfo.exe --transport http --listen 0.0.0.0:8080 --token my-secret-token

# 2. Open firewall if needed
New-NetFirewallRule -DisplayName "MCP SysInfo" -Direction Inbound -Port 8080 -Protocol TCP -Action Allow
```

```bash
# 3. On host: Connect Claude Code (replace IP with your VM's IP)
claude mcp add --transport http sysinfo-windows http://10.211.55.x:8080 \
  --header "Authorization: Bearer my-secret-token"
```

**Verify:**

```bash
claude mcp list   # List configured servers
/mcp              # Check status inside Claude Code
```

See [Quick Start](docs/getting-started/quickstart.md) for detailed setup instructions.

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

### Phase 1.7: SBOM & Inventory ✅ Complete (31/31 queries)

Software Bill of Materials for vulnerability detection.

**Implemented:**
- PATH executables discovery
- System package managers (dpkg, rpm, apk, pacman, brew, choco, winget, snap, flatpak, scoop)
- Language package managers (pip, npm, go modules, Cargo, RubyGems, Maven, Composer, NuGet)
- Lock file parsing (package-lock.json, requirements.txt, Cargo.lock, go.sum, Gemfile.lock)
- Platform-specific: macOS Applications, Windows Hotfixes/Programs/Features, Homebrew Casks
- Container images (Docker API: images, containers, history)
- SBOM export (CycloneDX 1.4, SPDX 2.3)
- Vulnerability lookup (OSV, Debian Security Tracker, NVD)

See [docs/09-sbom-inventory.md](docs/09-sbom-inventory.md)

### Phase 1.9: Triage & Summary ✅ Complete (25/25 queries)

High-level queries for incident triage and security posture assessment.

**Implemented:**
- OS info, system profile, service manager, cloud environment, language runtimes
- Recent events: reboots, service failures, kernel errors, OOM events, resource incidents
- Security: firewall/AV status, admin accounts, exposed services, SSH config, resource limits
- Services: failed units, pending timers, enabled services, pending updates
- Meta queries: incident triage snapshot, security posture snapshot, full system snapshot

### Phase 2.3: System Reports & Enhanced Metrics (3/3)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `generate_system_report` | Generate JSON data for HTML report templates | ✅ | ✅ | ✅ |
| `generate_iis_report` | IIS-specific web server report (Windows) | - | - | ✅ |
| `get_processes_sampled` | Accurate CPU% via time-delta sampling | ✅ | ✅ | ✅ |

**System Report Features:**
- Parallel data collection for all system metrics (16+ collectors)
- Return structured JSON data bindable to HTML templates
- Categories: os, hardware, uptime, cpu, memory, gpu, processes, disks, network, listening_ports, dns, routes, arp, startup_items, programs, runtimes
- Templates provided in `reports/` directory for customization
- IIS-specific report for Windows web servers with all IIS config data

**Process CPU Percentage (Fixed):**
- `CollectSampled()` method uses time-delta sampling for accurate CPU%
- Takes two CPU time measurements with configurable delay (default: 1000ms)
- Measures CPU time delta over sampling period for accurate percentages

### Future Phases

| Phase | Focus |
|-------|-------|
| 2.3 | System reports, IIS reports, process sampling |
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
| [api/openapi.yaml](api/openapi.yaml) | OpenAPI 3.1 specification |
| [charts/mcp-sysinfo/](charts/mcp-sysinfo/) | Helm chart for Kubernetes |
| [examples/](examples/) | Go and Python client examples |

---

## Kubernetes Deployment

Deploy to Kubernetes using Helm:

```bash
# Install from local chart
helm install mcp-sysinfo ./charts/mcp-sysinfo

# With OIDC authentication
helm install mcp-sysinfo ./charts/mcp-sysinfo \
  --set mcp.auth.oidc.enabled=true \
  --set mcp.auth.oidc.issuer=https://your-idp.example.com \
  --set mcp.auth.oidc.audience=mcp-sysinfo

# With Prometheus ServiceMonitor
helm install mcp-sysinfo ./charts/mcp-sysinfo \
  --set metrics.serviceMonitor.enabled=true
```

See [charts/mcp-sysinfo/README.md](charts/mcp-sysinfo/README.md) for full configuration options.

---

## Prometheus Metrics

When running in HTTP mode, Prometheus metrics are available at `/metrics`:

```bash
curl http://localhost:8080/metrics
```

**Available metrics:**

| Metric | Description |
|--------|-------------|
| `mcp_sysinfo_http_requests_total` | Total HTTP requests by method, path, status |
| `mcp_sysinfo_http_request_duration_seconds` | Request latency histogram |
| `mcp_sysinfo_tool_calls_total` | Tool calls by name and scope |
| `mcp_sysinfo_tool_call_duration_seconds` | Tool execution latency |
| `mcp_sysinfo_tool_call_errors_total` | Tool errors by type |
| `mcp_sysinfo_auth_requests_total` | Authentication attempts |

---

## Project Status

| Phase | Focus | Progress | Queries |
|-------|-------|----------|---------|
| **1.0** | Core Metrics | ✅ Complete | 7/7 |
| **1.5** | Log Access | ✅ Complete | 6/6 |
| **1.6** | System Hooks | ✅ Complete | 31/31 |
| **1.7** | SBOM & Inventory | ✅ Complete | 31/31 |
| **1.8** | App Discovery & Config | ✅ Complete | 2/2 |
| **1.9** | Triage & Summary | ✅ Complete | 25/25 |
| **1.10** | Windows Enterprise | ✅ Complete | 15/15 |
| **1.11** | Deep IIS Configuration | 📋 Planned | 0/35 |
| **1.12** | Complete IIS Coverage | 📋 Planned | 0/47 |
| **2.1-2.2** | GPU & Container Metrics | ✅ Complete | 3/3 |
| 2.3 | System Reports & Process Sampling | 📋 Planned | 0/3 |
| 3 | Storage Deep Dive | 📋 Planned | 0/5 |
| 4 | Network Intelligence | 📋 Planned | 0/5 |
| 5 | Analytics & Trends | 📋 Planned | 0/4 |
| 6 | Automation & Alerting | 📋 Planned | 0/5 |
| 7 | Security & Compliance | 📋 Planned | 0/5 |
| 8 | Integration & Plugins | 📋 Planned | 0/4 |
| 9 | LLM Features | 📋 Planned | 0/3 |

**Implemented: 120/246 queries (49%)**

**Phase 2.1-2.2 GPU & Container Metrics (Complete):**
- GPU information (NVIDIA/AMD/Intel detection, utilization, memory, temperature)
- Container stats (real-time CPU/memory/network/I/O for Docker/Podman)
- Container logs (stdout/stderr streaming with timestamps)

**Phase 1.10 Windows Enterprise Features (Complete):**
- Registry queries (read keys, enumerate, security descriptors)
- DCOM/COM security (applications, permissions, identities)
- IIS web server (sites, app pools, bindings, SSL, handlers)

**Phase 1.11-1.12 IIS Deep Dive (Planned - 82 queries):**
- Request filtering, URL rewrite, compression, caching
- App pool recycling, process model, CPU throttling
- ASP.NET configuration, FTP server, HTTP.sys integration
- ARR load balancing, Classic ASP, runtime monitoring

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

levantar-ai/mcp-sysinfo is licensed under the GNU Affero General Public License v3 (AGPLv3).

We offer a commercial licensing option for enterprises who require a proprietary license (for example to embed this project into closed-source products, or to run closed modifications in a hosted service). If you are interested in enterprise licensing, support, or custom modules, please contact: sales@levantar.ai

For licensing questions, contact: licensing@levantar.ai
