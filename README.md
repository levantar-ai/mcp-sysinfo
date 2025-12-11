# MCP System Info

A comprehensive, zero-dependency system monitoring server using the Model Context Protocol (MCP). Designed for AI-powered diagnostics with a focus on being lightweight and never impacting customer workloads.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         MCP SYSTEM INFO - 106 QUERIES                        ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Phase 1 (MVP)       Core system metrics                     7 queries  ✅   ║
║  Phase 1.5 (Logs)    System & app log access                 6 queries  📋   ║
║  Phase 1.6 (Hooks)   Deep system introspection              37 queries  📋   ║
║  Phase 1.7 (SBOM)    Software inventory & vulnerability     31 queries  📋   ║
║  Phases 2-7          Enhanced, Analytics, Security, etc.    25 queries  📋   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

## Key Principles

- **Zero Dependencies**: Uses only built-in OS tools (no third-party software required)
- **Cross-Platform**: Linux, macOS, and Windows support
- **Lightweight First**: Never impact customer workloads
- **On-Demand Only**: No background polling or auto-scanning
- **Resource Budgets**: Strict limits on CPU, memory, and time for every query

## Resource Impact Guarantee

Every query follows strict resource budgets:

| Impact | CPU | Memory | Time | Policy |
|--------|-----|--------|------|--------|
| 🟢 Minimal | <1% | <1MB | <100ms | Always allowed |
| 🟡 Low | <5% | <10MB | <1s | Default allowed |
| 🟠 Medium | <10% | <50MB | <5s | Requires opt-in |
| 🔴 High | - | - | - | **BLOCKED** - We never impact workloads |

---

## Phase 1: MVP (Complete)

Core system metrics with full cross-platform support.

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_cpu_info` | Usage, frequency, load average, cores | ✅ | ✅ | ✅ |
| `get_memory_info` | Total, used, available, swap | ✅ | ✅ | ✅ |
| `get_disk_info` | Partitions, usage, I/O stats | ✅ | ✅ | ✅ |
| `get_network_info` | Interfaces, I/O, connections | ✅ | ✅ | ✅ |
| `get_processes` | Process list, top by CPU/memory | ✅ | ✅ | ✅ |
| `get_uptime` | Boot time, uptime duration | ✅ | ✅ | ✅ |
| `get_temperature` | Hardware temperature sensors | ✅ | ⚠️ | ⚠️ |

**Status: 7/7 queries implemented**

---

## Phase 1.5: Log Access (Critical for Diagnostics)

Without logs, AI can only see symptoms. With logs, AI can diagnose root causes.

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_journal_logs` | Systemd journal (services, boot) | ✅ | - | - |
| `get_syslog` | Traditional syslog messages | ✅ | ✅ | - |
| `get_app_logs` | Application-specific logs | ✅ | ✅ | ✅ |
| `get_kernel_logs` | dmesg, boot, hardware errors | ✅ | ✅ | ✅ |
| `get_auth_logs` | Login, sudo, SSH attempts | ✅ | ✅ | ✅ |
| `get_event_log` | Windows Event Viewer | - | - | ✅ |

**Example Diagnostic Value:**

| Without Logs | With Logs |
|--------------|-----------|
| "CPU at 100%" | "CPU at 100% - OOM killer triggered, java killed at 14:32" |
| "Service down" | "nginx down - 'Too many open files' in error.log" |
| "Disk full" | "/var/log/app.log is 45GB, growing 100MB/min" |

---

## Phase 1.6: System Hooks (37 Queries)

Zero-dependency deep system introspection. See [docs/08-system-hooks.md](docs/08-system-hooks.md).

### Scheduled Tasks & Startup

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_cron_jobs` | Cron/systemd timers | 🟢 |
| `get_launchd_jobs` | macOS launchd jobs | 🟢 |
| `get_scheduled_tasks` | Windows Task Scheduler | 🟢 |
| `get_startup_items` | Boot/login startup items | 🟢 |

### Kernel & Drivers

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_kernel_modules` | Loaded modules/drivers | 🟢 |
| `get_kernel_params` | Sysctl parameters | 🟢 |

### Network Configuration

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_listening_ports` | Open ports + process owner | 🟢-🟡 |
| `get_dns_config` | DNS resolvers, search domains | 🟢 |
| `get_hosts_file` | Local DNS overrides | 🟢 |
| `get_routing_table` | Network routes | 🟢 |
| `get_arp_cache` | MAC-IP mappings | 🟢 |
| `get_firewall_rules` | Active firewall rules | 🟡 |

### File System

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_open_files` | Files held open (targeted) | 🟡-🟠 |
| `get_fd_limits` | File descriptor limits | 🟢 |
| `get_inode_usage` | Inode exhaustion | 🟢 |
| `get_mount_options` | Mount security flags | 🟢 |

### Security Configuration

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_user_accounts` | Local users/groups | 🟢 |
| `get_sudo_config` | Privilege escalation config | 🟢 |
| `get_ssh_config` | SSH server/client config | 🟢 |
| `get_ssl_certs` | Certificate expiry dates | 🟡 |
| `get_selinux_status` | SELinux status (Linux) | 🟢 |
| `get_apparmor_status` | AppArmor profiles (Linux) | 🟢 |

### Hardware Information

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_hardware_info` | System inventory (DMI/SMBIOS) | 🟡 |
| `get_usb_devices` | Connected USB devices | 🟢 |
| `get_pci_devices` | PCI devices | 🟢 |
| `get_block_devices` | Disk topology | 🟢 |

### Process & Resources

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_env_vars` | Environment variables | 🟢 |
| `get_ipc_resources` | Semaphores, shared memory | 🟢 |
| `get_namespaces` | Container namespaces | 🟢 |
| `get_cgroup_limits` | Resource limits | 🟢 |
| `get_capabilities` | Process capabilities | 🟢 |

### System State

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_vm_info` | Virtualization detection | 🟢 |
| `get_locale` | Locale/timezone | 🟢 |
| `get_ntp_status` | Time sync status | 🟡 |
| `get_core_dumps` | Crash dumps | 🟡 |
| `get_power_state` | Power/battery state | 🟢 |
| `get_numa_topology` | NUMA nodes | 🟢 |

---

## Phase 1.7: SBOM & Software Inventory (31 Queries)

Software Bill of Materials for vulnerability detection. See [docs/09-sbom-inventory.md](docs/09-sbom-inventory.md).

### System Package Managers

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_apt_packages` | Debian/Ubuntu packages | ✅ | - | - |
| `get_rpm_packages` | RHEL/Fedora packages | ✅ | - | - |
| `get_brew_packages` | Homebrew packages | - | ✅ | - |
| `get_macos_apps` | macOS applications | - | ✅ | - |
| `get_windows_programs` | Windows programs | - | - | ✅ |
| `get_windows_updates` | Windows updates | - | - | ✅ |

### Language Package Managers

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_pip_packages` | Python packages | 🟡 |
| `get_npm_packages` | Node.js packages | 🟡-🟠 |
| `get_go_modules` | Go modules | 🟢 |
| `get_cargo_crates` | Rust crates | 🟢 |
| `get_gem_packages` | Ruby gems | 🟡 |
| `get_maven_deps` | Java Maven dependencies | 🟠 |
| `get_composer_packages` | PHP packages | 🟢 |
| `get_nuget_packages` | .NET packages | 🟡 |

### Container Images

| Query | Description | Impact |
|-------|-------------|:------:|
| `get_docker_images` | Docker images | 🟢 |
| `get_container_packages` | Packages in container | 🟡 |
| `get_image_layers` | Image layer history | 🟢 |

### SBOM Export

| Query | Description | Impact |
|-------|-------------|:------:|
| `export_sbom_cyclonedx` | CycloneDX format | 🟡 |
| `export_sbom_spdx` | SPDX format | 🟡 |

### Vulnerability Lookup

| Query | Description | Impact |
|-------|-------------|:------:|
| `check_local_vulns` | Local security DB | 🟡 |
| `check_osv_vulns` | OSV database (network) | 🟠 |
| `check_nvd_vulns` | NVD database (network) | 🟠 |

---

## Future Phases (25 Queries)

| Phase | Description | Queries |
|-------|-------------|:-------:|
| Phase 2 | Enhanced (GPU, Battery, Containers, Services) | 6 |
| Phase 3 | Analytics (Historical, Trends, Anomaly) | 4 |
| Phase 4 | Automation (Alerts, Remediation) | 4 |
| Phase 5 | Security (Scan, Compliance, Forensics) | 4 |
| Phase 6 | Integration (Prometheus, Plugins, Multi-host) | 4 |
| Phase 7 | LLM Features (NL Queries, Auto-diagnostics) | 3 |

---

## Quick Start

```bash
# Build
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Run
./mcp-sysinfo
```

## Development

### Prerequisites

- Go 1.22+
- No external dependencies required (uses only built-in OS tools)

### Testing

```bash
# Unit tests
go test -v ./...

# Integration tests (requires real OS)
INTEGRATION_TEST=true go test -v -tags=integration ./test/integration/...
```

### Cross-Compilation

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o mcp-sysinfo-linux ./cmd/mcp-sysinfo

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o mcp-sysinfo-darwin ./cmd/mcp-sysinfo

# Windows
GOOS=windows GOARCH=amd64 go build -o mcp-sysinfo.exe ./cmd/mcp-sysinfo
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Overview](docs/00-overview.md) | Architecture and design |
| [Tier 1: Core Monitoring](docs/01-tier1-core-monitoring.md) | CPU, Memory, Disk, Network, Processes, Logs |
| [Tier 2: Analytics](docs/02-tier2-analytics.md) | Time-series, trends, anomalies |
| [Tier 3: Automation](docs/03-tier3-automation.md) | Alerts, remediation, webhooks |
| [Tier 4: Security](docs/04-tier4-security.md) | Scanning, compliance, forensics |
| [Tier 5: Integration](docs/05-tier5-integration.md) | Prometheus, OpenTelemetry, plugins |
| [Tier 6: LLM Features](docs/06-tier6-llm-features.md) | Health scoring, diagnostics |
| [Feature Support Matrix](docs/07-feature-support-matrix.md) | Complete feature breakdown |
| [System Hooks](docs/08-system-hooks.md) | 37 deep introspection hooks |
| [SBOM Inventory](docs/09-sbom-inventory.md) | Software inventory & vulnerabilities |

---

## Project Status

```
Phase 1 (MVP)       ████████████████████  100%  (7/7 queries)
Phase 1.5 (Logs)    ░░░░░░░░░░░░░░░░░░░░    0%  (0/6 queries)
Phase 1.6 (Hooks)   ░░░░░░░░░░░░░░░░░░░░    0%  (0/37 queries)
Phase 1.7 (SBOM)    ░░░░░░░░░░░░░░░░░░░░    0%  (0/31 queries)
Phases 2-7          ░░░░░░░░░░░░░░░░░░░░    0%  (0/25 queries)
───────────────────────────────────────────────────────────────
Total               ██░░░░░░░░░░░░░░░░░░    7%  (7/106 queries)
```

See [TODO.md](TODO.md) for the complete implementation checklist.

---

## License

MIT
