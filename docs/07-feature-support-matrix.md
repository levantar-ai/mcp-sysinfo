# Feature Support Matrix

A summary of feature support across Linux, macOS, and Windows.

---

## Phase Summary

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         MCP SYSTEM INFO - PHASE OVERVIEW                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Phase              Description                              Queries  Status ║
║  ─────────────────────────────────────────────────────────────────────────   ║
║  Phase 1 (MVP)      Core system metrics                           7   ✅ Done║
║  Phase 1.5 (Logs)   System & app log access for diagnostics       6   📋 Next║
║  Phase 1.6 (Hooks)  Deep system introspection (37 hooks!)        37   📋 Plan║
║  Phase 1.7 (SBOM)   Software inventory & vulnerability           31   📋 Plan║
║  Phase 2            Enhanced (GPU, Battery, Containers, etc.)     6   📋 Plan║
║  Phase 3            Analytics (Historical, Trends, Anomaly)       4   📋 Plan║
║  Phase 4            Automation (Alerts, Remediation)              4   📋 Plan║
║  Phase 5            Security (Scan, Compliance, Forensics)        4   📋 Plan║
║  Phase 6            Integration (Cloud, Plugins, Multi-host)      4   📋 Plan║
║  Phase 7            LLM Features (NL Queries, Auto-diagnostics)   3   📋 Plan║
║  ─────────────────────────────────────────────────────────────────────────   ║
║  TOTAL PLANNED QUERIES: 106                                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**Resource Impact Guarantee:** All queries follow strict resource budgets:
- 🟢 Minimal: <1% CPU, <1MB RAM, <100ms
- 🟡 Low: <5% CPU, <10MB RAM, <1s
- 🟠 Medium: <10% CPU, <50MB RAM, <5s (requires explicit opt-in)
- 🔴 High: Blocked - we NEVER impact customer workloads

---

## Phase 1 - MVP (Complete)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|-------|-------|---------|
| `get_cpu_info` | Usage, frequency, load average, cores | ✅ | ✅ | ✅ |
| `get_memory_info` | Total, used, available, swap | ✅ | ✅ | ✅ |
| `get_disk_info` | Partitions, usage, I/O stats | ✅ | ✅ | ✅ |
| `get_network_info` | Interfaces, I/O, connections | ✅ | ✅ | ✅ |
| `get_processes` | Process list, top by CPU/memory | ✅ | ✅ | ✅ |
| `get_uptime` | Boot time, uptime duration | ✅ | ✅ | ✅ |
| `get_temperature` | Hardware temperature sensors | ✅ | ⚠️ | ⚠️ |

**Status: 7/7 queries implemented**

---

## Phase 1.5 - Log Access (Critical for Diagnostics)

Without logs, AI can only see symptoms. With logs, AI can diagnose root causes.

| Query | Description | Linux | macOS | Windows |
|-------|-------------|-------|-------|---------|
| `get_journal_logs` | Systemd journal (services, boot) | ✅ journalctl | N/A | N/A |
| `get_syslog` | Traditional syslog messages | ✅ /var/log/syslog | ✅ log show | N/A |
| `get_app_logs` | Application-specific logs | ✅ /var/log/{app}/ | ✅ ~/Library/Logs | ✅ %AppData% |
| `get_kernel_logs` | dmesg, boot, hardware errors | ✅ dmesg | ✅ dmesg | ✅ Event Log |
| `get_auth_logs` | Login, sudo, SSH attempts | ✅ auth.log | ✅ secure.log | ✅ Security Log |
| `get_event_log` | Windows Event Viewer | N/A | N/A | ✅ Get-WinEvent |

**Impact Example:**

| Without Logs | With Logs |
|--------------|-----------|
| "CPU at 100%" | "CPU at 100% - OOM killer triggered, java process killed at 14:32" |
| "Service down" | "nginx down - 'Too many open files' in error.log, restart loop 5x" |
| "Disk full" | "/var/log/app.log is 45GB, growing 100MB/min due to debug enabled" |

**Status: 0/6 queries implemented**

---

## Phase 1.6 - System Hooks (Deep Introspection)

Zero-dependency deep system introspection. See [08-system-hooks.md](./08-system-hooks.md) for full details.

### Scheduled Tasks & Startup (4 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_cron_jobs` | Cron/systemd timers | ✅ /var/spool/cron | N/A | N/A | 🟢 |
| `get_launchd_jobs` | Launchd jobs | N/A | ✅ LaunchDaemons | N/A | 🟢 |
| `get_scheduled_tasks` | Task Scheduler | N/A | N/A | ✅ Tasks XML | 🟢 |
| `get_startup_items` | Boot/login items | ✅ systemd | ✅ LaunchAgents | ✅ Registry | 🟢 |

### Kernel & Drivers (2 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_kernel_modules` | Loaded modules/drivers | ✅ /proc/modules | ✅ kextstat | ✅ API | 🟢 |
| `get_kernel_params` | Sysctl parameters | ✅ /proc/sys | ✅ sysctl | ✅ Registry | 🟢 |

### Network Configuration (6 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_listening_ports` | Open ports + process | ✅ /proc/net | ✅ lsof | ✅ API | 🟢-🟡 |
| `get_dns_config` | Resolvers, search | ✅ resolv.conf | ✅ scutil | ✅ Registry | 🟢 |
| `get_hosts_file` | Local DNS overrides | ✅ /etc/hosts | ✅ /etc/hosts | ✅ hosts | 🟢 |
| `get_routing_table` | Network routes | ✅ /proc/net/route | ✅ netstat | ✅ API | 🟢 |
| `get_arp_cache` | MAC-IP mappings | ✅ /proc/net/arp | ✅ arp | ✅ API | 🟢 |
| `get_firewall_rules` | Active firewall rules | ✅ iptables/nft | ✅ pf | ✅ API | 🟡 |

### File System (4 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_open_files` | Files held open (targeted) | ✅ /proc/fd | ✅ lsof | ✅ API | 🟡-🟠 |
| `get_fd_limits` | File descriptor limits | ✅ /proc/sys | ✅ ulimit | ✅ API | 🟢 |
| `get_inode_usage` | Inode exhaustion | ✅ statfs | ✅ statfs | N/A | 🟢 |
| `get_mount_options` | Mount security flags | ✅ /proc/mounts | ✅ mount | ✅ API | 🟢 |

### Security Configuration (6 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_user_accounts` | Local users/groups | ✅ /etc/passwd | ✅ dscl | ✅ API | 🟢 |
| `get_sudo_config` | Privilege escalation | ✅ /etc/sudoers | ✅ /etc/sudoers | ✅ Admins | 🟢 |
| `get_ssh_config` | SSH server/client | ✅ sshd_config | ✅ sshd_config | ✅ sshd_config | 🟢 |
| `get_ssl_certs` | Certificate expiry | ✅ /etc/ssl | ✅ Keychain | ✅ CertStore | 🟡 |
| `get_selinux_status` | MAC status | ✅ /sys/fs/selinux | N/A | N/A | 🟢 |
| `get_apparmor_status` | AppArmor profiles | ✅ /sys/kernel | N/A | N/A | 🟢 |

### Hardware Information (4 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_hardware_info` | System inventory | ✅ /sys/class/dmi | ✅ profiler | ✅ WMI | 🟡 |
| `get_usb_devices` | USB devices | ✅ /sys/bus/usb | ✅ profiler | ✅ API | 🟢 |
| `get_pci_devices` | PCI devices | ✅ /sys/bus/pci | ✅ profiler | ✅ API | 🟢 |
| `get_block_devices` | Disk topology | ✅ /sys/block | ✅ diskutil | ✅ API | 🟢 |

### Process & Resources (5 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_env_vars` | Environment variables | ✅ /proc/environ | ✅ environ | ✅ API | 🟢 |
| `get_ipc_resources` | Semaphores, shm | ✅ /proc/sysvipc | ✅ ipcs | N/A | 🟢 |
| `get_namespaces` | Container namespaces | ✅ /proc/ns | N/A | N/A | 🟢 |
| `get_cgroup_limits` | Resource limits | ✅ /sys/fs/cgroup | N/A | ✅ Jobs | 🟢 |
| `get_capabilities` | Process capabilities | ✅ /proc/status | N/A | ✅ Token | 🟢 |

### System State (6 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_vm_info` | Virtualization detect | ✅ /sys/class/dmi | ✅ sysctl | ✅ WMI | 🟢 |
| `get_locale` | Locale/timezone | ✅ /etc/timezone | ✅ defaults | ✅ API | 🟢 |
| `get_ntp_status` | Time sync status | ✅ timedatectl | ✅ sntp | ✅ w32tm | 🟡 |
| `get_core_dumps` | Crash dumps | ✅ /var/crash | ✅ DiagReports | ✅ CrashDumps | 🟡 |
| `get_power_state` | Power/battery | ✅ /sys/class/power | ✅ pmset | ✅ API | 🟢 |
| `get_numa_topology` | NUMA nodes | ✅ /sys/devices/node | N/A | ✅ API | 🟢 |

**Status: 0/37 queries implemented**

---

## Phase 1.7 - SBOM & Software Inventory

Software Bill of Materials for vulnerability detection. See [09-sbom-inventory.md](./09-sbom-inventory.md) for full details.

### System Package Managers (6 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_apt_packages` | Debian/Ubuntu pkgs | ✅ dpkg/status | N/A | N/A | 🟢 |
| `get_rpm_packages` | RHEL/Fedora pkgs | ✅ rpm -qa | N/A | N/A | 🟡 |
| `get_brew_packages` | Homebrew pkgs | N/A | ✅ Cellar dir | N/A | 🟡 |
| `get_macos_apps` | macOS applications | N/A | ✅ /Applications | N/A | 🟡 |
| `get_windows_programs` | Windows programs | N/A | N/A | ✅ Registry | 🟢 |
| `get_windows_updates` | Windows updates | N/A | N/A | ✅ Get-HotFix | 🟡 |

### Language Package Managers (8 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_pip_packages` | Python packages | ✅ site-packages | ✅ site-packages | ✅ site-packages | 🟡 |
| `get_npm_packages` | Node.js packages | ✅ node_modules | ✅ node_modules | ✅ node_modules | 🟡-🟠 |
| `get_go_modules` | Go modules | ✅ go.sum | ✅ go.sum | ✅ go.sum | 🟢 |
| `get_cargo_crates` | Rust crates | ✅ Cargo.lock | ✅ Cargo.lock | ✅ Cargo.lock | 🟢 |
| `get_gem_packages` | Ruby gems | ✅ gemspec | ✅ gemspec | ✅ gemspec | 🟡 |
| `get_maven_deps` | Java Maven | ✅ .m2/repository | ✅ .m2/repository | ✅ .m2/repository | 🟠 |
| `get_composer_packages` | PHP packages | ✅ composer.lock | ✅ composer.lock | ✅ composer.lock | 🟢 |
| `get_nuget_packages` | .NET packages | ✅ packages | ✅ packages | ✅ packages | 🟡 |

### Container Images (3 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `get_docker_images` | Docker images | ✅ Docker API | ✅ Docker API | ✅ Docker API | 🟢 |
| `get_container_packages` | Packages in container | ✅ exec | ✅ exec | ✅ exec | 🟡 |
| `get_image_layers` | Image layer history | ✅ Docker API | ✅ Docker API | ✅ Docker API | 🟢 |

### SBOM Export (2 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `export_sbom_cyclonedx` | CycloneDX format | ✅ | ✅ | ✅ | 🟡 |
| `export_sbom_spdx` | SPDX format | ✅ | ✅ | ✅ | 🟡 |

### Vulnerability Lookup (3 queries)

| Query | Description | Linux | macOS | Windows | Impact |
|-------|-------------|-------|-------|---------|--------|
| `check_local_vulns` | Local security DB | ✅ apt lists | N/A | N/A | 🟡 |
| `check_osv_vulns` | OSV database (network) | ✅ | ✅ | ✅ | 🟠 |
| `check_nvd_vulns` | NVD database (network) | ✅ | ✅ | ✅ | 🟠 |

**Status: 0/31 queries implemented**

---

## Phase 2 - Enhanced Diagnostics

| Query | Description | Linux | macOS | Windows |
|-------|-------------|-------|-------|---------|
| `get_gpu_info` | GPU utilization, memory, temp | ✅ | ⚠️ | ✅ |
| `get_battery_info` | Battery status, health, cycles | ✅ | ✅ | ✅ |
| `get_services` | Service status, control | ✅ systemd | ✅ launchd | ✅ services |
| `get_containers` | Docker/Podman metrics | ✅ | ✅ | ✅ |
| `get_users` | Logged-in users, sessions | ✅ | ✅ | ✅ |
| `get_boot_events` | Boot history, failures | ✅ | ✅ | ✅ |

**Status: 0/6 queries implemented**

---

## Overview

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MCP SYSTEM INFO - FEATURE SUPPORT MATRIX                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Platform        Total    Built-in    pip/stdlib    Sys Pkg    N/A          ║
║  ─────────────────────────────────────────────────────────────────────────   ║
║  Linux            145        54           52           40        0           ║
║  macOS            104        57           36            9        6           ║
║  Windows          121        66           52            2        2           ║
║  Cross-Platform   105         -           98            -        -           ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  TOTAL IMPLEMENTATIONS: 475                                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Support Percentage by OS

```
Linux     ████████████████████████████████████████████████████  100%
Windows   ██████████████████████████████████████████████████    98%
macOS     █████████████████████████████████████████████████     94%
```

| Platform | Support | Notes |
|----------|---------|-------|
| **Linux** | 100% | Full support for all features |
| **Windows** | 98% | Missing ZFS, systemd |
| **macOS** | 94% | Missing GPU, some low-level features |

---

## N/A Features by Platform

### macOS (6 unsupported)

| Feature | Reason |
|---------|--------|
| NVIDIA GPU diagnostics | No modern NVIDIA driver support |
| AMD GPU diagnostics | No AMD support on macOS |
| Native containers | No Docker-less container runtime |
| LVM | Not supported on macOS |
| systemd | Uses launchd instead |
| ionice / I/O priority | No equivalent API |
| Cloud metadata | macOS not typically cloud-hosted |

### Windows (2 unsupported)

| Feature | Reason |
|---------|--------|
| ZFS | Not supported on Windows |
| systemd | Uses Windows Services instead |

### Linux (0 unsupported)

Full support for all documented features.

---

## Installation Breakdown

### By Platform

| Install Method | Linux | macOS | Windows |
|----------------|-------|-------|---------|
| Built-in (no install) | 54 | 57 | 66 |
| pip install | 52 | 36 | 52 |
| System package (apt/brew) | 40 | 9 | 2 |
| **Total** | **145** | **104** | **121** |

Plus **105 cross-platform features** that work identically on all platforms.

### Summary

| Category | Percentage |
|----------|------------|
| Zero-install (built-in) | ~40% |
| pip-only install | ~45% |
| System packages needed | ~15% |

---

## Availability Legend

| Symbol | Meaning |
|--------|---------|
| **Built-in** | Available by default, no installation needed |
| **Python stdlib** | Part of Python standard library |
| **pip install X** | Requires installing Python package X |
| **apt/brew** | Requires system package installation |
| **Root/Admin** | Requires elevated privileges |
| **N/A** | Not available on this platform |

---

## Key Insights

1. **Linux has the best coverage** - All features are supported, with the richest ecosystem of tools (eBPF, cgroups, systemd, /proc, /sys)

2. **Windows has excellent built-in support** - Most features work via WMI, Performance Counters, and PowerShell without extra packages

3. **macOS has good coverage but gaps** - Missing some low-level features (GPU, I/O priority, cgroups) due to platform restrictions

4. **Cross-platform features are the foundation** - 105 features work identically across all platforms using psutil and pure Python

5. **pip is the primary install method** - Most features only require `pip install` with no system dependencies

---

## Recommended Core Dependencies

These packages cover the majority of features:

```bash
pip install psutil          # Core system metrics (all platforms)
pip install watchdog        # File system events (all platforms)
pip install httpx           # HTTP client for webhooks
pip install duckdb          # Time-series storage
pip install pandas numpy    # Analytics
pip install prometheus-client  # Metrics export
```

### Platform-Specific Additions

**Linux:**
```bash
apt install smartmontools   # SMART disk health
apt install sysstat         # iostat
apt install bpfcc-tools     # eBPF tools (optional, advanced)
```

**macOS:**
```bash
brew install smartmontools  # SMART disk health
```

**Windows:**
```bash
pip install pywin32         # Windows APIs
pip install wmi             # WMI queries
```
