# MCP System Info - Implementation TODO

A comprehensive checklist for implementing all features across Linux, macOS, and Windows.

**Legend:**
- [ ] Not started
- [x] Completed
- 🐧 Linux | 🍎 macOS | 🪟 Windows
- 🧪 Unit Test | 🔬 Integration Test

---

## Phase 1: MVP - Core Diagnostics ✅ COMPLETE

### 1.1 CPU Information ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/stat` for CPU usage
- [ ] 🐧 Linux: Read `/proc/loadavg` for load average
- [ ] 🐧 Linux: Read `/proc/cpuinfo` for CPU details
- [ ] 🐧 Linux: Read `/sys/devices/system/cpu/` for frequency
- [ ] 🍎 macOS: Use `sysctl` for CPU info
- [ ] 🍎 macOS: Use `host_processor_info()` for usage
- [ ] 🍎 macOS: Use `getloadavg()` for load average
- [ ] 🪟 Windows: Use WMI `Win32_Processor`
- [ ] 🪟 Windows: Use Performance Counters for CPU usage
- [ ] 🪟 Windows: Use `GetSystemTimes()` for CPU times

#### Unit Tests
- [ ] 🧪 Test CPU percent calculation logic
- [ ] 🧪 Test per-CPU parsing
- [ ] 🧪 Test frequency info parsing
- [ ] 🧪 Test load average parsing (Unix)
- [ ] 🧪 Test edge cases (0%, 100%, multi-core)

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `top`/`htop` output
- [ ] 🔬 🐧 Linux: Test /proc filesystem reading
- [ ] 🔬 🍎 macOS: Verify against `top` output
- [ ] 🔬 🍎 macOS: Test sysctl calls
- [ ] 🔬 🪟 Windows: Verify against Task Manager
- [ ] 🔬 🪟 Windows: Test WMI queries

---

### 1.2 Memory Information

#### Implementation
- [ ] 🐧 Linux: Read `/proc/meminfo`
- [ ] 🐧 Linux: Parse swap info from `/proc/swaps`
- [ ] 🍎 macOS: Use `vm_statistics64`
- [ ] 🍎 macOS: Use `sysctl` for memory info
- [ ] 🍎 macOS: Use `swapusage` sysctl
- [ ] 🪟 Windows: Use `GlobalMemoryStatusEx()`
- [ ] 🪟 Windows: Use WMI `Win32_OperatingSystem`

#### Unit Tests
- [ ] 🧪 Test memory calculation (total, used, available)
- [ ] 🧪 Test swap parsing
- [ ] 🧪 Test percentage calculations
- [ ] 🧪 Test unit conversions (bytes, KB, MB, GB)

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `free -m`
- [ ] 🔬 🍎 macOS: Verify against `vm_stat`
- [ ] 🔬 🪟 Windows: Verify against Task Manager

---

### 1.3 Disk Information

#### Implementation
- [ ] 🐧 Linux: Read `/proc/mounts` for partitions
- [ ] 🐧 Linux: Use `statfs()` for usage
- [ ] 🐧 Linux: Read `/sys/block/*/stat` for I/O
- [ ] 🍎 macOS: Use `getmntinfo()` for mounts
- [ ] 🍎 macOS: Use `statfs()` for usage
- [ ] 🍎 macOS: Use IOKit for disk I/O
- [ ] 🪟 Windows: Use `GetLogicalDriveStrings()`
- [ ] 🪟 Windows: Use `GetDiskFreeSpaceEx()`
- [ ] 🪟 Windows: Use WMI `Win32_LogicalDisk`

#### Unit Tests
- [ ] 🧪 Test partition parsing
- [ ] 🧪 Test usage calculations
- [ ] 🧪 Test filesystem type detection
- [ ] 🧪 Test mount point parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `df -h`
- [ ] 🔬 🍎 macOS: Verify against `df -h`
- [ ] 🔬 🪟 Windows: Verify against Explorer properties

---

### 1.4 Network Information

#### Implementation
- [ ] 🐧 Linux: Read `/proc/net/dev` for stats
- [ ] 🐧 Linux: Read `/sys/class/net/` for interfaces
- [ ] 🐧 Linux: Use netlink for addresses
- [ ] 🍎 macOS: Use `getifaddrs()` for interfaces
- [ ] 🍎 macOS: Use IOKit for network stats
- [ ] 🪟 Windows: Use `GetAdaptersAddresses()`
- [ ] 🪟 Windows: Use `GetIfTable2()`
- [ ] 🪟 Windows: Use Performance Counters

#### Unit Tests
- [ ] 🧪 Test interface parsing
- [ ] 🧪 Test bytes/packets counting
- [ ] 🧪 Test IP address parsing
- [ ] 🧪 Test interface flags (up/down)

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `ip addr`
- [ ] 🔬 🐧 Linux: Verify against `ifconfig`
- [ ] 🔬 🍎 macOS: Verify against `ifconfig`
- [ ] 🔬 🪟 Windows: Verify against `ipconfig`

---

### 1.5 Process List

#### Implementation
- [ ] 🐧 Linux: Read `/proc/[pid]/stat` for each process
- [ ] 🐧 Linux: Read `/proc/[pid]/cmdline` for command
- [ ] 🐧 Linux: Read `/proc/[pid]/status` for details
- [ ] 🍎 macOS: Use `proc_listpids()` for PIDs
- [ ] 🍎 macOS: Use `proc_pidinfo()` for details
- [ ] 🪟 Windows: Use `EnumProcesses()`
- [ ] 🪟 Windows: Use `OpenProcess()` + query functions
- [ ] 🪟 Windows: Use WMI `Win32_Process`

#### Unit Tests
- [ ] 🧪 Test process info parsing
- [ ] 🧪 Test CPU percent calculation
- [ ] 🧪 Test memory usage calculation
- [ ] 🧪 Test sorting (by CPU, memory, name)
- [ ] 🧪 Test filtering

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `ps aux`
- [ ] 🔬 🍎 macOS: Verify against `ps aux`
- [ ] 🔬 🪟 Windows: Verify against Task Manager

---

### 1.6 System Uptime

#### Implementation
- [ ] 🐧 Linux: Read `/proc/uptime`
- [ ] 🍎 macOS: Use `sysctl kern.boottime`
- [ ] 🪟 Windows: Use `GetTickCount64()`
- [ ] 🪟 Windows: Use WMI `Win32_OperatingSystem.LastBootUpTime`

#### Unit Tests
- [ ] 🧪 Test uptime parsing
- [ ] 🧪 Test boot time calculation
- [ ] 🧪 Test human-readable formatting

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `uptime`
- [ ] 🔬 🍎 macOS: Verify against `uptime`
- [ ] 🔬 🪟 Windows: Verify against Task Manager

---

### 1.7 Temperature Information

#### Implementation
- [ ] 🐧 Linux: Read `/sys/class/thermal/`
- [ ] 🐧 Linux: Read `/sys/class/hwmon/`
- [ ] 🐧 Linux: Support lm-sensors
- [ ] 🍎 macOS: Use IOKit `SMCReadKey`
- [ ] 🍎 macOS: Use `powermetrics` (root)
- [ ] 🪟 Windows: Use WMI `MSAcpi_ThermalZoneTemperature`
- [ ] 🪟 Windows: Use Open Hardware Monitor WMI

#### Unit Tests
- [ ] 🧪 Test temperature parsing
- [ ] 🧪 Test sensor name mapping
- [ ] 🧪 Test unit conversion (C/F)

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `sensors`
- [ ] 🔬 🍎 macOS: Verify against iStats
- [ ] 🔬 🪟 Windows: Verify against HWMonitor

---

## Phase 1.5: Log Access (Critical for Diagnostics) 📋 NEXT

Log access enables true root cause analysis for security incident triage. Without logs, AI can only see symptoms ("CPU is high") but not causes.

### 1.5.1 Journald Logs (Linux)

#### Implementation
- [ ] 🐧 Linux: `journalctl -o json` for structured output
- [ ] 🐧 Linux: Filter by unit (`-u nginx`)
- [ ] 🐧 Linux: Filter by priority (`-p err..emerg`)
- [ ] 🐧 Linux: Filter by time (`--since`, `--until`)
- [ ] 🐧 Linux: Filter by executable (`_COMM=sshd`)
- [ ] 🐧 Linux: Kernel messages (`-k`)

#### Unit Tests
- [ ] 🧪 Test JSON parsing of journalctl output
- [ ] 🧪 Test time range filtering
- [ ] 🧪 Test priority filtering
- [ ] 🧪 Test log entry struct parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify service logs match `journalctl -u`
- [ ] 🔬 🐧 Linux: Verify kernel messages match `dmesg`

---

### 1.5.2 Syslog

#### Implementation
- [ ] 🐧 Linux: Read `/var/log/syslog` or `/var/log/messages`
- [ ] 🐧 Linux: Parse RFC 5424 syslog format
- [ ] 🍎 macOS: Use `log show` command with predicates
- [ ] 🍎 macOS: Read `/var/log/system.log` (legacy)

#### Unit Tests
- [ ] 🧪 Test syslog line parsing
- [ ] 🧪 Test facility/severity extraction
- [ ] 🧪 Test timestamp parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `tail /var/log/syslog`
- [ ] 🔬 🍎 macOS: Verify against `log show`

---

### 1.5.3 Application Logs

#### Implementation
- [ ] 🐧 Linux: Scan `/var/log/{app}/` directories
- [ ] 🐧 Linux: Common paths: nginx, apache2, mysql, postgresql
- [ ] 🐧 Linux: Docker logs via `docker logs` or container log files
- [ ] 🍎 macOS: Read `~/Library/Logs/` and `/Library/Logs/`
- [ ] 🍎 macOS: Use `log show --predicate` for app subsystems
- [ ] 🪟 Windows: Read `%AppData%\Local\{App}\Logs\`
- [ ] 🪟 Windows: Read `%ProgramData%\{App}\Logs\`

#### Unit Tests
- [ ] 🧪 Test log file discovery
- [ ] 🧪 Test common log format parsing
- [ ] 🧪 Test JSON log parsing
- [ ] 🧪 Test log rotation handling

#### Integration Tests
- [ ] 🔬 All: Verify known app logs are discoverable
- [ ] 🔬 🐧 Linux: Test Docker container log reading

---

### 1.5.4 Kernel/Boot Logs

#### Implementation
- [ ] 🐧 Linux: Read `dmesg` ring buffer
- [ ] 🐧 Linux: Read `/var/log/kern.log`
- [ ] 🐧 Linux: Use `journalctl -k -b` for boot kernel messages
- [ ] 🍎 macOS: Use `dmesg` command
- [ ] 🍎 macOS: Use `log show --predicate 'sender == "kernel"'`
- [ ] 🪟 Windows: Read System Event Log
- [ ] 🪟 Windows: Use `Get-WinEvent -LogName System`

#### Unit Tests
- [ ] 🧪 Test dmesg parsing
- [ ] 🧪 Test kernel log severity extraction
- [ ] 🧪 Test boot message filtering

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `dmesg` output
- [ ] 🔬 🪟 Windows: Verify against Event Viewer

---

### 1.5.5 Authentication/Security Logs

#### Implementation
- [ ] 🐧 Linux (Debian): Read `/var/log/auth.log`
- [ ] 🐧 Linux (RHEL): Read `/var/log/secure`
- [ ] 🐧 Linux: Parse SSH login attempts
- [ ] 🐧 Linux: Parse sudo commands
- [ ] 🐧 Linux: Read audit.log if auditd enabled
- [ ] 🍎 macOS: Read `/var/log/secure.log`
- [ ] 🍎 macOS: Use `log show --predicate 'category == "auth"'`
- [ ] 🪟 Windows: Read Security Event Log
- [ ] 🪟 Windows: Filter login events (4624, 4625)

#### Unit Tests
- [ ] 🧪 Test auth log parsing
- [ ] 🧪 Test SSH attempt extraction
- [ ] 🧪 Test Windows event ID filtering

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify failed login detection
- [ ] 🔬 🪟 Windows: Verify against Security Event Log

---

### 1.5.6 Windows Event Log

#### Implementation
- [ ] 🪟 Windows: Use `Get-WinEvent` PowerShell
- [ ] 🪟 Windows: Query System log
- [ ] 🪟 Windows: Query Application log
- [ ] 🪟 Windows: Query Security log (requires admin)
- [ ] 🪟 Windows: Query Setup log
- [ ] 🪟 Windows: Filter by event ID, level, time range

#### Unit Tests
- [ ] 🧪 Test event log entry parsing
- [ ] 🧪 Test event ID filtering
- [ ] 🧪 Test time range queries

#### Integration Tests
- [ ] 🔬 🪟 Windows: Verify against Event Viewer

---

## Phase 1.6: System Hooks (37 Queries) 📋 PLANNED

Zero-dependency deep system introspection. See [docs/08-system-hooks.md](docs/08-system-hooks.md) for full details.

### 1.6.1 Scheduled Tasks & Startup (4 queries)

#### Implementation
- [ ] 🐧 Linux: Read `/var/spool/cron/crontabs/*` for user crons
- [ ] 🐧 Linux: Read `/etc/crontab`, `/etc/cron.d/*` for system crons
- [ ] 🐧 Linux: List `systemctl list-timers` for systemd timers
- [ ] 🍎 macOS: Read `/Library/LaunchDaemons/*.plist`
- [ ] 🍎 macOS: Read `/Library/LaunchAgents/*.plist`
- [ ] 🍎 macOS: Read `~/Library/LaunchAgents/*.plist`
- [ ] 🪟 Windows: Read `C:\Windows\System32\Tasks\*` XML files
- [ ] 🐧 Linux: Read `/etc/systemd/system/*.wants/` for startup services
- [ ] 🍎 macOS: Read Login Items from LaunchAgents
- [ ] 🪟 Windows: Read `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

#### Unit Tests
- [ ] 🧪 Test crontab parsing
- [ ] 🧪 Test plist parsing
- [ ] 🧪 Test Windows Task XML parsing
- [ ] 🧪 Test systemd timer parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `crontab -l`
- [ ] 🔬 🍎 macOS: Verify against `launchctl list`
- [ ] 🔬 🪟 Windows: Verify against Task Scheduler

---

### 1.6.2 Kernel & Drivers (2 queries)

#### Implementation
- [ ] 🐧 Linux: Read `/proc/modules` for loaded modules
- [ ] 🐧 Linux: Read `/sys/module/*/parameters/` for module params
- [ ] 🐧 Linux: Read `/proc/sys/` for kernel parameters
- [ ] 🍎 macOS: Parse `kextstat` output for kernel extensions
- [ ] 🍎 macOS: Read `sysctl -a` for kernel parameters
- [ ] 🪟 Windows: Use `EnumDeviceDrivers()` API
- [ ] 🪟 Windows: Read registry for driver parameters

#### Unit Tests
- [ ] 🧪 Test /proc/modules parsing
- [ ] 🧪 Test kextstat output parsing
- [ ] 🧪 Test sysctl parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `lsmod`
- [ ] 🔬 🍎 macOS: Verify against `kextstat`
- [ ] 🔬 🪟 Windows: Verify against `driverquery`

---

### 1.6.3 Network Configuration (6 queries)

#### Implementation
- [ ] 🐧 Linux: Read `/proc/net/tcp`, `/proc/net/udp` for listening ports
- [ ] 🐧 Linux: Map ports to processes via `/proc/[pid]/fd`
- [ ] 🍎 macOS: Parse `lsof -i -P` for listening ports
- [ ] 🪟 Windows: Use `GetExtendedTcpTable()` / `GetExtendedUdpTable()`
- [ ] 🐧 Linux: Read `/etc/resolv.conf` for DNS config
- [ ] 🍎 macOS: Parse `scutil --dns` for DNS config
- [ ] 🪟 Windows: Read `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
- [ ] All: Read `/etc/hosts` (or Windows equivalent)
- [ ] 🐧 Linux: Read `/proc/net/route` for routing table
- [ ] 🐧 Linux: Read `/proc/net/arp` for ARP cache
- [ ] 🐧 Linux: Parse `iptables -L -n` or `nft list ruleset`
- [ ] 🍎 macOS: Parse `pfctl -sr` for firewall rules
- [ ] 🪟 Windows: Use `Get-NetFirewallRule` via PowerShell

#### Unit Tests
- [ ] 🧪 Test /proc/net/tcp parsing
- [ ] 🧪 Test resolv.conf parsing
- [ ] 🧪 Test hosts file parsing
- [ ] 🧪 Test route table parsing
- [ ] 🧪 Test iptables/nft rule parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `ss -tulpn`
- [ ] 🔬 🐧 Linux: Verify against `ip route`
- [ ] 🔬 🐧 Linux: Verify against `iptables -L`

---

### 1.6.4 File System (4 queries)

#### Implementation
- [ ] 🐧 Linux: Read `/proc/[pid]/fd/` for open files (targeted by PID)
- [ ] 🍎 macOS: Parse `lsof -p [pid]` for open files
- [ ] 🪟 Windows: Use `NtQuerySystemInformation()` for handles
- [ ] 🐧 Linux: Read `/proc/sys/fs/file-nr` for FD limits
- [ ] 🐧 Linux: Use `statfs()` for inode usage
- [ ] 🐧 Linux: Read `/proc/mounts` for mount options

#### Unit Tests
- [ ] 🧪 Test /proc/[pid]/fd parsing
- [ ] 🧪 Test file-nr parsing
- [ ] 🧪 Test mount options parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `lsof -p`
- [ ] 🔬 🐧 Linux: Verify against `df -i`

---

### 1.6.5 Security Configuration (6 queries)

#### Implementation
- [ ] 🐧 Linux: Read `/etc/passwd`, `/etc/group` for users/groups
- [ ] 🍎 macOS: Use `dscl . -list /Users` for users
- [ ] 🪟 Windows: Use `NetUserEnum()` API
- [ ] 🐧 Linux: Read `/etc/sudoers`, `/etc/sudoers.d/*`
- [ ] 🐧 Linux: Read `/etc/ssh/sshd_config`
- [ ] 🐧 Linux: Scan `/etc/ssl/certs/` for certificate expiry
- [ ] 🍎 macOS: Query Keychain for certificates
- [ ] 🪟 Windows: Query Certificate Store
- [ ] 🐧 Linux: Read `/sys/fs/selinux/enforce` for SELinux status
- [ ] 🐧 Linux: Read `/sys/kernel/security/apparmor/profiles`

#### Unit Tests
- [ ] 🧪 Test /etc/passwd parsing
- [ ] 🧪 Test sudoers parsing
- [ ] 🧪 Test sshd_config parsing
- [ ] 🧪 Test X.509 certificate parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `getent passwd`
- [ ] 🔬 🐧 Linux: Verify against `sestatus`

---

### 1.6.6 Hardware Information (4 queries)

#### Implementation
- [ ] 🐧 Linux: Read `/sys/class/dmi/id/*` for hardware info
- [ ] 🍎 macOS: Parse `system_profiler SPHardwareDataType -json`
- [ ] 🪟 Windows: Use WMI `Win32_ComputerSystem`, `Win32_BaseBoard`
- [ ] 🐧 Linux: Read `/sys/bus/usb/devices/*/` for USB devices
- [ ] 🐧 Linux: Read `/sys/bus/pci/devices/*/` for PCI devices
- [ ] 🐧 Linux: Read `/sys/block/*/` for block device topology

#### Unit Tests
- [ ] 🧪 Test DMI sysfs parsing
- [ ] 🧪 Test USB device parsing
- [ ] 🧪 Test PCI device parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `lsusb`
- [ ] 🔬 🐧 Linux: Verify against `lspci`

---

### 1.6.7 Process & Resources (5 queries)

#### Implementation
- [ ] 🐧 Linux: Read `/proc/[pid]/environ` for environment variables
- [ ] 🐧 Linux: Read `/proc/sysvipc/*` for IPC resources
- [ ] 🐧 Linux: Read `/proc/[pid]/ns/` for namespaces
- [ ] 🐧 Linux: Read `/sys/fs/cgroup/` for cgroup limits
- [ ] 🐧 Linux: Read `/proc/[pid]/status` for capabilities

#### Unit Tests
- [ ] 🧪 Test environ parsing
- [ ] 🧪 Test sysvipc parsing
- [ ] 🧪 Test namespace detection
- [ ] 🧪 Test cgroup parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `ipcs`
- [ ] 🔬 🐧 Linux: Verify against `lsns`

---

### 1.6.8 System State (6 queries)

#### Implementation
- [ ] 🐧 Linux: Read `/sys/class/dmi/id/product_name` for VM detection
- [ ] 🐧 Linux: Check `/proc/cpuinfo` hypervisor flag
- [ ] 🍎 macOS: Check `sysctl kern.hv_support`
- [ ] 🪟 Windows: Check WMI for hypervisor
- [ ] All: Read `/etc/timezone` or equivalent for locale
- [ ] 🐧 Linux: Parse `timedatectl status` for NTP status
- [ ] 🐧 Linux: Scan `/var/crash/` for core dumps
- [ ] 🐧 Linux: Read `/sys/class/power_supply/` for power state
- [ ] 🐧 Linux: Read `/sys/devices/system/node/` for NUMA topology

#### Unit Tests
- [ ] 🧪 Test VM detection heuristics
- [ ] 🧪 Test timedatectl parsing
- [ ] 🧪 Test power supply sysfs parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `systemd-detect-virt`
- [ ] 🔬 🐧 Linux: Verify against `numactl -H`

---

## Phase 1.7: SBOM & Software Inventory (31 Queries) 📋 PLANNED

Software Bill of Materials for vulnerability detection. See [docs/09-sbom-inventory.md](docs/09-sbom-inventory.md) for full details.

### 1.7.1 System Package Managers (6 queries)

#### Implementation
- [ ] 🐧 Linux (Debian): Parse `/var/lib/dpkg/status` directly
- [ ] 🐧 Linux (RHEL): Use `rpm -qa --queryformat`
- [ ] 🐧 Linux (Alpine): Read `/lib/apk/db/installed`
- [ ] 🐧 Linux (Arch): Read `/var/lib/pacman/local/*/desc`
- [ ] 🍎 macOS: Scan `/usr/local/Cellar/` or `/opt/homebrew/Cellar/`
- [ ] 🍎 macOS: Read `INSTALL_RECEIPT.json` for package info
- [ ] 🍎 macOS: Scan `/Applications/`, read `Info.plist`
- [ ] 🪟 Windows: Read `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*`
- [ ] 🪟 Windows: Also check `Wow6432Node` for 32-bit apps
- [ ] 🪟 Windows: Use `Get-HotFix` for Windows updates

#### Unit Tests
- [ ] 🧪 Test dpkg/status file parsing
- [ ] 🧪 Test rpm queryformat parsing
- [ ] 🧪 Test Homebrew receipt JSON parsing
- [ ] 🧪 Test Info.plist parsing
- [ ] 🧪 Test Windows registry parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `dpkg -l`
- [ ] 🔬 🐧 Linux: Verify against `rpm -qa`
- [ ] 🔬 🍎 macOS: Verify against `brew list`
- [ ] 🔬 🪟 Windows: Verify against Programs and Features

---

### 1.7.2 Language Package Managers (8 queries)

#### Implementation
- [ ] All: Scan `site-packages/*/METADATA` for Python packages
- [ ] All: Read `node_modules/*/package.json` for npm (global + project)
- [ ] All: Read `package-lock.json` for full dependency tree
- [ ] All: Read `go.sum` for Go modules
- [ ] All: Read `Cargo.lock` for Rust crates
- [ ] All: Scan `specifications/*.gemspec` for Ruby gems
- [ ] All: Scan `~/.m2/repository/` for Maven dependencies
- [ ] All: Read `composer.lock` for PHP packages
- [ ] All: Scan NuGet packages folder for .NET packages

#### Unit Tests
- [ ] 🧪 Test Python METADATA parsing
- [ ] 🧪 Test package.json parsing
- [ ] 🧪 Test go.sum parsing
- [ ] 🧪 Test Cargo.lock parsing
- [ ] 🧪 Test gemspec parsing
- [ ] 🧪 Test composer.lock parsing

#### Integration Tests
- [ ] 🔬 All: Verify against `pip list`
- [ ] 🔬 All: Verify against `npm list`
- [ ] 🔬 All: Verify against `go list -m all`

---

### 1.7.3 Container Images (3 queries)

#### Implementation
- [ ] All: Call Docker API `/images/json` for image list
- [ ] All: Call Docker API `/images/[id]/history` for layers
- [ ] All: Call Docker API `/images/[id]/json` for inspect
- [ ] All: `docker exec` to read container package state

#### Unit Tests
- [ ] 🧪 Test Docker API response parsing
- [ ] 🧪 Test image layer parsing

#### Integration Tests
- [ ] 🔬 All: Verify against `docker images`
- [ ] 🔬 All: Verify against `docker history`

---

### 1.7.4 SBOM Export (2 queries)

#### Implementation
- [ ] All: Generate CycloneDX 1.4 JSON format
- [ ] All: Generate SPDX 2.3 JSON format
- [ ] All: Include Package URLs (purl) for all packages

#### Unit Tests
- [ ] 🧪 Test CycloneDX schema compliance
- [ ] 🧪 Test SPDX schema compliance
- [ ] 🧪 Test purl generation

---

### 1.7.5 Vulnerability Lookup (3 queries)

#### Implementation
- [ ] 🐧 Linux (Debian): Correlate with apt security lists
- [ ] All: Query OSV API (`api.osv.dev/v1/query`)
- [ ] All: Query NVD data feeds (cached)

#### Unit Tests
- [ ] 🧪 Test vulnerability correlation logic
- [ ] 🧪 Test OSV response parsing
- [ ] 🧪 Test NVD feed parsing

#### Integration Tests
- [ ] 🔬 All: Verify known CVE detection

---

## Phase 2: Enhanced Diagnostics

### 2.1 GPU Diagnostics

#### Implementation
- [ ] 🐧 Linux (NVIDIA): Use NVML library
- [ ] 🐧 Linux (AMD): Read `/sys/class/drm/` sysfs
- [ ] 🐧 Linux (Intel): Read i915 sysfs
- [ ] 🍎 macOS (Apple Silicon): Use Metal Performance Shaders
- [ ] 🍎 macOS (Intel): Use IOKit
- [ ] 🪟 Windows (NVIDIA): Use NVML
- [ ] 🪟 Windows (AMD): Use ADL library
- [ ] 🪟 Windows (Intel): Use WMI
- [ ] 🪟 Windows: Use D3DKMT APIs

#### Unit Tests
- [ ] 🧪 Test GPU info parsing
- [ ] 🧪 Test memory usage calculation
- [ ] 🧪 Test utilization percentage
- [ ] 🧪 Test multi-GPU handling

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `nvidia-smi`
- [ ] 🔬 🐧 Linux: Verify against `radeontop`
- [ ] 🔬 🪟 Windows: Verify against GPU-Z

---

### 2.2 Container Metrics

#### Implementation
- [ ] 🐧 Linux (Docker): Use Docker API via socket
- [ ] 🐧 Linux (Podman): Use Podman API via socket
- [ ] 🐧 Linux: Direct cgroup reading `/sys/fs/cgroup/`
- [ ] 🍎 macOS: Use Docker Desktop API
- [ ] 🪟 Windows: Use Docker Desktop API
- [ ] 🪟 Windows: Use HCS API for Windows containers

#### Unit Tests
- [ ] 🧪 Test container list parsing
- [ ] 🧪 Test stats calculation
- [ ] 🧪 Test container state detection

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `docker stats`
- [ ] 🔬 🍎 macOS: Verify against `docker stats`
- [ ] 🔬 🪟 Windows: Verify against `docker stats`

---

### 2.3 VM Detection

#### Implementation
- [ ] 🐧 Linux: Read `/sys/class/dmi/id/product_name`
- [ ] 🐧 Linux: Check `/proc/cpuinfo` hypervisor flag
- [ ] 🐧 Linux: Use `systemd-detect-virt`
- [ ] 🍎 macOS: Check `sysctl kern.hv_support`
- [ ] 🍎 macOS: Use `system_profiler`
- [ ] 🪟 Windows: Check WMI `Win32_ComputerSystem.Model`
- [ ] 🪟 Windows: Check Hyper-V registry keys

#### Unit Tests
- [ ] 🧪 Test VM type detection
- [ ] 🧪 Test hypervisor identification

#### Integration Tests
- [ ] 🔬 All: Test on real VM vs bare metal

---

## Phase 3: Storage Deep Dive

### 3.1 SMART Disk Health

#### Implementation
- [ ] 🐧 Linux: Call `smartctl` with JSON output
- [ ] 🐧 Linux: Parse NVMe health via `nvme-cli`
- [ ] 🍎 macOS: Call `smartctl` (Homebrew)
- [ ] 🍎 macOS: Use `diskutil info` for basic health
- [ ] 🪟 Windows: Call `smartctl` (if installed)
- [ ] 🪟 Windows: Use WMI `MSStorageDriver_ATAPISmartData`

#### Unit Tests
- [ ] 🧪 Test SMART attribute parsing
- [ ] 🧪 Test health status interpretation
- [ ] 🧪 Test NVMe health parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `smartctl -a`
- [ ] 🔬 🍎 macOS: Verify against `smartctl -a`
- [ ] 🔬 🪟 Windows: Verify against CrystalDiskInfo

---

### 3.2 I/O Latency Tracking

#### Implementation
- [ ] 🐧 Linux: Read `/sys/block/*/stat`
- [ ] 🐧 Linux: Parse `iostat` output
- [ ] 🐧 Linux: Use eBPF if available (optional)
- [ ] 🍎 macOS: Use `iostat` command
- [ ] 🍎 macOS: Use IOKit disk stats
- [ ] 🪟 Windows: Use Performance Counters `LogicalDisk`
- [ ] 🪟 Windows: Use ETW (optional)

#### Unit Tests
- [ ] 🧪 Test I/O stats parsing
- [ ] 🧪 Test latency calculation
- [ ] 🧪 Test throughput calculation

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `iostat -x`
- [ ] 🔬 🍎 macOS: Verify against `iostat`
- [ ] 🔬 🪟 Windows: Verify against Resource Monitor

---

### 3.3 Filesystem Events

#### Implementation
- [ ] 🐧 Linux: Use inotify via `golang.org/x/sys/unix`
- [ ] 🐧 Linux: Use fanotify for system-wide (optional)
- [ ] 🍎 macOS: Use FSEvents via cgo
- [ ] 🪟 Windows: Use `ReadDirectoryChangesW`
- [ ] All: Use `fsnotify` library as cross-platform option

#### Unit Tests
- [ ] 🧪 Test event types (create, modify, delete)
- [ ] 🧪 Test path filtering
- [ ] 🧪 Test recursive watching

#### Integration Tests
- [ ] 🔬 All: Create/modify/delete files and verify events

---

### 3.4 Mount Point Detection

#### Implementation
- [ ] 🐧 Linux: Watch `/proc/mounts`
- [ ] 🐧 Linux: Parse NFS stats from `/proc/net/rpc/nfs`
- [ ] 🍎 macOS: Use `getmntinfo()` periodically
- [ ] 🍎 macOS: Use FSEvents for mount changes
- [ ] 🪟 Windows: Use WMI `Win32_Volume` events
- [ ] 🪟 Windows: Monitor drive letters

#### Unit Tests
- [ ] 🧪 Test mount parsing
- [ ] 🧪 Test NFS/SMB detection
- [ ] 🧪 Test mount change detection

#### Integration Tests
- [ ] 🔬 All: Mount/unmount and verify detection

---

### 3.5 ZFS/LVM/RAID Status

#### Implementation
- [ ] 🐧 Linux (ZFS): Parse `zpool status` JSON
- [ ] 🐧 Linux (LVM): Parse `lvs --reportformat json`
- [ ] 🐧 Linux (MD RAID): Read `/proc/mdstat`
- [ ] 🍎 macOS (ZFS): Parse `zpool status` (if installed)
- [ ] 🍎 macOS: Parse `diskutil appleRAID list`
- [ ] 🪟 Windows: Use `Get-StoragePool` via PowerShell

#### Unit Tests
- [ ] 🧪 Test ZFS pool parsing
- [ ] 🧪 Test LVM volume parsing
- [ ] 🧪 Test RAID status parsing

#### Integration Tests
- [ ] 🔬 🐧 Linux: Test with real ZFS/LVM/RAID if available
- [ ] 🔬 🪟 Windows: Test with Storage Spaces if available

---

## Phase 4: Network Intelligence

### 4.1 Per-Connection Tracking

#### Implementation
- [ ] 🐧 Linux: Read `/proc/net/tcp` and `/proc/net/udp`
- [ ] 🐧 Linux: Map connections to processes via `/proc/[pid]/fd`
- [ ] 🍎 macOS: Use `lsof -i` parsing
- [ ] 🍎 macOS: Use `netstat -anv` parsing
- [ ] 🪟 Windows: Use `GetExtendedTcpTable()`
- [ ] 🪟 Windows: Use `GetExtendedUdpTable()`

#### Unit Tests
- [ ] 🧪 Test connection parsing
- [ ] 🧪 Test process mapping
- [ ] 🧪 Test state detection (ESTABLISHED, LISTEN, etc.)

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify against `ss -tulpn`
- [ ] 🔬 🍎 macOS: Verify against `netstat`
- [ ] 🔬 🪟 Windows: Verify against `netstat -ano`

---

### 4.2 DNS Resolution Stats

#### Implementation
- [ ] 🐧 Linux: Parse `resolvectl statistics` (systemd)
- [ ] 🐧 Linux: Read `/etc/resolv.conf`
- [ ] 🍎 macOS: Parse `scutil --dns`
- [ ] 🪟 Windows: Use `DnsQuery` API
- [ ] 🪟 Windows: Use `Get-DnsClientCache` parsing

#### Unit Tests
- [ ] 🧪 Test resolver config parsing
- [ ] 🧪 Test cache stats parsing

#### Integration Tests
- [ ] 🔬 All: Perform DNS lookups and verify timing

---

### 4.3 Firewall Rule Inspection

#### Implementation
- [ ] 🐧 Linux (iptables): Parse `iptables -L -n` output
- [ ] 🐧 Linux (nftables): Parse `nft list ruleset`
- [ ] 🐧 Linux (ufw): Parse `ufw status`
- [ ] 🍎 macOS: Parse `pfctl -sr`
- [ ] 🍎 macOS: Parse `socketfilterfw` output
- [ ] 🪟 Windows: Use `Get-NetFirewallRule` parsing
- [ ] 🪟 Windows: Use `netsh advfirewall` parsing

#### Unit Tests
- [ ] 🧪 Test rule parsing
- [ ] 🧪 Test port/protocol extraction

#### Integration Tests
- [ ] 🔬 All: Verify against native firewall tools

---

### 4.4 WiFi Signal Metrics

#### Implementation
- [ ] 🐧 Linux: Read `/proc/net/wireless`
- [ ] 🐧 Linux: Use `iw` command parsing
- [ ] 🐧 Linux: Use netlink for nl80211
- [ ] 🍎 macOS: Use CoreWLAN framework
- [ ] 🍎 macOS: Parse `airport -I` output
- [ ] 🪟 Windows: Use `WlanGetNetworkBssList()`
- [ ] 🪟 Windows: Parse `netsh wlan show interfaces`

#### Unit Tests
- [ ] 🧪 Test signal strength parsing
- [ ] 🧪 Test SSID/BSSID parsing
- [ ] 🧪 Test channel info parsing

#### Integration Tests
- [ ] 🔬 All: Verify against native WiFi tools

---

### 4.5 Network Latency Probes

#### Implementation
- [ ] All: Implement ICMP ping (raw sockets)
- [ ] All: Implement TCP ping (connect timing)
- [ ] All: Implement HTTP probe
- [ ] All: Calculate RTT statistics (min, max, avg, p99)

#### Unit Tests
- [ ] 🧪 Test RTT calculation
- [ ] 🧪 Test timeout handling
- [ ] 🧪 Test statistics aggregation

#### Integration Tests
- [ ] 🔬 All: Ping localhost and external hosts

---

## Phase 5: Analytics & Intelligence

### 5.1 Time-Series Storage

#### Implementation
- [ ] All: SQLite backend with time-series schema
- [ ] All: DuckDB backend (optional)
- [ ] All: Retention policy (auto-delete old data)
- [ ] All: Downsampling for long-term data

#### Unit Tests
- [ ] 🧪 Test insert/query operations
- [ ] 🧪 Test time range queries
- [ ] 🧪 Test aggregations (avg, min, max)
- [ ] 🧪 Test retention cleanup

#### Integration Tests
- [ ] 🔬 All: Store and retrieve real metrics

---

### 5.2 Trend Detection

#### Implementation
- [ ] All: Linear regression for trends
- [ ] All: Moving average calculation
- [ ] All: Rate of change detection

#### Unit Tests
- [ ] 🧪 Test trend calculation
- [ ] 🧪 Test edge cases (flat, increasing, decreasing)

---

### 5.3 Anomaly Detection

#### Implementation
- [ ] All: Z-score based detection
- [ ] All: IQR (Interquartile Range) method
- [ ] All: Baseline learning

#### Unit Tests
- [ ] 🧪 Test anomaly detection accuracy
- [ ] 🧪 Test baseline calculation

---

### 5.4 Capacity Forecasting

#### Implementation
- [ ] All: Linear extrapolation
- [ ] All: Time-to-full prediction
- [ ] All: Configurable prediction windows

#### Unit Tests
- [ ] 🧪 Test prediction accuracy
- [ ] 🧪 Test with different growth patterns

---

## Phase 6: Automation & Alerting

### 6.1 Threshold Alerts

#### Implementation
- [ ] All: Alert rule configuration (YAML/JSON)
- [ ] All: Threshold comparison engine
- [ ] All: Hysteresis to prevent flapping
- [ ] All: Alert state management

#### Unit Tests
- [ ] 🧪 Test threshold comparison
- [ ] 🧪 Test hysteresis logic
- [ ] 🧪 Test alert state transitions

---

### 6.2 Composite Alerts

#### Implementation
- [ ] All: Boolean expression parser
- [ ] All: AND/OR/NOT operators
- [ ] All: Nested conditions

#### Unit Tests
- [ ] 🧪 Test expression parsing
- [ ] 🧪 Test evaluation logic

---

### 6.3 Auto-Remediation

#### Implementation
- [ ] 🐧 Linux: Kill process by PID
- [ ] 🐧 Linux: Restart systemd service
- [ ] 🐧 Linux: Clear temp directories
- [ ] 🍎 macOS: Kill process by PID
- [ ] 🍎 macOS: Restart launchd service
- [ ] 🪟 Windows: Kill process by PID
- [ ] 🪟 Windows: Restart Windows service

#### Unit Tests
- [ ] 🧪 Test action configuration parsing
- [ ] 🧪 Test dry-run mode

#### Integration Tests
- [ ] 🔬 All: Test with expendable processes

---

### 6.4 Webhook Triggers

#### Implementation
- [ ] All: HTTP POST to configurable URLs
- [ ] All: Retry with exponential backoff
- [ ] All: Payload templating
- [ ] All: Authentication (Bearer, Basic)

#### Unit Tests
- [ ] 🧪 Test payload generation
- [ ] 🧪 Test retry logic

#### Integration Tests
- [ ] 🔬 All: Send to test webhook endpoint

---

### 6.5 Process Management

#### Implementation
- [ ] 🐧 Linux: Process signals (SIGTERM, SIGKILL)
- [ ] 🐧 Linux: Nice/renice via syscall
- [ ] 🐧 Linux: cgroup resource limits
- [ ] 🍎 macOS: Process signals
- [ ] 🍎 macOS: Nice/renice
- [ ] 🪟 Windows: TerminateProcess()
- [ ] 🪟 Windows: SetPriorityClass()
- [ ] 🪟 Windows: Job objects for limits

#### Unit Tests
- [ ] 🧪 Test signal handling
- [ ] 🧪 Test priority changes

#### Integration Tests
- [ ] 🔬 All: Test with test processes

---

## Phase 7: Security & Compliance

### 7.1 Open Port Detection

#### Implementation
- [ ] All: Detect listening ports (reuse connection tracking)
- [ ] All: Whitelist comparison
- [ ] All: Process identification

#### Unit Tests
- [ ] 🧪 Test port detection
- [ ] 🧪 Test whitelist matching

#### Integration Tests
- [ ] 🔬 All: Start listener and detect it

---

### 7.2 Failed Login Tracking

#### Implementation
- [ ] 🐧 Linux: Parse `/var/log/auth.log`
- [ ] 🐧 Linux: Parse `journalctl -u sshd`
- [ ] 🍎 macOS: Parse `log show` output
- [ ] 🪟 Windows: Query Security Event Log (4625)

#### Unit Tests
- [ ] 🧪 Test log parsing
- [ ] 🧪 Test IP extraction
- [ ] 🧪 Test counting/aggregation

#### Integration Tests
- [ ] 🔬 All: Verify with intentional failed logins

---

### 7.3 File Integrity Monitoring

#### Implementation
- [ ] All: SHA256 hashing of files
- [ ] All: Baseline storage
- [ ] All: Change detection
- [ ] All: Configurable paths

#### Unit Tests
- [ ] 🧪 Test hashing
- [ ] 🧪 Test change detection

#### Integration Tests
- [ ] 🔬 All: Modify files and detect changes

---

### 7.4 Security Benchmarks

#### Implementation
- [ ] 🐧 Linux: CIS benchmark checks
- [ ] 🍎 macOS: CIS benchmark checks
- [ ] 🪟 Windows: CIS benchmark checks
- [ ] All: Scoring system

#### Unit Tests
- [ ] 🧪 Test individual checks
- [ ] 🧪 Test score calculation

---

### 7.5 Patch Status

#### Implementation
- [ ] 🐧 Linux (Debian): Parse `apt list --upgradable`
- [ ] 🐧 Linux (RHEL): Parse `yum check-update`
- [ ] 🍎 macOS: Parse `softwareupdate -l`
- [ ] 🪟 Windows: Query Windows Update API

#### Unit Tests
- [ ] 🧪 Test update parsing

#### Integration Tests
- [ ] 🔬 All: Verify against package managers

---

## Phase 8: Integration & Extensibility

### 8.1 Prometheus Metrics

#### Implementation
- [ ] All: `/metrics` HTTP endpoint
- [ ] All: Gauge/Counter/Histogram metrics
- [ ] All: Label support

#### Unit Tests
- [ ] 🧪 Test metric generation
- [ ] 🧪 Test Prometheus format output

#### Integration Tests
- [ ] 🔬 All: Scrape with Prometheus

---

### 8.2 OpenTelemetry Export

#### Implementation
- [ ] All: OTLP gRPC exporter
- [ ] All: OTLP HTTP exporter
- [ ] All: Metric/trace/log export

#### Unit Tests
- [ ] 🧪 Test OTLP payload generation

---

### 8.3 Plugin System

#### Implementation
- [ ] All: Plugin interface definition
- [ ] All: Plugin discovery and loading
- [ ] All: Plugin configuration
- [ ] All: Hot reload (optional)

#### Unit Tests
- [ ] 🧪 Test plugin loading
- [ ] 🧪 Test plugin lifecycle

---

### 8.4 Multi-Host Agent

#### Implementation
- [ ] All: Agent mode (push metrics)
- [ ] All: HTTP/gRPC push
- [ ] All: Agent registration
- [ ] All: Heartbeat

#### Unit Tests
- [ ] 🧪 Test metric serialization
- [ ] 🧪 Test push logic

---

## Phase 9: LLM Features

### 9.1 Health Scoring

#### Implementation
- [ ] All: Category scoring (CPU, Memory, Disk, etc.)
- [ ] All: Weighted aggregation
- [ ] All: Issue detection

#### Unit Tests
- [ ] 🧪 Test scoring logic
- [ ] 🧪 Test issue detection

---

### 9.2 Diagnostic Workflows

#### Implementation
- [ ] All: Decision tree engine
- [ ] All: Pre-built diagnostics
- [ ] All: Custom workflow support

#### Unit Tests
- [ ] 🧪 Test workflow execution

---

### 9.3 Documentation Generation

#### Implementation
- [ ] All: System inventory template
- [ ] All: Markdown output
- [ ] All: JSON export

#### Unit Tests
- [ ] 🧪 Test template rendering

---

## Infrastructure

### CI/CD
- [x] GitHub Actions workflow
- [x] Multi-platform matrix (Linux, macOS, Windows)
- [x] Unit test job
- [x] Integration test jobs (per-platform)
- [x] Build job (cross-compilation)
- [x] Lint job
- [x] Security scan job

### Documentation
- [x] Feature documentation (6 tier docs)
- [x] Feature support matrix
- [ ] API documentation
- [ ] User guide
- [ ] Contributing guide

### Release
- [ ] Semantic versioning
- [ ] Changelog generation
- [ ] Binary releases
- [ ] Container image
- [ ] Homebrew formula
- [ ] APT/YUM repository
- [ ] Windows installer

---

## Summary

| Category | Queries | Implementation Tasks | Test Tasks |
|----------|:-------:|:--------------------:|:----------:|
| **Phase 1 (MVP)** | 7 | ~70 | ~40 |
| **Phase 1.5 (Logs)** | 6 | ~25 | ~15 |
| **Phase 1.6 (Hooks)** | 37 | ~80 | ~50 |
| **Phase 1.7 (SBOM)** | 31 | ~35 | ~25 |
| Phase 2 (Enhanced) | 6 | ~30 | ~20 |
| Phase 3 (Storage) | 5 | ~35 | ~20 |
| Phase 4 (Network) | 5 | ~40 | ~25 |
| Phase 5 (Analytics) | 4 | ~20 | ~15 |
| Phase 6 (Automation) | 5 | ~35 | ~20 |
| Phase 7 (Security) | 5 | ~30 | ~20 |
| Phase 8 (Integration) | 4 | ~20 | ~15 |
| Phase 9 (LLM) | 3 | ~15 | ~10 |
| **TOTAL** | **106** | **~435** | **~275** |

**Progress:**
- Phase 1 (MVP): ✅ Complete (7/7 queries)
- Phase 1.5-1.7: 📋 Documented, ready for implementation (74 queries)
- Phase 2-9: 📋 Planned (25 queries)
