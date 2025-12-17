# MCP System Info - Implementation TODO

A comprehensive checklist for implementing all features across Linux, macOS, and Windows.

**Legend:**
- [ ] Not started
- [x] Completed
- 🐧 Linux | 🍎 macOS | 🪟 Windows
- 🧪 Unit Test | 🔬 Integration Test

---

## Cross-Platform Architecture

All queries are designed to be **cross-platform** (Linux, macOS, Windows) using only native OS APIs and built-in tools. No external dependencies required.

### Implementation Approach

| Category | Linux | macOS | Windows |
|----------|-------|-------|---------|
| **System Info** | `/proc`, `sysctl` | `sysctl`, IOKit | WMI, Registry |
| **Services** | systemd, sysvinit | launchd | SCM, Event Log |
| **Logs** | journald, syslog | unified logs | Event Log |
| **Auth Logs** | `/var/log/auth.log` | unified logs | Security Event Log |
| **Kernel Events** | `dmesg`, journal | unified logs | System Event Log |
| **Firewall** | iptables/nftables/ufw | pfctl | `Get-NetFirewallRule` |
| **Packages** | dpkg/rpm/apk/pacman | brew/pkgutil | choco/winget/wmic |

### Cross-Platform Guarantees

**All queries rely only on:**
- Native OS logs and APIs
- Built-in commands (no external binaries)
- Structured APIs (systemd/dbus, launchd, WMI/PowerShell)
- Cloud metadata endpoints
- Reading config files

**No queries require:**
- Third-party packages or binaries
- Kernel modules or extensions
- Background daemons
- Filesystem indexing
- Driver-level probing

This is the exact same architectural pattern used for existing CPU/memory/disk/network queries.

---

## Phase 1: MVP - Core Diagnostics ✅ COMPLETE

### 1.0.1 CPU Information ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/stat` for CPU usage
- [x] 🐧 Linux: Read `/proc/loadavg` for load average
- [x] 🐧 Linux: Read `/proc/cpuinfo` for CPU details
- [x] 🐧 Linux: Read `/sys/devices/system/cpu/` for frequency
- [x] 🍎 macOS: Use `sysctl` for CPU info
- [x] 🍎 macOS: Use `host_processor_info()` for usage
- [x] 🍎 macOS: Use `getloadavg()` for load average
- [x] 🪟 Windows: Use WMI `Win32_Processor`
- [x] 🪟 Windows: Use Performance Counters for CPU usage
- [x] 🪟 Windows: Use `GetSystemTimes()` for CPU times

#### Unit Tests
- [x] 🧪 Test CPU percent calculation logic
- [x] 🧪 Test per-CPU parsing
- [x] 🧪 Test frequency info parsing
- [x] 🧪 Test load average parsing (Unix)
- [x] 🧪 Test edge cases (0%, 100%, multi-core)

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `top`/`htop` output
- [x] 🔬 🐧 Linux: Test /proc filesystem reading
- [x] 🔬 🍎 macOS: Verify against `top` output
- [x] 🔬 🍎 macOS: Test sysctl calls
- [x] 🔬 🪟 Windows: Verify against Task Manager
- [x] 🔬 🪟 Windows: Test WMI queries

---

### 1.0.2 Memory Information ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/meminfo`
- [x] 🐧 Linux: Parse swap info from `/proc/swaps`
- [x] 🍎 macOS: Use `vm_statistics64`
- [x] 🍎 macOS: Use `sysctl` for memory info
- [x] 🍎 macOS: Use `swapusage` sysctl
- [x] 🪟 Windows: Use `GlobalMemoryStatusEx()`
- [x] 🪟 Windows: Use WMI `Win32_OperatingSystem`

#### Unit Tests
- [x] 🧪 Test memory calculation (total, used, available)
- [x] 🧪 Test swap parsing
- [x] 🧪 Test percentage calculations
- [x] 🧪 Test unit conversions (bytes, KB, MB, GB)

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `free -m`
- [x] 🔬 🍎 macOS: Verify against `vm_stat`
- [x] 🔬 🪟 Windows: Verify against Task Manager

---

### 1.0.3 Disk Information ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/mounts` for partitions
- [x] 🐧 Linux: Use `statfs()` for usage
- [x] 🐧 Linux: Read `/sys/block/*/stat` for I/O
- [x] 🍎 macOS: Use `getmntinfo()` for mounts
- [x] 🍎 macOS: Use `statfs()` for usage
- [x] 🍎 macOS: Use IOKit for disk I/O
- [x] 🪟 Windows: Use `GetLogicalDriveStrings()`
- [x] 🪟 Windows: Use `GetDiskFreeSpaceEx()`
- [x] 🪟 Windows: Use WMI `Win32_LogicalDisk`

#### Unit Tests
- [x] 🧪 Test partition parsing
- [x] 🧪 Test usage calculations
- [x] 🧪 Test filesystem type detection
- [x] 🧪 Test mount point parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `df -h`
- [x] 🔬 🍎 macOS: Verify against `df -h`
- [x] 🔬 🪟 Windows: Verify against Explorer properties

---

### 1.0.4 Network Information ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/net/dev` for stats
- [x] 🐧 Linux: Read `/sys/class/net/` for interfaces
- [x] 🐧 Linux: Use netlink for addresses
- [x] 🍎 macOS: Use `getifaddrs()` for interfaces
- [x] 🍎 macOS: Use IOKit for network stats
- [x] 🪟 Windows: Use `GetAdaptersAddresses()`
- [x] 🪟 Windows: Use `GetIfTable2()`
- [x] 🪟 Windows: Use Performance Counters

#### Unit Tests
- [x] 🧪 Test interface parsing
- [x] 🧪 Test bytes/packets counting
- [x] 🧪 Test IP address parsing
- [x] 🧪 Test interface flags (up/down)

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `ip addr`
- [x] 🔬 🐧 Linux: Verify against `ifconfig`
- [x] 🔬 🍎 macOS: Verify against `ifconfig`
- [x] 🔬 🪟 Windows: Verify against `ipconfig`

---

### 1.0.5 Process List ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/[pid]/stat` for each process
- [x] 🐧 Linux: Read `/proc/[pid]/cmdline` for command
- [x] 🐧 Linux: Read `/proc/[pid]/status` for details
- [x] 🍎 macOS: Use `proc_listpids()` for PIDs
- [x] 🍎 macOS: Use `proc_pidinfo()` for details
- [x] 🪟 Windows: Use `EnumProcesses()`
- [x] 🪟 Windows: Use `OpenProcess()` + query functions
- [x] 🪟 Windows: Use WMI `Win32_Process`

#### Unit Tests
- [x] 🧪 Test process info parsing
- [x] 🧪 Test CPU percent calculation
- [x] 🧪 Test memory usage calculation
- [x] 🧪 Test sorting (by CPU, memory, name)
- [x] 🧪 Test filtering

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `ps aux`
- [x] 🔬 🍎 macOS: Verify against `ps aux`
- [x] 🔬 🪟 Windows: Verify against Task Manager

---

### 1.0.6 System Uptime ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/uptime`
- [x] 🍎 macOS: Use `sysctl kern.boottime`
- [x] 🪟 Windows: Use `GetTickCount64()`
- [x] 🪟 Windows: Use WMI `Win32_OperatingSystem.LastBootUpTime`

#### Unit Tests
- [x] 🧪 Test uptime parsing
- [x] 🧪 Test boot time calculation
- [x] 🧪 Test human-readable formatting

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `uptime`
- [x] 🔬 🍎 macOS: Verify against `uptime`
- [x] 🔬 🪟 Windows: Verify against Task Manager

---

### 1.0.7 Temperature Information ✅

#### Implementation
- [x] 🐧 Linux: Read `/sys/class/thermal/`
- [x] 🐧 Linux: Read `/sys/class/hwmon/`
- [x] 🐧 Linux: Support lm-sensors
- [x] 🍎 macOS: Use IOKit `SMCReadKey`
- [ ] 🍎 macOS: Use `powermetrics` (root) - optional, requires root
- [x] 🪟 Windows: Use WMI `MSAcpi_ThermalZoneTemperature`
- [ ] 🪟 Windows: Use Open Hardware Monitor WMI - optional, requires OHM installed

#### Unit Tests
- [x] 🧪 Test temperature parsing
- [x] 🧪 Test sensor name mapping
- [x] 🧪 Test unit conversion (C/F)

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `sensors`
- [x] 🔬 🍎 macOS: Verify against iStats
- [x] 🔬 🪟 Windows: Verify against HWMonitor

---

## Phase 1.5: Log Access (Critical for Diagnostics) ✅ COMPLETE

Log access enables true root cause analysis for security incident triage. Without logs, AI can only see symptoms ("CPU is high") but not causes.

### 1.5.1 Journald Logs (Linux) ✅

#### Implementation
- [x] 🐧 Linux: `journalctl -o json` for structured output
- [x] 🐧 Linux: Filter by unit (`-u nginx`)
- [x] 🐧 Linux: Filter by priority (`-p err..emerg`)
- [x] 🐧 Linux: Filter by time (`--since`, `--until`)
- [x] 🐧 Linux: Filter by executable (`_COMM=sshd`)
- [x] 🐧 Linux: Kernel messages (`-k`)

#### Unit Tests
- [x] 🧪 Test JSON parsing of journalctl output
- [x] 🧪 Test time range filtering
- [x] 🧪 Test priority filtering
- [x] 🧪 Test log entry struct parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify service logs match `journalctl -u`
- [x] 🔬 🐧 Linux: Verify kernel messages match `dmesg`

---

### 1.5.2 Syslog ✅

#### Implementation
- [x] 🐧 Linux: Read `/var/log/syslog` or `/var/log/messages`
- [x] 🐧 Linux: Parse RFC 5424 syslog format
- [x] 🍎 macOS: Use `log show` command with predicates
- [x] 🍎 macOS: Read `/var/log/system.log` (legacy)

#### Unit Tests
- [x] 🧪 Test syslog line parsing
- [x] 🧪 Test facility/severity extraction
- [x] 🧪 Test timestamp parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `tail /var/log/syslog`
- [x] 🔬 🍎 macOS: Verify against `log show`

---

### 1.5.3 Application Logs ✅

#### Implementation
- [x] 🐧 Linux: Scan `/var/log/{app}/` directories
- [x] 🐧 Linux: Common paths: nginx, apache2, mysql, postgresql
- [x] 🐧 Linux: Docker logs via `docker logs` or container log files
- [x] 🍎 macOS: Read `~/Library/Logs/` and `/Library/Logs/`
- [x] 🍎 macOS: Use `log show --predicate` for app subsystems
- [x] 🪟 Windows: Read `%AppData%\Local\{App}\Logs\`
- [x] 🪟 Windows: Read `%ProgramData%\{App}\Logs\`

#### Unit Tests
- [x] 🧪 Test log file discovery
- [x] 🧪 Test common log format parsing
- [x] 🧪 Test JSON log parsing
- [x] 🧪 Test log rotation handling

#### Integration Tests
- [x] 🔬 All: Verify known app logs are discoverable
- [x] 🔬 🐧 Linux: Test Docker container log reading

---

### 1.5.4 Kernel/Boot Logs ✅

#### Implementation
- [x] 🐧 Linux: Read `dmesg` ring buffer
- [x] 🐧 Linux: Read `/var/log/kern.log`
- [x] 🐧 Linux: Use `journalctl -k -b` for boot kernel messages
- [x] 🍎 macOS: Use `dmesg` command
- [x] 🍎 macOS: Use `log show --predicate 'sender == "kernel"'`
- [x] 🪟 Windows: Read System Event Log
- [x] 🪟 Windows: Use `Get-WinEvent -LogName System`

#### Unit Tests
- [x] 🧪 Test dmesg parsing
- [x] 🧪 Test kernel log severity extraction
- [x] 🧪 Test boot message filtering

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `dmesg` output
- [x] 🔬 🪟 Windows: Verify against Event Viewer

---

### 1.5.5 Authentication/Security Logs ✅

#### Implementation
- [x] 🐧 Linux (Debian): Read `/var/log/auth.log`
- [x] 🐧 Linux (RHEL): Read `/var/log/secure`
- [x] 🐧 Linux: Parse SSH login attempts
- [x] 🐧 Linux: Parse sudo commands
- [x] 🐧 Linux: Read audit.log if auditd enabled
- [x] 🍎 macOS: Read `/var/log/secure.log`
- [x] 🍎 macOS: Use `log show --predicate 'category == "auth"'`
- [x] 🪟 Windows: Read Security Event Log
- [x] 🪟 Windows: Filter login events (4624, 4625)

#### Unit Tests
- [x] 🧪 Test auth log parsing
- [x] 🧪 Test SSH attempt extraction
- [x] 🧪 Test Windows event ID filtering

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify failed login detection
- [x] 🔬 🪟 Windows: Verify against Security Event Log

---

### 1.5.6 Windows Event Log ✅

#### Implementation
- [x] 🪟 Windows: Use `Get-WinEvent` PowerShell
- [x] 🪟 Windows: Query System log
- [x] 🪟 Windows: Query Application log
- [x] 🪟 Windows: Query Security log (requires admin)
- [x] 🪟 Windows: Query Setup log
- [x] 🪟 Windows: Filter by event ID, level, time range

#### Unit Tests
- [x] 🧪 Test event log entry parsing
- [x] 🧪 Test event ID filtering
- [x] 🧪 Test time range queries

#### Integration Tests
- [x] 🔬 🪟 Windows: Verify against Event Viewer

---

## Phase 1.6: System Hooks (31 Queries) ✅ COMPLETE

Zero-dependency deep system introspection. See [docs/08-system-hooks.md](docs/08-system-hooks.md) for full details.

### 1.6.1 Scheduled Tasks & Startup (4 queries) ✅

#### Implementation
- [x] 🐧 Linux: Read `/var/spool/cron/crontabs/*` for user crons
- [x] 🐧 Linux: Read `/etc/crontab`, `/etc/cron.d/*` for system crons
- [x] 🐧 Linux: List `systemctl list-timers` for systemd timers
- [x] 🍎 macOS: Read `/Library/LaunchDaemons/*.plist`
- [x] 🍎 macOS: Read `/Library/LaunchAgents/*.plist`
- [x] 🍎 macOS: Read `~/Library/LaunchAgents/*.plist`
- [x] 🪟 Windows: Read `C:\Windows\System32\Tasks\*` XML files
- [x] 🐧 Linux: Read `/etc/systemd/system/*.wants/` for startup services
- [x] 🍎 macOS: Read Login Items from LaunchAgents
- [x] 🪟 Windows: Read `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

#### Unit Tests
- [x] 🧪 Test crontab parsing
- [x] 🧪 Test plist parsing
- [x] 🧪 Test Windows Task XML parsing
- [x] 🧪 Test systemd timer parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `crontab -l`
- [x] 🔬 🍎 macOS: Verify against `launchctl list`
- [x] 🔬 🪟 Windows: Verify against Task Scheduler

---

### 1.6.2 Kernel & Drivers (2 queries) ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/modules` for loaded modules
- [x] 🐧 Linux: Read `/sys/module/*/parameters/` for module params
- [x] 🐧 Linux: Read `/proc/sys/` for kernel parameters
- [x] 🍎 macOS: Parse `kextstat` output for kernel extensions
- [x] 🍎 macOS: Read `sysctl -a` for kernel parameters
- [x] 🪟 Windows: Use `EnumDeviceDrivers()` API
- [x] 🪟 Windows: Read registry for driver parameters

#### Unit Tests
- [x] 🧪 Test /proc/modules parsing
- [x] 🧪 Test kextstat output parsing
- [x] 🧪 Test sysctl parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `lsmod`
- [x] 🔬 🍎 macOS: Verify against `kextstat`
- [x] 🔬 🪟 Windows: Verify against `driverquery`

---

### 1.6.3 Network Configuration (6 queries) ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/net/tcp`, `/proc/net/udp` for listening ports
- [x] 🐧 Linux: Map ports to processes via `/proc/[pid]/fd`
- [x] 🍎 macOS: Parse `lsof -i -P` for listening ports
- [x] 🪟 Windows: Use `GetExtendedTcpTable()` / `GetExtendedUdpTable()`
- [x] 🐧 Linux: Read `/etc/resolv.conf` for DNS config
- [x] 🍎 macOS: Parse `scutil --dns` for DNS config
- [x] 🪟 Windows: Read `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
- [x] All: Read `/etc/hosts` (or Windows equivalent)
- [x] 🐧 Linux: Read `/proc/net/route` for routing table
- [x] 🐧 Linux: Read `/proc/net/arp` for ARP cache
- [x] 🐧 Linux: Parse `iptables -L -n` or `nft list ruleset`
- [x] 🍎 macOS: Parse `pfctl -sr` for firewall rules
- [x] 🪟 Windows: Use `Get-NetFirewallRule` via PowerShell

#### Unit Tests
- [x] 🧪 Test /proc/net/tcp parsing
- [x] 🧪 Test resolv.conf parsing
- [x] 🧪 Test hosts file parsing
- [x] 🧪 Test route table parsing
- [x] 🧪 Test iptables/nft rule parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `ss -tulpn`
- [x] 🔬 🐧 Linux: Verify against `ip route`
- [x] 🔬 🐧 Linux: Verify against `iptables -L`

---

### 1.6.4 File System (4 queries) ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/[pid]/fd/` for open files (targeted by PID)
- [x] 🍎 macOS: Parse `lsof -p [pid]` for open files
- [x] 🪟 Windows: Use `NtQuerySystemInformation()` for handles
- [x] 🐧 Linux: Read `/proc/sys/fs/file-nr` for FD limits
- [x] 🐧 Linux: Use `statfs()` for inode usage
- [x] 🐧 Linux: Read `/proc/mounts` for mount options

#### Unit Tests
- [x] 🧪 Test /proc/[pid]/fd parsing
- [x] 🧪 Test file-nr parsing
- [x] 🧪 Test mount options parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `lsof -p`
- [x] 🔬 🐧 Linux: Verify against `df -i`

---

### 1.6.5 Security Configuration (6 queries) - PARTIAL (sensitive scope)

Some security queries require `sensitive` scope and are not exposed by default.

#### Implementation
- [x] 🐧 Linux: Read `/etc/passwd`, `/etc/group` for users/groups
- [x] 🍎 macOS: Use `dscl . -list /Users` for users
- [x] 🪟 Windows: Use `NetUserEnum()` API
- [x] 🐧 Linux: Read `/etc/sudoers`, `/etc/sudoers.d/*`
- [x] 🐧 Linux: Read `/etc/ssh/sshd_config`
- [x] 🐧 Linux: Scan `/etc/ssl/certs/` for certificate expiry
- [x] 🍎 macOS: Query Keychain for certificates
- [x] 🪟 Windows: Query Certificate Store
- [x] 🐧 Linux: Read `/sys/fs/selinux/enforce` for SELinux status
- [x] 🐧 Linux: Read `/sys/kernel/security/apparmor/profiles`

#### Unit Tests
- [x] 🧪 Test /etc/passwd parsing
- [x] 🧪 Test sudoers parsing
- [x] 🧪 Test sshd_config parsing
- [x] 🧪 Test X.509 certificate parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `getent passwd`
- [x] 🔬 🐧 Linux: Verify against `sestatus`

---

### 1.6.6 Hardware Information (4 queries) ✅

#### Implementation
- [x] 🐧 Linux: Read `/sys/class/dmi/id/*` for hardware info
- [x] 🍎 macOS: Parse `system_profiler SPHardwareDataType -json`
- [x] 🪟 Windows: Use WMI `Win32_ComputerSystem`, `Win32_BaseBoard`
- [x] 🐧 Linux: Read `/sys/bus/usb/devices/*/` for USB devices
- [x] 🐧 Linux: Read `/sys/bus/pci/devices/*/` for PCI devices
- [x] 🐧 Linux: Read `/sys/block/*/` for block device topology

#### Unit Tests
- [x] 🧪 Test DMI sysfs parsing
- [x] 🧪 Test USB device parsing
- [x] 🧪 Test PCI device parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `lsusb`
- [x] 🔬 🐧 Linux: Verify against `lspci`

---

### 1.6.7 Process & Resources (5 queries) ✅

#### Implementation
- [x] 🐧 Linux: Read `/proc/[pid]/environ` for environment variables
- [x] 🐧 Linux: Read `/proc/sysvipc/*` for IPC resources
- [x] 🐧 Linux: Read `/proc/[pid]/ns/` for namespaces
- [x] 🐧 Linux: Read `/sys/fs/cgroup/` for cgroup limits
- [x] 🐧 Linux: Read `/proc/[pid]/status` for capabilities

#### Unit Tests
- [x] 🧪 Test environ parsing
- [x] 🧪 Test sysvipc parsing
- [x] 🧪 Test namespace detection
- [x] 🧪 Test cgroup parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `ipcs`
- [x] 🔬 🐧 Linux: Verify against `lsns`

---

### 1.6.8 System State (6 queries) ✅

#### Implementation
- [x] 🐧 Linux: Read `/sys/class/dmi/id/product_name` for VM detection
- [x] 🐧 Linux: Check `/proc/cpuinfo` hypervisor flag
- [x] 🍎 macOS: Check `sysctl kern.hv_support`
- [x] 🪟 Windows: Check WMI for hypervisor
- [x] All: Read `/etc/timezone` or equivalent for locale
- [x] 🐧 Linux: Parse `timedatectl status` for NTP status
- [x] 🐧 Linux: Scan `/var/crash/` for core dumps
- [x] 🐧 Linux: Read `/sys/class/power_supply/` for power state
- [x] 🐧 Linux: Read `/sys/devices/system/node/` for NUMA topology

#### Unit Tests
- [x] 🧪 Test VM detection heuristics
- [x] 🧪 Test timedatectl parsing
- [x] 🧪 Test power supply sysfs parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `systemd-detect-virt`
- [x] 🔬 🐧 Linux: Verify against `numactl -H`

---

## Phase 1.7: SBOM & Software Inventory (31 Queries) ✅ COMPLETE

Software Bill of Materials for vulnerability detection. See [docs/09-sbom-inventory.md](docs/09-sbom-inventory.md) for full details.

**Progress: 31/31 queries implemented**

### 1.7.0 PATH Executables (1 query) ✅ COMPLETE

> ⚠️ **Scope Limitation**: This query only scans directories in the PATH environment variable. It does **not** perform a deep filesystem scan or index all executables on the system. This is intentional for performance and security reasons. For complete software inventory, use `get_system_packages`.

#### Implementation
- [x] All: Iterate directories in PATH environment variable
- [x] All: Find all executable files in each directory
- [x] All: Deduplicate (first occurrence wins, like shell behavior)
- [x] All: Return list with name, path, and file metadata (size, mtime)
- [ ] Optional: Attempt version detection via `--version` with timeout
- [x] Optional: Categorize by type (script, binary, symlink)

#### Unit Tests
- [x] 🧪 Test PATH parsing (colon-separated on Unix, semicolon on Windows)
- [x] 🧪 Test executable detection (file permissions on Unix, extensions on Windows)
- [x] 🧪 Test deduplication logic
- [x] 🧪 Test handling of non-existent PATH directories

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `which -a` for common commands
- [x] 🔬 🍎 macOS: Verify against `which -a` for common commands
- [x] 🔬 🪟 Windows: Verify against `where.exe` for common commands

---

### 1.7.1 System Package Managers (6 queries) ✅ COMPLETE

#### Implementation
- [x] 🐧 Linux (Debian): Use `dpkg-query` with custom format
- [x] 🐧 Linux (RHEL): Use `rpm -qa --queryformat`
- [x] 🐧 Linux (Alpine): Use `apk info -v`
- [x] 🐧 Linux (Arch): Use `pacman -Q`
- [x] 🍎 macOS: Use `brew list --versions`
- [x] 🍎 macOS: Use `pkgutil --pkgs` for system packages
- [x] 🍎 macOS: Scan `/Applications/`, read `Info.plist`
- [x] 🪟 Windows: Use `choco list --local-only`
- [x] 🪟 Windows: Use `winget list`
- [x] 🪟 Windows: Use `wmic product get` as fallback
- [x] 🪟 Windows: Use `Get-HotFix` for Windows updates

#### Unit Tests
- [x] 🧪 Test dpkg output parsing
- [x] 🧪 Test rpm queryformat parsing
- [x] 🧪 Test apk output parsing
- [x] 🧪 Test pacman output parsing
- [x] 🧪 Test Homebrew output parsing
- [x] 🧪 Test pkgutil output parsing
- [x] 🧪 Test Chocolatey output parsing
- [x] 🧪 Test winget output parsing
- [x] 🧪 Test wmic CSV parsing

#### Integration Tests
- [x] 🔬 🐧 Linux: Verify against `dpkg -l`
- [x] 🔬 🐧 Linux: Verify against `rpm -qa`
- [x] 🔬 🍎 macOS: Verify against `brew list`
- [x] 🔬 🪟 Windows: Verify against `choco list`

---

### 1.7.2 Language Package Managers (5 queries) ✅ COMPLETE

#### Implementation
- [x] All: Scan `site-packages/*/METADATA` for Python packages
- [x] All: Read `node_modules/*/package.json` for npm (global)
- [ ] All: Read `package-lock.json` for full dependency tree
- [x] All: Scan `go/pkg/mod/cache` for Go modules
- [x] All: Scan `.cargo/registry/cache` for Rust crates
- [x] All: Scan `specifications/*.gemspec` for Ruby gems
- [x] All: Scan `~/.m2/repository/` for Maven dependencies
- [x] All: Read Composer global packages for PHP
- [x] All: Scan NuGet packages folder for .NET packages

#### Unit Tests
- [x] 🧪 Test Python METADATA parsing
- [x] 🧪 Test package.json parsing
- [x] 🧪 Test Go module path decoding
- [x] 🧪 Test Cargo registry scanning
- [x] 🧪 Test gemspec parsing
- [x] 🧪 Test Maven repository scanning
- [x] 🧪 Test PHP Composer parsing
- [x] 🧪 Test NuGet package parsing

#### Integration Tests
- [x] 🔬 All: Verify against `pip list`
- [x] 🔬 All: Verify against `npm list`
- [x] 🔬 All: Verify against `go list -m all`

---

### 1.7.3 Container Images (3 queries) ✅ COMPLETE

#### Implementation
- [x] All: Call Docker API `/images/json` for image list
- [x] All: Call Docker API `/images/[id]/history` for layers
- [x] All: Call Docker API `/containers/json` for container list
- [ ] All: `docker exec` to read container package state

#### Unit Tests
- [ ] 🧪 Test Docker API response parsing
- [ ] 🧪 Test image layer parsing

#### Integration Tests
- [x] 🔬 All: Verify against `docker images`
- [x] 🔬 All: Verify against `docker history`

---

### 1.7.4 SBOM Export (2 queries) ✅ COMPLETE

#### Implementation
- [x] All: Generate CycloneDX 1.4 JSON format
- [x] All: Generate SPDX 2.3 JSON format
- [x] All: Include Package URLs (purl) for all packages

#### Unit Tests
- [ ] 🧪 Test CycloneDX schema compliance
- [ ] 🧪 Test SPDX schema compliance
- [x] 🧪 Test purl generation

---

### 1.7.5 Vulnerability Lookup (3 queries) ✅ COMPLETE

#### Implementation
- [x] 🐧 Linux (Debian): Query Debian Security Tracker API
- [x] All: Query OSV API (`api.osv.dev/v1/query`)
- [x] All: Query NVD API for CVE lookup

#### Unit Tests
- [x] 🧪 Test vulnerability correlation logic
- [x] 🧪 Test OSV response parsing
- [x] 🧪 Test Debian Security Tracker parsing
- [x] 🧪 Test NVD API response parsing

#### Integration Tests
- [x] 🔬 All: Verify known CVE detection

---

## Phase 1.8: Application Discovery & Configuration (2 Queries) ✅ COMPLETE

Dynamic application discovery and secure configuration reading with rigorous redaction.

### 1.8.1 Application Discovery (1 query: `get_applications`)

Automatically discover installed/running applications and their metadata.

#### Implementation
- [x] 🐧 Linux: Scan systemd services (`systemctl list-units`)
- [x] 🐧 Linux: Check running processes and map to known applications
- [x] 🐧 Linux: Probe well-known config paths (`/etc/nginx`, `/etc/apache2`, `/etc/mysql`, etc.)
- [x] 🐧 Linux: Check listening ports and correlate to services
- [x] 🐧 Linux: Parse package manager for installed server software
- [x] 🍎 macOS: Scan launchd services (`launchctl list`)
- [x] 🍎 macOS: Check Homebrew services (`brew services list`)
- [x] 🍎 macOS: Scan `/Applications` for installed apps
- [x] 🍎 macOS: Check running processes
- [x] 🪟 Windows: Scan Windows Services (`Get-Service`)
- [x] 🪟 Windows: Query IIS metabase for web apps
- [x] 🪟 Windows: Check registry for installed applications
- [x] 🪟 Windows: Scan running processes
- [x] 🪟 Windows: Check SQL Server instances
- [x] All: Return structured data: name, type, version, service, status, config_paths, log_paths

#### Application Types to Detect
- Web Servers: nginx, Apache, IIS, Tomcat, Caddy
- Databases: MySQL/MariaDB, PostgreSQL, SQL Server, MongoDB, Redis, Elasticsearch
- Message Queues: RabbitMQ, Kafka, ActiveMQ
- App Runtimes: PHP-FPM, Node.js, .NET, JVM apps
- Caching: Memcached, Varnish
- Mail: Postfix, Exchange
- Directory: Active Directory, OpenLDAP
- Containers: Docker, Podman
- Security: Fail2ban, ModSecurity

#### Unit Tests
- [ ] 🧪 Test service enumeration parsing
- [ ] 🧪 Test process-to-application mapping
- [ ] 🧪 Test config path detection
- [ ] 🧪 Test version extraction

#### Integration Tests
- [ ] 🔬 🐧 Linux: Verify nginx detection when installed
- [ ] 🔬 🐧 Linux: Verify MySQL detection when installed
- [ ] 🔬 🪟 Windows: Verify IIS detection when installed
- [ ] 🔬 🪟 Windows: Verify SQL Server detection when installed

---

### 1.8.2 Application Configuration (1 query: `get_app_config`)

Read application configuration files with rigorous secret redaction.

#### Implementation
- [x] All: Accept app name (uses discovered paths) or explicit file path
- [x] All: Auto-detect config format by extension and content
- [x] All: Parse and validate config structure where possible
- [x] All: Apply comprehensive redaction before returning
- [x] All: Return: path, format, content (redacted), redaction summary

#### Config Format Parsers
- [x] INI / properties files
- [x] XML (IIS, Tomcat, .NET web.config)
- [x] JSON
- [x] YAML
- [x] TOML
- [x] Nginx conf format
- [x] Apache conf format
- [x] Key=value / environment files

#### Redaction Patterns (CRITICAL - must be rigorous)

**Key Name Patterns** (case-insensitive):
- [x] `password`, `passwd`, `pwd`
- [x] `secret`, `private`
- [x] `token`, `apikey`, `api_key`, `api-key`
- [x] `credential`, `cred`
- [x] `auth`, `authentication`
- [x] `key` (when followed by `=` or `:`)
- [x] `certificate`, `cert` (for private keys)
- [x] `connection_string`, `connectionstring`, `connstr`

**Value Patterns**:
- [x] Connection strings: `mongodb://`, `mysql://`, `postgres://`, `redis://`, `amqp://`
- [x] AWS credentials: `AKIA[A-Z0-9]{16}`, `aws_secret_access_key`
- [x] Azure: `AccountKey=`, `SharedAccessSignature=`
- [x] GCP: `private_key_id`, `private_key` in JSON
- [x] JWT tokens: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- [x] Bearer tokens: `Bearer [A-Za-z0-9_-]+`
- [x] PEM blocks: `-----BEGIN.*PRIVATE KEY-----`
- [x] Base64 blobs (long strings that decode to binary)
- [x] Hex-encoded secrets (32+ char hex strings)

**Environment Variable References** (flag but don't redact):
- [x] `${VAR}`, `$VAR`
- [x] `%VAR%` (Windows)
- [x] `{{VAR}}` (templates)

#### Unit Tests
- [ ] 🧪 Test each config format parser
- [ ] 🧪 Test key name redaction patterns
- [ ] 🧪 Test value pattern redaction (AWS, connection strings, etc.)
- [ ] 🧪 Test PEM block redaction
- [ ] 🧪 Test JWT redaction
- [ ] 🧪 Test redaction doesn't break config structure
- [ ] 🧪 Test redaction summary accuracy

#### Integration Tests
- [ ] 🔬 All: Read nginx.conf and verify passwords redacted
- [ ] 🔬 All: Read database config and verify credentials redacted
- [ ] 🔬 🪟 Windows: Read IIS web.config and verify connection strings redacted
- [ ] 🔬 All: Verify non-sensitive values are NOT redacted

---

## Phase 1.9: Triage & Summary Queries (25 Queries) 🚧 IN PROGRESS

High-level queries for incident triage, providing summarized views and snapshots. All queries are cross-platform with OS-specific backends.

**Progress: 5/25 queries implemented**

### 1.9.1 System Overview (4 queries) ✅ COMPLETE

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_os_info` | OS version, build, kernel | ✅ | ✅ | ✅ |
| `get_system_profile` | CPU/RAM/disk summary | ✅ | ✅ | ✅ |
| `get_service_manager_info` | Service manager status | ✅ | ✅ | ✅ |
| `get_cloud_environment` | Cloud provider detection | ✅ | ✅ | ✅ |

#### Implementation
- [x] 🐧 Linux: `/etc/os-release`, `uname`, `/proc`
- [x] 🍎 macOS: `sw_vers`, `sysctl`, `system_profiler`
- [x] 🪟 Windows: WMI `Win32_OperatingSystem`, Registry
- [x] All: Cloud metadata endpoints (169.254.169.254, DMI strings)

---

### 1.9.2 Recent Events (6 queries)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_recent_reboots` | Recent system reboots | ✅ | ✅ | ⚠️ |
| `get_recent_service_failures` | Failed service restarts | ⚠️ | ⚠️ | ⚠️ |
| `get_recent_kernel_events` | Kernel warnings/errors | ⚠️ | ⚠️ | ⚠️ |
| `get_recent_resource_incidents` | OOM, CPU throttle events | ⚠️ | ⚠️ | ⚠️ |
| `get_recent_config_changes` | Package/config changes | ⚠️ | ⚠️ | ⚠️ |
| `get_recent_critical_events` | Critical log entries | ⚠️ | ⚠️ | ⚠️ |

#### Implementation
- [ ] 🐧 Linux: `last`, journald, `dmesg`, package logs
- [ ] 🍎 macOS: `last`, unified logs, `dmesg`
- [ ] 🪟 Windows: Event Log (System, Application, Security)

---

### 1.9.3 Service & Scheduling (4 queries)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_failed_units` | Failed services/units | ⚠️ | ⚠️ | ⚠️ |
| `get_timer_jobs` | Scheduled timers/jobs | ⚠️ | ⚠️ | ⚠️ |
| `get_service_log_view` | Service-specific logs | ⚠️ | ⚠️ | ⚠️ |
| `get_deployment_events` | Package install/update logs | ⚠️ | ⚠️ | ⚠️ |

#### Implementation
- [ ] 🐧 Linux: `systemctl --failed`, `systemctl list-timers`, journald
- [ ] 🍎 macOS: `launchctl list`, `log show --predicate`
- [ ] 🪟 Windows: `Get-Service`, Task Scheduler, Event Log

---

### 1.9.4 Security Summary (6 queries)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_auth_failure_summary` | Failed auth attempts | ⚠️ | ⚠️ | ⚠️ |
| `get_security_basics` | Firewall/SELinux status | ⚠️ | ⚠️ | ⚠️ |
| `get_ssh_security_summary` | SSH config analysis | ⚠️ | ⚠️ | ⚠️ |
| `get_admin_account_summary` | Admin/sudo users | ⚠️ | ⚠️ | ⚠️ |
| `get_exposed_services_summary` | Listening services | ⚠️ | ⚠️ | ⚠️ |
| `get_top_resource_limits` | ulimit/quota summary | ⚠️ | ⚠️ | ⚠️ |

#### Implementation
- [ ] 🐧 Linux: `/var/log/auth.log`, `iptables`, `/etc/ssh/sshd_config`, `getent`
- [ ] 🍎 macOS: unified logs, `pfctl`, `/etc/ssh/sshd_config`, `dscl`
- [ ] 🪟 Windows: Security Event Log, `Get-NetFirewallRule`, OpenSSH config, `net user`

---

### 1.9.5 Software & Runtime (3 queries) - PARTIAL (1/3)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_recently_installed_software` | Recent package installs | ⚠️ | ⚠️ | ⚠️ |
| `get_language_runtime_versions` | Python/Node/Go/etc versions | ✅ | ✅ | ✅ |
| `get_fs_health_summary` | Filesystem health overview | ⚠️ | ⚠️ | ⚠️ |

#### Implementation
- [ ] 🐧 Linux: dpkg/rpm logs, `df`
- [ ] 🍎 macOS: brew logs, pkgutil history, `diskutil`
- [ ] 🪟 Windows: MSI logs, `wmic`, `fsutil`
- [x] All: Language runtime detection (`python --version`, `node --version`, etc.)

---

### 1.9.6 Meta Queries (2 queries)

Composite queries that orchestrate multiple sub-queries for comprehensive snapshots.

| Query | Description | Components |
|-------|-------------|------------|
| `get_incident_triage_snapshot` | Full incident context | os_info, recent_events, service_failures, auth_failures |
| `get_security_posture_snapshot` | Security overview | security_basics, exposed_services, admin_accounts, ssh_config |

#### Implementation
- [ ] All: Orchestrate OS-specific sub-queries
- [ ] All: Return unified JSON schema across platforms
- [ ] All: Include cross-references between related data

---

### Cross-Platform Support Legend

- **✅ Fully identical behaviour** - Same output schema, same data sources
- **⚠️ OS-specific backends** - Same output schema, different implementation per OS

All ⚠️ queries follow the existing pattern used for CPU/memory/disk/network queries.

---

## Phase 1.10: Windows Enterprise Features (15 Queries) 📋 PLANNED

Windows-specific queries for enterprise environments. These queries are Windows-only but follow the same zero-dependency architecture using native APIs (WMI, Registry, COM).

### 1.10.1 Registry Queries (3 queries)

| Query | Description | API |
|-------|-------------|-----|
| `get_registry_key` | Read registry key and values | `RegOpenKeyEx`, `RegQueryValueEx` |
| `get_registry_tree` | Enumerate subkeys recursively | `RegEnumKeyEx`, `RegEnumValue` |
| `get_registry_security` | Key permissions and ownership | `RegGetKeySecurity` |

#### Implementation
- [ ] 🪟 Read from HKLM, HKCU, HKCR, HKU hives
- [ ] 🪟 Support REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ types
- [ ] 🪟 Parse security descriptors (owner, DACL, SACL)
- [ ] 🪟 Handle access denied gracefully
- [ ] 🪟 Support path wildcards for discovery

#### Common Registry Paths for Diagnostics
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` - Startup programs
- `HKLM\SYSTEM\CurrentControlSet\Services` - Windows services
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` - OS version details
- `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` - System environment

---

### 1.10.2 DCOM/COM Security (4 queries)

| Query | Description | API |
|-------|-------------|-----|
| `get_dcom_applications` | List registered DCOM apps | Registry + `CoGetClassObject` |
| `get_dcom_permissions` | Launch/access permissions | `CoGetSecurityDescriptor` |
| `get_dcom_identities` | RunAs identities per app | Registry `AppID` keys |
| `get_com_security_defaults` | Machine-wide COM security | `CoGetDefaultSecurity` |

#### Implementation
- [ ] 🪟 Read `HKCR\AppID\{GUID}` for DCOM application registration
- [ ] 🪟 Parse `LaunchPermission` and `AccessPermission` binary values
- [ ] 🪟 Read `RunAs` identity (Interactive User, Launching User, specific account)
- [ ] 🪟 Check `HKLM\SOFTWARE\Microsoft\Ole` for machine defaults
- [ ] 🪟 Decode security descriptors to human-readable ACLs
- [ ] 🪟 Identify DCOM apps running as SYSTEM or with elevated privileges

#### Security Considerations
- Flag DCOM apps with weak permissions (Everyone: Allow)
- Identify apps running as LocalSystem unnecessarily
- Check for anonymous access enabled

---

### 1.10.3 IIS Web Server (8 queries)

| Query | Description | API |
|-------|-------------|-----|
| `get_iis_sites` | List all IIS websites | `Microsoft.Web.Administration` / WMI |
| `get_iis_app_pools` | Application pool configuration | `Microsoft.Web.Administration` |
| `get_iis_bindings` | Site bindings (ports, hostnames, SSL) | WMI `IIsWebServerSetting` |
| `get_iis_virtual_dirs` | Virtual directories and applications | `Microsoft.Web.Administration` |
| `get_iis_handlers` | Handler mappings | `applicationHost.config` |
| `get_iis_modules` | Installed IIS modules | `applicationHost.config` |
| `get_iis_ssl_certs` | SSL certificate bindings | `netsh http show sslcert` |
| `get_iis_auth_config` | Authentication settings per site | `web.config` parsing |

#### Implementation
- [ ] 🪟 Read `%SystemRoot%\System32\inetsrv\config\applicationHost.config`
- [ ] 🪟 Parse site bindings, protocols, physical paths
- [ ] 🪟 Read app pool identity, recycling settings, process model
- [ ] 🪟 Check handler mappings for security (CGI, ISAPI)
- [ ] 🪟 Enumerate installed modules (authentication, compression, etc.)
- [ ] 🪟 Parse `web.config` files with redaction of connection strings
- [ ] 🪟 Check SSL certificate expiry and binding configuration
- [ ] 🪟 Support IIS 7.5, 8.0, 8.5, 10.0

#### IIS Security Checks
- [ ] 🪟 Identify sites running as LocalSystem
- [ ] 🪟 Check for directory browsing enabled
- [ ] 🪟 Verify SSL/TLS configuration (weak ciphers)
- [ ] 🪟 Check authentication modes (Anonymous, Windows, Basic)
- [ ] 🪟 Identify handler mappings allowing script execution

#### Unit Tests
- [ ] 🧪 Test applicationHost.config parsing
- [ ] 🧪 Test web.config parsing with redaction
- [ ] 🧪 Test binding parsing (HTTP, HTTPS, net.tcp)
- [ ] 🧪 Test app pool identity parsing

#### Integration Tests
- [ ] 🔬 🪟 Verify against IIS Manager UI
- [ ] 🔬 🪟 Verify against `appcmd list site`
- [ ] 🔬 🪟 Verify SSL bindings against `netsh http show sslcert`

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

| Category | Queries | Status |
|----------|:-------:|:------:|
| **Phase 1 (MVP)** | 7 | ✅ Complete |
| **Phase 1.5 (Logs)** | 6 | ✅ Complete |
| **Phase 1.6 (Hooks)** | 31 | ✅ Complete |
| **Phase 1.7 (SBOM)** | 31 | ✅ Complete |
| **Phase 1.8 (App Config)** | 2 | ✅ Complete |
| **Phase 1.9 (Triage)** | 25 | 🚧 5/25 |
| **Phase 1.10 (Windows)** | 15 | 📋 Planned |
| Phase 2 (Enhanced) | 6 | 📋 Planned |
| Phase 3 (Storage) | 5 | 📋 Planned |
| Phase 4 (Network) | 5 | 📋 Planned |
| Phase 5 (Analytics) | 4 | 📋 Planned |
| Phase 6 (Automation) | 5 | 📋 Planned |
| Phase 7 (Security) | 5 | 📋 Planned |
| Phase 8 (Integration) | 4 | 📋 Planned |
| Phase 9 (LLM) | 3 | 📋 Planned |

**Current Status: 84/149 queries implemented (56%)**

- Phase 1 (MVP): ✅ Complete (7/7 queries)
- Phase 1.5 (Logs): ✅ Complete (6/6 queries)
- Phase 1.6 (Hooks): ✅ Complete (31/31 queries)
- Phase 1.7 (SBOM): ✅ Complete (31/31 queries)
- Phase 1.8 (App Config): ✅ Complete (2/2 queries)
- Phase 1.9 (Triage): 🚧 In Progress (5/25 queries)
- Phase 1.10: 📋 Planned (15 queries) - Windows Enterprise
- Phase 2-9: 📋 Planned (37 queries)
