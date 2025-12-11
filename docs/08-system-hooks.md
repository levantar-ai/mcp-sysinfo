# System Hooks - Deep System Introspection

Zero-dependency system introspection using only built-in OS tools. These hooks provide deep visibility into system state without installing any third-party software.

---

## Design Principles

### Lightweight First

**Critical:** These hooks must NEVER cause resource exhaustion or impact customer workloads.

| Principle | Implementation |
|-----------|----------------|
| **Lazy Loading** | Only read data when explicitly requested |
| **Streaming** | Stream large outputs, don't buffer in memory |
| **Caching** | Cache static data (hardware info) vs dynamic (processes) |
| **Rate Limiting** | Built-in cooldowns for expensive operations |
| **Timeouts** | Hard timeouts on all operations (default 5s) |
| **Sampling** | Sample large datasets rather than full reads |
| **No Polling** | Never poll continuously; always on-demand |

### Resource Budgets

| Operation Type | Max CPU | Max Memory | Max Time |
|----------------|---------|------------|----------|
| Simple file read | <1% | <1MB | <100ms |
| Command execution | <5% | <10MB | <5s |
| Directory scan | <5% | <50MB | <10s |
| Full system scan | <10% | <100MB | <30s |

### Implementation Pattern

```go
// Every hook follows this pattern
type HookOptions struct {
    Timeout     time.Duration  // Hard timeout (default 5s)
    MaxResults  int            // Limit result count
    MaxBytes    int64          // Limit memory usage
    Sample      float64        // Sample rate 0.0-1.0
    NoCache     bool           // Force fresh data
}
```

---

## Scheduled Tasks & Startup

### Cron Jobs (Linux)

What's scheduled to run automatically.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/var/spool/cron/crontabs/*` | Built-in | None | 🟢 Minimal - file read |
| **Linux** | Read `/etc/cron.d/`, `/etc/cron.daily/`, etc. | Built-in | None | 🟢 Minimal - dir scan |
| **Linux** | `systemctl list-timers` for systemd timers | Built-in | None | 🟢 Minimal |

**Lightweight approach:** Read files directly, don't spawn processes.

---

### Launchd Jobs (macOS)

macOS scheduled tasks and daemons.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **macOS** | Read `/Library/LaunchDaemons/*.plist` | Built-in | None | 🟢 Minimal - file read |
| **macOS** | Read `/Library/LaunchAgents/*.plist` | Built-in | None | 🟢 Minimal |
| **macOS** | Read `~/Library/LaunchAgents/*.plist` | Built-in | None | 🟢 Minimal |
| **macOS** | `launchctl list` (if needed) | Built-in | None | 🟡 Low - process spawn |

**Lightweight approach:** Parse plist files directly with Go's plist library.

---

### Task Scheduler (Windows)

Windows scheduled tasks.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Windows** | Read `C:\Windows\System32\Tasks\*` XML files | Built-in | None | 🟢 Minimal - file read |
| **Windows** | `schtasks /query /fo CSV` | Built-in | None | 🟡 Low - process spawn |
| **Windows** | COM `Schedule.Service` API | Built-in | None | 🟢 Minimal - API call |

**Lightweight approach:** Read XML task files directly.

---

### Startup Items

What runs at boot/login - critical for security auditing.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/etc/systemd/system/*.service` | Built-in | None | 🟢 Minimal |
| **Linux** | Read `/etc/init.d/*` | Built-in | None | 🟢 Minimal |
| **Linux** | `~/.config/autostart/*.desktop` | Built-in | None | 🟢 Minimal |
| **macOS** | Read LaunchDaemons/LaunchAgents (see above) | Built-in | None | 🟢 Minimal |
| **macOS** | Login Items via `osascript` | Built-in | None | 🟡 Low |
| **Windows** | Read `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Built-in | None | 🟢 Minimal |
| **Windows** | Read `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Built-in | None | 🟢 Minimal |
| **Windows** | Scan Startup folder | Built-in | None | 🟢 Minimal |

---

## Kernel & Drivers

### Loaded Kernel Modules

What drivers/modules are loaded - critical for stability issues.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/modules` | Built-in | None | 🟢 Minimal - single file |
| **Linux** | Read `/sys/module/*/` for parameters | Built-in | None | 🟢 Minimal |
| **macOS** | `kextstat` or `kmutil showloaded` | Built-in | None | 🟡 Low - process spawn |
| **Windows** | Read via `EnumDeviceDrivers()` API | Built-in | None | 🟢 Minimal - API call |
| **Windows** | `driverquery /fo CSV` | Built-in | None | 🟡 Low |

---

### Kernel Parameters

Sysctl tuning - critical for performance and security.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/sys/` hierarchy | Built-in | None | 🟢 Minimal - file reads |
| **Linux** | Focus on key paths: `vm/`, `net/`, `kernel/` | Built-in | None | 🟢 Minimal |
| **macOS** | `sysctl -a` or read specific keys | Built-in | None | 🟡 Low |
| **Windows** | Registry `HKLM\SYSTEM\CurrentControlSet\` | Built-in | None | 🟢 Minimal |

**Lightweight approach:** Read specific known-important keys, not full dump.

---

## Network Configuration

### Listening Ports

What's bound to which ports - critical for security.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/net/tcp`, `/proc/net/tcp6` | Built-in | None | 🟢 Minimal - file read |
| **Linux** | Read `/proc/net/udp`, `/proc/net/udp6` | Built-in | None | 🟢 Minimal |
| **Linux** | Correlate with `/proc/[pid]/fd/` for process | Built-in | None | 🟡 Low - dir scan |
| **macOS** | `lsof -i -P -n` (limited) | Built-in | None | 🟠 Medium - can be slow |
| **macOS** | `netstat -anv` | Built-in | None | 🟡 Low |
| **Windows** | `GetExtendedTcpTable()` API | Built-in | None | 🟢 Minimal - API call |
| **Windows** | `netstat -ano` | Built-in | None | 🟡 Low |

**Lightweight approach:** On Linux, read /proc files directly. Avoid `lsof` on large systems.

---

### DNS Configuration

Resolver settings - critical for "can't resolve" issues.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/etc/resolv.conf` | Built-in | None | 🟢 Minimal - single file |
| **Linux** | Read `/etc/systemd/resolved.conf` | Built-in | None | 🟢 Minimal |
| **Linux** | `resolvectl status` (if systemd-resolved) | Built-in | None | 🟡 Low |
| **macOS** | `scutil --dns` | Built-in | None | 🟡 Low |
| **macOS** | Read `/etc/resolv.conf` | Built-in | None | 🟢 Minimal |
| **Windows** | Registry or `Get-DnsClientServerAddress` | Built-in | None | 🟢 Minimal |

---

### Hosts File

Local DNS overrides - often forgotten cause of issues.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/etc/hosts` | Built-in | None | 🟢 Minimal - single file |
| **macOS** | Read `/etc/hosts` | Built-in | None | 🟢 Minimal |
| **Windows** | Read `C:\Windows\System32\drivers\etc\hosts` | Built-in | None | 🟢 Minimal |

---

### Routing Table

Network paths - critical for connectivity issues.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/net/route` | Built-in | None | 🟢 Minimal - single file |
| **Linux** | Read `/proc/net/ipv6_route` | Built-in | None | 🟢 Minimal |
| **macOS** | `netstat -rn` | Built-in | None | 🟡 Low |
| **Windows** | `GetIpForwardTable()` API | Built-in | None | 🟢 Minimal - API call |

---

### ARP Cache

MAC-IP mappings - network discovery, spoofing detection.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/net/arp` | Built-in | None | 🟢 Minimal - single file |
| **macOS** | `arp -a` | Built-in | None | 🟡 Low |
| **Windows** | `GetIpNetTable()` API | Built-in | None | 🟢 Minimal - API call |

---

### Firewall Rules

What's being blocked - critical for "can't connect" issues.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux (iptables)** | `iptables-save` or `/proc/net/ip_tables_*` | Built-in | Root | 🟡 Low |
| **Linux (nftables)** | `nft list ruleset` | Built-in | Root | 🟡 Low |
| **Linux (ufw)** | Read `/etc/ufw/*.rules` | Built-in | None | 🟢 Minimal |
| **macOS (pf)** | Read `/etc/pf.conf` | Built-in | None | 🟢 Minimal |
| **macOS (pf)** | `pfctl -sr` | Built-in | Root | 🟡 Low |
| **Windows** | `Get-NetFirewallRule` via PowerShell | Built-in | None | 🟡 Low |
| **Windows** | Firewall API | Built-in | None | 🟢 Minimal |

---

## File System

### Open Files/Handles

What's holding files open - "Why can't I delete this?"

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/[pid]/fd/` symlinks | Built-in | None | 🟠 Medium - many dirs |
| **Linux** | **Targeted:** Only scan specific file's holders | Built-in | None | 🟢 Minimal |
| **macOS** | `lsof [file]` - targeted query | Built-in | None | 🟡 Low |
| **Windows** | `NtQuerySystemInformation` API | Built-in | None | 🟠 Medium |

**Lightweight approach:** Never do full `lsof`. Always target specific file or PID.

---

### File Descriptor Limits

FD exhaustion - "Too many open files".

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/sys/fs/file-nr` (system-wide) | Built-in | None | 🟢 Minimal - single file |
| **Linux** | Read `/proc/[pid]/limits` (per-process) | Built-in | None | 🟢 Minimal |
| **macOS** | `launchctl limit maxfiles` | Built-in | None | 🟡 Low |
| **Windows** | Handle count via process API | Built-in | None | 🟢 Minimal |

---

### Inode Usage

"No space left" but disk isn't full.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | `statfs()` syscall for each mount | Built-in | None | 🟢 Minimal - syscall |
| **macOS** | `statfs()` syscall | Built-in | None | 🟢 Minimal |
| **Windows** | N/A (NTFS doesn't have inodes) | N/A | N/A | N/A |

---

### Mount Options

How filesystems are mounted - security audit.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/mounts` | Built-in | None | 🟢 Minimal - single file |
| **Linux** | Read `/proc/self/mountinfo` for more detail | Built-in | None | 🟢 Minimal |
| **macOS** | `mount` command or `getmntinfo()` | Built-in | None | 🟢 Minimal |
| **Windows** | `GetVolumeInformation()` API | Built-in | None | 🟢 Minimal |

---

## Security Configuration

### User Accounts

Local users and groups - unauthorized account detection.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/etc/passwd`, `/etc/shadow` (perms), `/etc/group` | Built-in | None | 🟢 Minimal - file read |
| **Linux** | Read `/etc/login.defs` for policies | Built-in | None | 🟢 Minimal |
| **macOS** | `dscl . list /Users` | Built-in | None | 🟡 Low |
| **macOS** | Read `/etc/passwd` (limited info) | Built-in | None | 🟢 Minimal |
| **Windows** | `NetUserEnum()` API | Built-in | None | 🟢 Minimal |
| **Windows** | `Get-LocalUser` PowerShell | Built-in | None | 🟡 Low |

---

### Sudo Configuration

Privilege escalation rules - security audit.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/etc/sudoers` (if readable) | Built-in | None | 🟢 Minimal |
| **Linux** | Read `/etc/sudoers.d/*` | Built-in | None | 🟢 Minimal |
| **macOS** | Same as Linux | Built-in | None | 🟢 Minimal |
| **Windows** | Check Local Administrators group | Built-in | None | 🟢 Minimal |

---

### SSH Configuration

SSH server and client config - security audit.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/etc/ssh/sshd_config` | Built-in | None | 🟢 Minimal |
| **Linux** | Read `~/.ssh/config`, `~/.ssh/authorized_keys` | Built-in | None | 🟢 Minimal |
| **macOS** | Same paths as Linux | Built-in | None | 🟢 Minimal |
| **Windows** | Read `C:\ProgramData\ssh\sshd_config` | Built-in | None | 🟢 Minimal |

---

### SSL/TLS Certificates

System trust store - cert expiry, trust issues.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Scan `/etc/ssl/certs/` | Built-in | None | 🟡 Low - dir scan |
| **Linux** | Read `/etc/ca-certificates.conf` | Built-in | None | 🟢 Minimal |
| **macOS** | `security find-certificate -a` | Built-in | None | 🟡 Low |
| **Windows** | Cert store API | Built-in | None | 🟡 Low |

**Lightweight approach:** Only check expiry dates, don't parse full certs unless asked.

---

### SELinux/AppArmor Status

Mandatory Access Control status.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux (SELinux)** | Read `/sys/fs/selinux/enforce` | Built-in | None | 🟢 Minimal - single file |
| **Linux (AppArmor)** | Read `/sys/kernel/security/apparmor/profiles` | Built-in | None | 🟢 Minimal |
| **macOS** | N/A (uses SIP) | N/A | N/A | N/A |
| **Windows** | N/A | N/A | N/A | N/A |

---

## Hardware Information

### Hardware Inventory

Detailed hardware info - troubleshooting.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/sys/class/dmi/id/*` | Built-in | None | 🟢 Minimal - file reads |
| **Linux** | Read `/sys/devices/` hierarchy | Built-in | None | 🟡 Low |
| **Linux** | Read `/proc/cpuinfo`, `/proc/meminfo` | Built-in | None | 🟢 Minimal |
| **macOS** | `system_profiler -json SPHardwareDataType` | Built-in | None | 🟡 Low |
| **Windows** | WMI `Win32_ComputerSystem`, etc. | Built-in | None | 🟡 Low |

**Lightweight approach:** Cache hardware info - it rarely changes.

---

### USB Devices

Connected USB devices.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/sys/bus/usb/devices/*/` | Built-in | None | 🟢 Minimal |
| **macOS** | `system_profiler -json SPUSBDataType` | Built-in | None | 🟡 Low |
| **Windows** | `SetupDiGetClassDevs()` API | Built-in | None | 🟢 Minimal |

---

### PCI Devices

Hardware components and drivers.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/sys/bus/pci/devices/*/` | Built-in | None | 🟢 Minimal |
| **Linux** | Read `/usr/share/hwdata/pci.ids` for names | Built-in | None | 🟢 Minimal |
| **macOS** | `system_profiler -json SPPCIDataType` | Built-in | None | 🟡 Low |
| **Windows** | `SetupDiGetClassDevs()` API | Built-in | None | 🟢 Minimal |

---

### Block Device Topology

Disk layout - LVM, RAID, partitions.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/sys/block/*/` hierarchy | Built-in | None | 🟢 Minimal |
| **Linux** | Read `/proc/partitions` | Built-in | None | 🟢 Minimal |
| **macOS** | `diskutil list -plist` | Built-in | None | 🟡 Low |
| **Windows** | `GetLogicalDriveStrings()` + `DeviceIoControl()` | Built-in | None | 🟢 Minimal |

---

## Process & Resource Information

### Environment Variables

System and process environment.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/[pid]/environ` | Built-in | None | 🟢 Minimal |
| **Linux** | Read `/etc/environment` | Built-in | None | 🟢 Minimal |
| **macOS** | `environ` global or `launchctl getenv` | Built-in | None | 🟢 Minimal |
| **Windows** | `GetEnvironmentStrings()` API | Built-in | None | 🟢 Minimal |

---

### IPC Resources

Semaphores, shared memory, message queues.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/sysvipc/sem`, `/proc/sysvipc/shm` | Built-in | None | 🟢 Minimal |
| **macOS** | `ipcs` command | Built-in | None | 🟡 Low |
| **Windows** | N/A (different model) | N/A | N/A | N/A |

---

### Namespaces (Containers)

Container isolation information.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/[pid]/ns/*` symlinks | Built-in | None | 🟢 Minimal |
| **Linux** | Read `/proc/[pid]/cgroup` | Built-in | None | 🟢 Minimal |
| **macOS** | N/A | N/A | N/A | N/A |
| **Windows** | Job object APIs | Built-in | None | 🟡 Low |

---

### Cgroup Limits

Resource limits and usage.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux (v2)** | Read `/sys/fs/cgroup/` hierarchy | Built-in | None | 🟢 Minimal |
| **Linux (v1)** | Read `/sys/fs/cgroup/{cpu,memory}/` | Built-in | None | 🟢 Minimal |
| **macOS** | N/A | N/A | N/A | N/A |
| **Windows** | Job object APIs | Built-in | None | 🟡 Low |

---

### Process Capabilities

Linux capabilities for privilege debugging.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/proc/[pid]/status` CapEff, CapPrm, etc. | Built-in | None | 🟢 Minimal |
| **macOS** | N/A (uses entitlements) | N/A | N/A | N/A |
| **Windows** | Token privileges via API | Built-in | None | 🟢 Minimal |

---

## System State

### Virtualization Detection

Detect if running in VM and which hypervisor.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/sys/class/dmi/id/product_name` | Built-in | None | 🟢 Minimal |
| **Linux** | Check `/proc/cpuinfo` for hypervisor flag | Built-in | None | 🟢 Minimal |
| **Linux** | Read `/sys/hypervisor/type` | Built-in | None | 🟢 Minimal |
| **macOS** | `sysctl kern.hv_support` | Built-in | None | 🟢 Minimal |
| **Windows** | WMI `Win32_ComputerSystem.Model` | Built-in | None | 🟢 Minimal |

---

### Locale & Timezone

System locale settings - internationalization issues.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/etc/timezone`, `/etc/localtime` | Built-in | None | 🟢 Minimal |
| **Linux** | Read `$LANG`, `$LC_*` environment | Built-in | None | 🟢 Minimal |
| **macOS** | `defaults read .GlobalPreferences` | Built-in | None | 🟡 Low |
| **Windows** | `GetUserDefaultLocaleName()` API | Built-in | None | 🟢 Minimal |

---

### NTP Status

Time synchronization - critical for distributed systems.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/var/lib/ntp/ntp.drift` | Built-in | None | 🟢 Minimal |
| **Linux** | `timedatectl show` | Built-in | None | 🟡 Low |
| **macOS** | `sntp -d time.apple.com` (active check) | Built-in | None | 🟠 Medium - network |
| **Windows** | `w32tm /query /status` | Built-in | None | 🟡 Low |

**Lightweight approach:** Read local state, don't actively query NTP servers.

---

### Core Dumps

Crash dumps for debugging.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Scan `/var/crash/`, `/var/lib/systemd/coredump/` | Built-in | None | 🟡 Low - dir scan |
| **Linux** | `coredumpctl list --json` | Built-in | None | 🟡 Low |
| **macOS** | Scan `~/Library/Logs/DiagnosticReports/` | Built-in | None | 🟡 Low |
| **Windows** | Scan `%LocalAppData%\CrashDumps\` | Built-in | None | 🟡 Low |

**Lightweight approach:** List metadata only, don't read dump contents.

---

### Power State

Power management and battery.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/sys/class/power_supply/*/` | Built-in | None | 🟢 Minimal |
| **Linux** | Read `/sys/power/state` | Built-in | None | 🟢 Minimal |
| **macOS** | `pmset -g batt` | Built-in | None | 🟡 Low |
| **Windows** | `GetSystemPowerStatus()` API | Built-in | None | 🟢 Minimal |

---

### NUMA Topology

Memory topology for performance tuning.

| Platform | Implementation | Availability | Install | Resource Impact |
|----------|----------------|--------------|---------|-----------------|
| **Linux** | Read `/sys/devices/system/node/*/` | Built-in | None | 🟢 Minimal |
| **macOS** | N/A (unified memory) | N/A | N/A | N/A |
| **Windows** | `GetNumaHighestNodeNumber()` API | Built-in | None | 🟢 Minimal |

---

## Resource Impact Legend

| Symbol | Impact | Description |
|--------|--------|-------------|
| 🟢 | Minimal | <1% CPU, <1MB RAM, <100ms |
| 🟡 | Low | <5% CPU, <10MB RAM, <1s |
| 🟠 | Medium | <10% CPU, <50MB RAM, <5s |
| 🔴 | High | >10% CPU or >50MB RAM or >5s - **AVOID** |

---

## Query Count Summary

| Category | Queries | Avg Impact |
|----------|---------|------------|
| Scheduled Tasks & Startup | 4 | 🟢 Minimal |
| Kernel & Drivers | 2 | 🟢 Minimal |
| Network Configuration | 6 | 🟢-🟡 |
| File System | 4 | 🟢-🟠 |
| Security Configuration | 6 | 🟢 Minimal |
| Hardware Information | 4 | 🟢-🟡 |
| Process & Resources | 5 | 🟢 Minimal |
| System State | 6 | 🟢-🟡 |
| **Total** | **37** | 🟢 Mostly Minimal |
