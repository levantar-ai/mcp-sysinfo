# Tier 1: Core Security Diagnostics

System metrics, storage analysis, network intelligence, and **log access for security diagnostics**.

---

## System Log Access (Critical for Diagnostics)

Without log access, an AI can only see symptoms ("CPU is high") but not causes. Log access enables true root cause analysis for security incident triage.

### Journald Logs (Linux)
Systemd journal - the primary log source on modern Linux systems.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `journalctl` with JSON output (`-o json`) | Built-in | systemd-based distros |
| **Linux** | `systemd` Python bindings | pip | `pip install systemd-python` |
| **Linux** | Direct reading `/var/log/journal/` | Built-in | None |
| **macOS** | N/A | N/A | Uses unified logging instead |
| **Windows** | N/A | N/A | Uses Event Viewer instead |

**Key queries:**
- `journalctl -u nginx --since "1 hour ago"` - Service logs
- `journalctl -k` - Kernel messages (OOM, hardware errors)
- `journalctl -p err..emerg` - Errors and above
- `journalctl _COMM=sshd` - By executable name
- `journalctl --disk-usage` - Log storage stats

---

### Syslog (Cross-platform)
Traditional Unix logging, still used by many applications.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `/var/log/syslog` or `/var/log/messages` | Built-in | rsyslog/syslog-ng |
| **Linux** | Parse with Python `re` or `syslog-rfc5424-parser` | pip | `pip install syslog-rfc5424-parser` |
| **macOS** | `/var/log/system.log` (legacy) | Built-in | Deprecated, use `log` command |
| **macOS** | `log show --predicate 'process == "kernel"'` | Built-in | None |
| **Windows** | N/A (use Event Log) | N/A | N/A |

---

### Application Logs
Application-specific log files in standard locations.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `/var/log/{app}/` directory scanning | Built-in | None |
| **Linux** | Common paths: `/var/log/nginx/`, `/var/log/apache2/`, `/var/log/mysql/` | Built-in | Per-app |
| **Linux** | Docker: `docker logs {container}` or `/var/lib/docker/containers/*/` | Built-in | Docker |
| **macOS** | `~/Library/Logs/`, `/Library/Logs/` | Built-in | None |
| **macOS** | `log show --predicate 'subsystem == "com.app.name"'` | Built-in | None |
| **Windows** | `%AppData%\Local\{App}\Logs\` | Built-in | None |
| **Windows** | `%ProgramData%\{App}\Logs\` | Built-in | None |
| **Windows** | Event Log application channel | Built-in | None |

---

### Kernel/Boot Logs
Critical for hardware issues, driver problems, and boot failures.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `dmesg` ring buffer | Built-in | None |
| **Linux** | `/var/log/kern.log` | Built-in | rsyslog configured |
| **Linux** | `journalctl -k -b` (current boot kernel msgs) | Built-in | systemd |
| **Linux** | `/var/log/boot.log` | Built-in | Some distros |
| **macOS** | `dmesg` | Built-in | None |
| **macOS** | `log show --predicate 'sender == "kernel"'` | Built-in | None |
| **macOS** | `/var/log/DiagnosticMessages/` | Built-in | None |
| **Windows** | Event Viewer System channel | Built-in | None |
| **Windows** | `Get-WinEvent -LogName System` PowerShell | Built-in | None |
| **Windows** | Boot log: `bcdedit /set bootlog yes` then `%SystemRoot%\ntbtlog.txt` | Built-in | Needs enable |

---

### Authentication/Security Logs
Login attempts, sudo usage, SSH access - critical for security diagnostics.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `/var/log/auth.log` (Debian) or `/var/log/secure` (RHEL) | Built-in | None |
| **Linux** | `journalctl _SYSTEMD_UNIT=sshd.service` | Built-in | systemd |
| **Linux** | `lastlog`, `last`, `lastb` commands | Built-in | None |
| **Linux** | `/var/log/audit/audit.log` (if auditd) | Built-in | `apt install auditd` |
| **macOS** | `/var/log/secure.log` | Built-in | None |
| **macOS** | `log show --predicate 'category == "auth"'` | Built-in | None |
| **macOS** | `/var/log/opendirectoryd.log` | Built-in | None |
| **Windows** | Security Event Log (Event ID 4624=login, 4625=failed) | Built-in | None |
| **Windows** | `Get-WinEvent -LogName Security -MaxEvents 100` | Built-in | Admin required |
| **Windows** | Audit policies via `auditpol /get /category:*` | Built-in | None |

---

### Windows Event Log
The primary log source on Windows systems.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Windows** | `Get-WinEvent` PowerShell | Built-in | None |
| **Windows** | `wevtutil` command-line | Built-in | None |
| **Windows** | `pywin32` Python bindings | pip | `pip install pywin32` |
| **Windows** | `winevt` package | pip | `pip install winevt` |
| **Linux/macOS** | N/A | N/A | Windows only |

**Key event logs:**
- `System` - OS, drivers, hardware
- `Application` - Application errors, warnings
- `Security` - Logins, audit events
- `Setup` - Windows updates, installations
- Custom app logs under `Applications and Services Logs`

---

### Log Analysis Helpers
Tools to make log analysis more effective.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `tail -f` / `Get-Content -Wait` for live tailing | Built-in | None |
| **All** | Regex parsing for structured extraction | Python stdlib | None |
| **Linux** | `journalctl --since "2 hours ago" --until "1 hour ago"` | Built-in | None |
| **Linux** | `grep -E 'error|fail|critical' /var/log/*` | Built-in | None |
| **Linux** | `logwatch` for summaries | apt | `apt install logwatch` |
| **All** | Log rotation status (`logrotate -d /etc/logrotate.conf`) | Built-in | None |

---

### Why Log Access Matters for AI Diagnostics

| Scenario | Without Logs | With Logs |
|----------|--------------|-----------|
| High CPU | "CPU at 100%" | "CPU at 100% - journald shows OOM killer invoked at 14:32, killing java process" |
| Service down | "nginx not responding" | "nginx down - error.log shows 'Too many open files', systemd restart loop 5 times" |
| Disk full | "/ at 99%" | "/ at 99% - /var/log/app.log is 45GB, growing 100MB/min due to debug logging enabled" |
| Network issues | "Connection refused" | "Connection refused - auth.log shows IP banned by fail2ban after 5 failed SSH attempts" |
| Boot failure | "System won't start" | "Boot fails - dmesg shows 'ata1: COMRESET failed', disk not detected" |
| Memory leak | "RAM usage climbing" | "RAM climbing - journald shows repeated 'malloc failed' from app, core dump at /var/crash/" |

---

## Real-Time Metrics

### Live Streaming Metrics
Real-time WebSocket/SSE streams for dashboards and continuous diagnostics.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `psutil` + `asyncio` + `websockets`/`aiohttp` SSE | pip | `pip install psutil websockets aiohttp` |
| **macOS** | `psutil` + `asyncio` + `websockets`/`aiohttp` SSE | pip | `pip install psutil websockets aiohttp` |
| **Windows** | `psutil` + `asyncio` + `websockets`/`aiohttp` SSE | pip | `pip install psutil websockets aiohttp` |

---

### Per-Process Resource Tracking
CPU, memory, I/O usage tracked per PID over time.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `psutil.Process(pid)` - reads `/proc/[pid]/stat`, `/proc/[pid]/io` | pip | `pip install psutil` |
| **macOS** | `psutil.Process(pid)` - uses `proc_pidinfo()`. I/O counters limited | pip | `pip install psutil` |
| **Windows** | `psutil.Process(pid)` - uses Win32 APIs (`GetProcessTimes`, etc.) | pip | `pip install psutil` |

---

### GPU Diagnostics
NVIDIA, AMD, and Intel GPU statistics.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (NVIDIA)** | `pynvml` library wrapping NVML | pip + driver | `pip install pynvml` (requires NVIDIA driver) |
| **Linux (AMD)** | `pyamdgpuinfo` or `/sys/class/drm/card*/device/gpu_busy_percent` | pip or Built-in | `pip install pyamdgpuinfo` or read sysfs |
| **Linux (Intel)** | `intel_gpu_top` parsing or `i915` sysfs | apt | `apt install intel-gpu-tools` |
| **macOS (Apple Silicon)** | `powermetrics` (requires root), `ioreg` parsing | Built-in | Root required |
| **macOS (Intel)** | `ioreg` parsing, Metal performance HUD | Built-in | Limited metrics |
| **macOS (NVIDIA/AMD)** | N/A | N/A | No modern support |
| **Windows (NVIDIA)** | `pynvml` | pip + driver | `pip install pynvml` |
| **Windows (AMD)** | `pyamdgpuinfo` or WMI `Win32_VideoController` | pip or Built-in | `pip install pyamdgpuinfo` |
| **Windows (Intel)** | WMI or DirectX diagnostics | Built-in | WMI queries |
| **Windows (Universal)** | `GPUtil` or Performance Counters | pip or Built-in | `pip install GPUtil` |

---

### Container Metrics
Docker/Podman container resource usage.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (Docker)** | `docker` Python SDK, `docker.from_env().containers.stats()` | pip + Docker | `pip install docker` + Docker installed |
| **Linux (Podman)** | REST API at `unix:///run/podman/podman.sock` | Podman | Podman installed |
| **Linux (cgroups)** | Direct reading `/sys/fs/cgroup/` | Built-in | Kernel cgroups enabled |
| **macOS (Docker)** | `docker` Python SDK (Docker Desktop runs Linux VM) | pip + Docker Desktop | `pip install docker` + Docker Desktop |
| **macOS (Podman)** | `podman machine` REST API | brew + Podman | `brew install podman` |
| **macOS (Native)** | N/A | N/A | No native containers |
| **Windows (Docker)** | `docker` Python SDK (Docker Desktop) | pip + Docker Desktop | `pip install docker` |
| **Windows (Native)** | HCS API via `winhc` or `Get-Container` PowerShell | Built-in | Windows Server containers |

---

### VM Guest Metrics
Detect if running in VM, expose hypervisor-specific metrics.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `systemd-detect-virt`, `/sys/class/dmi/id/product_name`, `dmidecode` | Built-in | `apt install dmidecode` for detailed info |
| **Linux** | `/proc/cpuinfo` hypervisor flag, `lscpu` | Built-in | None |
| **macOS** | `sysctl kern.hv_support`, `system_profiler`, `ioreg` | Built-in | None |
| **Windows** | WMI `Win32_ComputerSystem.Model`, registry check, `systeminfo` | Built-in | None |

---

## Storage Deep Dive

### SMART Disk Health
Predict drive failures via SMART attributes.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `pySMART` (wraps `smartctl`) | pip + apt | `pip install pySMART` + `apt install smartmontools` |
| **Linux (NVMe)** | `nvme smart-log /dev/nvme0` | apt | `apt install nvme-cli` |
| **macOS** | `pySMART`, `smartctl` via Homebrew | pip + brew | `pip install pySMART` + `brew install smartmontools` |
| **macOS** | `diskutil info`, `system_profiler SPNVMeDataType` | Built-in | Basic health only |
| **Windows** | `pySMART` (needs smartmontools) | pip + install | `pip install pySMART` + smartmontools binary |
| **Windows** | WMI `MSStorageDriver_ATAPISmartData` | Built-in | Limited attributes |
| **Windows** | `wmic diskdrive get status` | Built-in | Basic only (OK/Pred Fail) |

---

### I/O Latency Tracking
Read/write latency percentiles (p50, p95, p99).

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `blktrace` + `blkparse` | apt | `apt install blktrace` |
| **Linux** | `bpftrace` scripts | apt | `apt install bpftrace` (kernel 4.9+) |
| **Linux** | `/sys/block/*/stat` | Built-in | Basic stats only |
| **Linux** | `iostat -x` parsing | apt | `apt install sysstat` |
| **Linux (eBPF)** | `biolatency` from BCC tools | apt | `apt install bpfcc-tools` |
| **macOS** | `fs_usage` command | Built-in | Root required |
| **macOS** | `dtrace` scripts | Built-in | SIP may restrict |
| **macOS** | `iostat` | Built-in | Throughput only, no latency |
| **Windows** | Performance Counters `Logical Disk/*` | Built-in | `diskperf -y` to enable |
| **Windows** | `typeperf "\LogicalDisk(*)\Avg. Disk sec/Read"` | Built-in | None |
| **Windows** | ETW tracing | Built-in | Complex setup |

---

### Filesystem Events
Watch for file changes in real-time.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `watchdog` library (uses `inotify`) | pip | `pip install watchdog` |
| **Linux** | `inotify_simple` | pip | `pip install inotify_simple` |
| **Linux** | `fanotify` (system-wide) | Kernel | Requires CAP_SYS_ADMIN |
| **macOS** | `watchdog` library (uses FSEvents) | pip | `pip install watchdog` |
| **macOS** | `fsevents` module | pip | `pip install fsevents` |
| **macOS** | `kqueue` | Python stdlib | Lower-level control |
| **Windows** | `watchdog` library (uses `ReadDirectoryChangesW`) | pip | `pip install watchdog` |
| **Windows** | `pywin32` direct Win32 API | pip | `pip install pywin32` |

---

### Mount Point Detection
Auto-detect new mounts, NFS/SMB health.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `psutil.disk_partitions()` | pip | `pip install psutil` |
| **Linux** | Watch `/proc/mounts` or `/proc/self/mountinfo` | Built-in | None |
| **Linux (NFS)** | `nfsstat`, `/proc/net/rpc/nfs` | Built-in | NFS packages if using NFS |
| **Linux (SMB)** | `smbstatus` | apt | `apt install samba-common-bin` |
| **macOS** | `psutil.disk_partitions()`, `diskutil list`, `mount` | pip + Built-in | `pip install psutil` |
| **macOS (NFS)** | `nfsstat` | Built-in | None |
| **macOS (SMB)** | `smbutil statshares` | Built-in | None |
| **Windows** | `psutil.disk_partitions()` | pip | `pip install psutil` |
| **Windows** | WMI `Win32_LogicalDisk`, `Win32_MountPoint` | Built-in | None |
| **Windows (SMB)** | `Get-SmbConnection` PowerShell, `net use` | Built-in | None |

---

### ZFS/LVM/RAID Status
Advanced storage pool and array metrics.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (ZFS)** | `zpool status`, `zfs list` parsing | apt | `apt install zfsutils-linux` |
| **Linux (LVM)** | `lvs`, `vgs`, `pvs` with `--reportformat json` | apt | `apt install lvm2` (usually pre-installed) |
| **Linux (MD RAID)** | `/proc/mdstat`, `mdadm --detail` | Built-in | `apt install mdadm` |
| **macOS (ZFS)** | OpenZFS - same `zpool`/`zfs` commands | brew | `brew install openzfs` |
| **macOS (RAID)** | `diskutil appleRAID list` | Built-in | Software RAID only |
| **macOS (LVM)** | N/A | N/A | Not supported |
| **Windows (ZFS)** | N/A | N/A | Not supported |
| **Windows (Storage Spaces)** | `Get-StoragePool`, `Get-VirtualDisk` PowerShell | Built-in | None |
| **Windows (HW RAID)** | Vendor CLI tools | Vendor-specific | Varies |

---

## Network Intelligence

### Per-Connection Tracking
Bandwidth usage by process/connection.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `nethogs` parsing | apt | `apt install nethogs` |
| **Linux** | `ss -p` + `/proc/net/tcp` | Built-in | None |
| **Linux (eBPF)** | `tcptop` from BCC tools | apt | `apt install bpfcc-tools` |
| **Linux** | `conntrack` for stateful tracking | apt | `apt install conntrack` |
| **macOS** | `nettop` command parsing | Built-in | None |
| **macOS** | `lsof -i` | Built-in | None |
| **macOS** | `dtrace` scripts | Built-in | SIP may restrict |
| **Windows** | `Get-NetTCPConnection` PowerShell | Built-in | None |
| **Windows** | `netstat -b` | Built-in | Requires admin |
| **Windows** | ETW network tracing | Built-in | Complex setup |

---

### DNS Resolution Stats
Query times, cache hit rates, resolver health.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (systemd)** | `resolvectl statistics` | Built-in | systemd-resolved enabled |
| **Linux** | Parse `/etc/resolv.conf`, `dig` with timing | apt | `apt install dnsutils` |
| **Linux** | `tcpdump port 53` for analysis | apt | `apt install tcpdump` |
| **macOS** | `dns-sd` command, `scutil --dns` | Built-in | None |
| **macOS** | `mDNSResponder` stats via `log stream` | Built-in | None |
| **macOS** | `dig` for timing | Built-in | Xcode CLI or brew |
| **Windows** | `Get-DnsClientCache` PowerShell | Built-in | None |
| **Windows** | Performance Counters `DNS Client` | Built-in | None |
| **Windows** | `Resolve-DnsName` with timing | Built-in | None |

---

### Firewall Rule Inspection
Analyze firewall configuration and rules.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (iptables)** | `iptables -L -n -v --line-numbers` | Built-in | Root required |
| **Linux (nftables)** | `nft list ruleset` | Built-in | Root required |
| **Linux (firewalld)** | `firewall-cmd --list-all` | apt | `apt install firewalld` |
| **Linux (ufw)** | `ufw status verbose` | apt | `apt install ufw` |
| **macOS (pf)** | `/etc/pf.conf` parsing, `pfctl -sr` | Built-in | Root required |
| **macOS (App FW)** | `socketfilterfw --listapps` | Built-in | Root required |
| **Windows** | `Get-NetFirewallRule` PowerShell | Built-in | None |
| **Windows** | `netsh advfirewall show allprofiles` | Built-in | None |
| **Windows** | WMI `MSFT_NetFirewallRule` | Built-in | None |

---

### WiFi Signal Metrics
Signal strength, noise, channel congestion.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `iwconfig` | apt | `apt install wireless-tools` |
| **Linux** | `/proc/net/wireless` | Built-in | WiFi hardware required |
| **Linux** | `iw dev wlan0 link`, `iw dev wlan0 scan` | apt | `apt install iw` (scan needs root) |
| **Linux (NM)** | `nmcli -f ALL dev wifi` | apt | NetworkManager installed |
| **macOS** | `airport -I` (private framework) | Built-in | None |
| **macOS** | CoreWLAN framework via `pyobjc` | pip | `pip install pyobjc-framework-CoreWLAN` |
| **Windows** | `netsh wlan show interfaces` | Built-in | None |
| **Windows** | `netsh wlan show networks mode=bssid` | Built-in | None |
| **Windows** | WMI `MSNdis_80211_*` | Built-in | Complex queries |
| **Windows** | `wlanapi` via ctypes | Python stdlib | Low-level |

---

### Network Latency Probes
Continuous ping/traceroute to key endpoints.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `ping3` library (pure Python) | pip | `pip install ping3` |
| **Linux** | `subprocess` with `ping` | Built-in | None |
| **Linux** | `mtr --json` | apt | `apt install mtr` |
| **Linux** | `scapy` for custom probes | pip | `pip install scapy` (root for raw sockets) |
| **macOS** | `ping3` library | pip | `pip install ping3` (root for ICMP) |
| **macOS** | `subprocess` with `ping` | Built-in | None |
| **macOS** | `mtr` | brew | `brew install mtr` |
| **Windows** | `ping3` library | pip | `pip install ping3` (admin for ICMP) |
| **Windows** | `subprocess` with `ping` | Built-in | None |
| **Windows** | `pythonping` library | pip | `pip install pythonping` |
| **Windows** | `Test-Connection` PowerShell | Built-in | None |
