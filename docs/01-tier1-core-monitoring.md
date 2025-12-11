# Tier 1: Enhanced Core Monitoring

Real-time metrics, storage deep dive, and network intelligence.

---

## Real-Time Metrics

### Live Streaming Metrics
Real-time WebSocket/SSE streams for dashboards and continuous monitoring.

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

### GPU Monitoring
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

### Mount Point Monitoring
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
