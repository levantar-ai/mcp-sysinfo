# Tier 3: Automation & Alerting

Smart alerts, automated actions, and process management.

---

## Smart Alerts

### Threshold Alerts
Alert when metrics cross defined thresholds.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Pure Python comparison against config thresholds | Python stdlib | None |
| **All** | Config via JSON/YAML | pip | `pip install pyyaml` (for YAML) |
| **All** | Hysteresis to prevent flapping | Python stdlib | None |

---

### Predictive Alerts
Warn before problems occur based on trends.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Combine capacity forecasting with alerting | pip | `pip install numpy` |
| **All** | Configurable prediction horizon | Python stdlib | None |

---

### Composite Alerts
Multiple conditions combined with AND/OR logic.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `pyparsing` for expression parsing | pip | `pip install pyparsing` |
| **All** | Custom DSL: `cpu > 90 AND memory > 80` | Python stdlib | None |

---

### Alert Fatigue Prevention
Deduplication, grouping, and escalation.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Debounce (min interval between repeats) | Python stdlib | None |
| **All** | Group related alerts | Python stdlib | None |
| **All** | Escalation after N occurrences | Python stdlib | None |

---

### Maintenance Windows
Suppress alerts during known maintenance.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Configurable time windows in config | Python stdlib | None |
| **All** | Check window before firing | Python stdlib | None |

---

## Automated Actions

### Auto-Remediation
Automatically fix common issues.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Kill runaway: `os.kill(pid, signal.SIGTERM)` | Python stdlib | None |
| **Linux** | Clear temp: `shutil.rmtree('/tmp/cache')` | Python stdlib | None |
| **Linux** | Restart services: `systemctl restart svc` | Built-in | Root required |
| **macOS** | Kill processes: `os.kill()` | Python stdlib | None |
| **macOS** | Clear caches: `shutil.rmtree()` | Python stdlib | None |
| **macOS** | Restart services: `launchctl kickstart -k` | Built-in | Root required |
| **Windows** | Kill processes: `psutil.Process(pid).terminate()` | pip | `pip install psutil` |
| **Windows** | Clear temp: `shutil.rmtree(os.environ['TEMP'])` | Python stdlib | None |
| **Windows** | Restart services: `sc restart svc` | Built-in | Admin required |

---

### Scheduled Tasks
Cron-like scheduled health checks.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `APScheduler` library (in-process) | pip | `pip install apscheduler` |
| **Linux** | System cron via `crontab` module | pip | `pip install python-crontab` |
| **macOS** | launchd plist creation | Built-in | None |
| **Windows** | Task Scheduler via `schtasks` | Built-in | None |
| **Windows** | `win32com.client` for Task Scheduler | pip | `pip install pywin32` |

---

### Webhook Triggers
POST to external services on events.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `httpx` async HTTP client | pip | `pip install httpx` |
| **All** | `aiohttp` async HTTP | pip | `pip install aiohttp` |
| **All** | Retry with exponential backoff | pip | `pip install tenacity` |

---

### Script Execution
Run custom scripts when conditions are met.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `subprocess.run()` | Python stdlib | None |
| **Linux** | Pass context via env vars or JSON stdin | Python stdlib | None |
| **macOS** | `subprocess.run()` | Python stdlib | None |
| **Windows** | `subprocess.run()` with PowerShell/batch | Python stdlib | None |
| **All** | Timeout protection via `timeout` param | Python stdlib | None |

---

## Process Management

### Process Control
Start/stop/restart services via MCP.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (systemd)** | `systemctl start/stop/restart svc` | Built-in | Root required |
| **Linux (SysV)** | `/etc/init.d/svc start/stop` | Built-in | Root required |
| **Linux (direct)** | `os.kill(pid, signal)` | Python stdlib | None |
| **macOS (launchd)** | `launchctl start/stop/kickstart` | Built-in | Root for system services |
| **macOS (direct)** | `os.kill(pid, signal)` | Python stdlib | None |
| **Windows (services)** | `sc start/stop svc` | Built-in | Admin required |
| **Windows (services)** | `win32serviceutil` | pip | `pip install pywin32` |
| **Windows (direct)** | `psutil.Process().terminate()` | pip | `pip install psutil` |

---

### Resource Limits
Set CPU/memory limits on processes.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | cgroups v2: write to `/sys/fs/cgroup/` | Built-in | Kernel cgroups enabled |
| **Linux** | `cgroups` Python library | pip | `pip install cgroups` |
| **Linux** | `systemd-run` with resource flags | Built-in | systemd |
| **macOS** | `launchctl limit` | Built-in | Limited support |
| **macOS** | Process priority via `os.setpriority()` | Python stdlib | None (no cgroups) |
| **Windows** | Job objects: `win32job.CreateJobObject()` | pip | `pip install pywin32` |
| **Windows** | `psutil.Process().cpu_affinity()` | pip | `pip install psutil` |

---

### Priority Management
Renice processes, adjust I/O priority.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `os.setpriority()` | Python stdlib | None |
| **Linux** | `psutil.Process().nice()` | pip | `pip install psutil` |
| **Linux** | `ionice` command | apt | `apt install util-linux` (usually pre-installed) |
| **Linux** | `ioprio_set` syscall | Python stdlib | `ctypes` |
| **macOS** | `os.setpriority()` | Python stdlib | None |
| **macOS** | `psutil.Process().nice()` | pip | `pip install psutil` |
| **macOS** | I/O priority: N/A | N/A | No ionice equivalent |
| **Windows** | `psutil.Process().nice()` with priority classes | pip | `pip install psutil` |
| **Windows** | `SetPriorityClass()` for I/O background mode | pip | `pip install pywin32` |

---

### Dependency Tracking
Understand and visualize service dependencies.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (systemd)** | Parse `systemctl show -p Requires,Wants,After` | Built-in | None |
| **Linux** | Build graph with `networkx` | pip | `pip install networkx` |
| **macOS (launchd)** | Parse plist `KeepAlive`, `RunAtLoad` | Built-in | Limited dependencies |
| **Windows** | `Get-Service -DependentServices` PowerShell | Built-in | None |
| **Windows** | WMI `Win32_DependentService` | Built-in | None |
| **Windows** | Build graph with `networkx` | pip | `pip install networkx` |
