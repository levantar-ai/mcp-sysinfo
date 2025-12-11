# Tier 2: Analytics & Intelligence

Historical data, trends, anomaly detection, and comparative analysis.

---

## Historical Data & Trends

### Time-Series Database
Store metrics in embedded database for historical analysis.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `DuckDB` | pip | `pip install duckdb` |
| **Linux** | `SQLite` (with time-series patterns) | Python stdlib | None (built into Python) |
| **Linux** | `pandas` for analysis | pip | `pip install pandas` |
| **Linux** | Storage: `~/.local/share/mcp-sysinfo/` | Built-in | None |
| **macOS** | `DuckDB` | pip | `pip install duckdb` |
| **macOS** | `SQLite` | Python stdlib | None |
| **macOS** | Storage: `~/Library/Application Support/mcp-sysinfo/` | Built-in | None |
| **Windows** | `DuckDB` | pip | `pip install duckdb` |
| **Windows** | `SQLite` | Python stdlib | None |
| **Windows** | Storage: `%APPDATA%\mcp-sysinfo\` | Built-in | None |

---

### Trend Detection
Identify metric trends (e.g., "Memory usage up 15% over last week").

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `numpy` linear regression | pip | `pip install numpy` |
| **All** | `scipy.stats.linregress` | pip | `pip install scipy` |
| **All** | `pandas` rolling averages | pip | `pip install pandas` |

---

### Anomaly Detection
ML-based unusual behavior flagging.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `scikit-learn` IsolationForest | pip | `pip install scikit-learn` |
| **All** | `scikit-learn` LocalOutlierFactor | pip | `pip install scikit-learn` |
| **All** | Z-score detection | pip | `pip install numpy scipy` |
| **All** | `prophet` for time-series anomalies | pip | `pip install prophet` |

---

### Capacity Forecasting
Predict when resources will be exhausted.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Linear extrapolation with `numpy` | pip | `pip install numpy` |
| **All** | `prophet` forecasting | pip | `pip install prophet` |
| **All** | `statsmodels` ARIMA | pip | `pip install statsmodels` |

---

### Correlation Analysis
Find relationships between metrics.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `pandas.DataFrame.corr()` | pip | `pip install pandas` |
| **All** | `scipy.stats.pearsonr` | pip | `pip install scipy` |
| **All** | `numpy.correlate` for cross-correlation | pip | `pip install numpy` |

---

## Resource Profiling

### Application Profiling
Track which apps consume most resources over time.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `psutil.Process` aggregated by `name()` or `exe()` | pip | `pip install psutil` |
| **Linux** | Group by cgroup via `/proc/[pid]/cgroup` | Built-in | None |
| **macOS** | `psutil.Process` by `name()` | pip | `pip install psutil` |
| **macOS** | Bundle ID via `NSRunningApplication` | pip | `pip install pyobjc-framework-Cocoa` |
| **Windows** | `psutil.Process` by `name()` | pip | `pip install psutil` |
| **Windows** | Group by window title or UWP package | Built-in | Win32 APIs |

---

### Peak Usage Analysis
Identify resource bottlenecks by time of day/week.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Time-bucket in SQLite/DuckDB | pip | `pip install duckdb` or stdlib |
| **All** | `pandas` groupby hour/day | pip | `pip install pandas` |
| **All** | Heatmap with `matplotlib` or `seaborn` | pip | `pip install matplotlib seaborn` |

---

### Resource Attribution
Break down usage by user/service/container/cgroup.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `psutil.Process.username()` | pip | `pip install psutil` |
| **Linux** | Cgroup parsing from `/proc/[pid]/cgroup` | Built-in | None |
| **Linux** | Systemd slice attribution | Built-in | systemd |
| **macOS** | `psutil.Process.username()` | pip | `pip install psutil` |
| **macOS** | Group by app bundle or launchd service | Built-in | None (no cgroups) |
| **Windows** | `psutil.Process.username()` | pip | `pip install psutil` |
| **Windows** | Job objects via `win32job` | pip | `pip install pywin32` |
| **Windows** | Service attribution via `win32service` | pip | `pip install pywin32` |

---

### Idle Resource Detection
Find zombie processes, unused services.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `psutil.Process.status() == 'zombie'` | pip | `pip install psutil` |
| **Linux** | Unused systemd services via `systemctl list-units` | Built-in | None |
| **macOS** | `psutil.Process.status() == 'zombie'` | pip | `pip install psutil` |
| **macOS** | Unused launchd services via `launchctl list` | Built-in | None |
| **Windows** | `psutil.Process.status()` for hung processes | pip | `pip install psutil` |
| **Windows** | `Get-Service` where StartType=Auto but not running | Built-in | None |

---

## Comparative Analysis

### Baseline Comparison
Compare current state to learned "normal" baseline.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Store baseline (mean, stddev) in SQLite | Python stdlib | None |
| **All** | Compare current values, alert on >2 sigma | pip | `pip install numpy` |

---

### Before/After Snapshots
Compare system state across deployments or changes.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Serialize full state to JSON | Python stdlib | None |
| **All** | `deepdiff` library for comparison | pip | `pip install deepdiff` |
| **All** | Store snapshots with timestamps in DB | Python stdlib | None |

---

### Multi-Machine Comparison
Compare metrics across fleet (when multi-host enabled).

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Central aggregator via HTTP/gRPC | pip | `pip install fastapi grpcio` |
| **All** | Store per-host in PostgreSQL/TimescaleDB | External | PostgreSQL server |
| **All** | Query across hosts with SQL | External | Database client |

---

### Configuration Drift Detection
Track system config changes over time.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Hash `/etc/passwd`, `/etc/ssh/sshd_config` with `hashlib` | Python stdlib | None |
| **Linux** | `etckeeper` integration | apt | `apt install etckeeper` |
| **macOS** | Hash config files, plists in `/Library/Preferences/` | Python stdlib | None |
| **macOS** | Track via `defaults export` | Built-in | None |
| **Windows** | Registry snapshots via `winreg` | Python stdlib | None |
| **Windows** | Compare `HKLM\SOFTWARE` keys | Python stdlib | None |
| **Windows** | Track Group Policy via `gpresult` | Built-in | None |
