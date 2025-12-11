# Tier 5: Integration & Extensibility

Platform integrations, data export, plugins, and multi-host features.

---

## Platform Integrations

### Cloud Metadata
AWS/GCP/Azure instance info, tags, pricing.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (AWS)** | `http://169.254.169.254/latest/meta-data/` | Built-in | On EC2 only |
| **Linux (GCP)** | `http://metadata.google.internal/` | Built-in | On GCE only |
| **Linux (Azure)** | `http://169.254.169.254/metadata/instance` | Built-in | On Azure only |
| **Linux** | `httpx` for requests | pip | `pip install httpx` |
| **macOS** | N/A | N/A | macOS not cloud-hosted |
| **Windows (AWS)** | Same metadata endpoint | Built-in | On EC2 only |
| **Windows (Azure)** | Azure Instance Metadata Service | Built-in | On Azure only |

---

### Kubernetes Awareness
Pod metrics, node status, kubectl-style queries.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `kubernetes` Python client | pip | `pip install kubernetes` |
| **Linux** | Auto-detect in-cluster via service account | Built-in | In K8s pod |
| **macOS** | `kubernetes` Python client (remote cluster) | pip | `pip install kubernetes` |
| **Windows** | `kubernetes` Python client (AKS Windows nodes) | pip | `pip install kubernetes` |

---

### systemd Integration
Service status, unit dependencies, journal logs.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `pystemd` library | pip | `pip install pystemd` |
| **Linux** | `dbus-python` | pip | `pip install dbus-python` |
| **Linux** | `systemctl show` parsing | Built-in | None |
| **Linux** | `journalctl --output=json` | Built-in | None |
| **macOS** | N/A | N/A | Uses launchd, not systemd |
| **Windows** | N/A | N/A | Uses Windows Services |

---

### Package Managers
List installed packages, check updates.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (Debian)** | `apt list --installed` | Built-in | None |
| **Linux (Debian)** | `python-apt` library | apt | `apt install python3-apt` |
| **Linux (RHEL)** | `rpm -qa` | Built-in | None |
| **Linux (RHEL)** | `dnf` Python bindings | Built-in | None |
| **macOS** | Homebrew: `brew list --versions` | brew | `brew` installed |
| **macOS** | Native: `pkgutil --pkgs` | Built-in | None |
| **macOS** | App Store: `mas list` | brew | `brew install mas` |
| **Windows** | `Get-Package` PowerShell | Built-in | None |
| **Windows** | WMI `Win32_Product` | Built-in | Slow query |
| **Windows** | Registry Uninstall keys | Python stdlib | `winreg` |

---

## Data Export

### Prometheus Metrics Endpoint
Standard `/metrics` endpoint for monitoring stack.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `prometheus_client` library | pip | `pip install prometheus-client` |
| **All** | Expose HTTP endpoint | pip | Included in above |
| **All** | Define gauges/counters for each metric | pip | Included in above |

---

### OpenTelemetry Export
OTLP traces, metrics, and logs.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `opentelemetry-sdk` | pip | `pip install opentelemetry-sdk` |
| **All** | `opentelemetry-exporter-otlp` | pip | `pip install opentelemetry-exporter-otlp` |
| **All** | Configure collector endpoint | External | OTEL collector |

---

### Grafana Datasource
Native Grafana integration.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Grafana JSON datasource API | pip | `pip install fastapi` |
| **All** | Or use Prometheus endpoint | pip | `pip install prometheus-client` |

---

### CSV/JSON/Parquet Export
Bulk data export for external analysis.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `pandas.DataFrame.to_csv()` | pip | `pip install pandas` |
| **All** | `pandas.DataFrame.to_json()` | pip | `pip install pandas` |
| **All** | `pandas.DataFrame.to_parquet()` | pip | `pip install pandas pyarrow` |

---

## Plugin Architecture

### Custom Metric Plugins
User-defined metrics via Python modules.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Plugin dir: `~/.config/mcp-sysinfo/plugins/` | Python stdlib | None |
| **Linux** | `importlib` to load modules | Python stdlib | None |
| **macOS** | Plugin dir: `~/Library/Application Support/mcp-sysinfo/plugins/` | Python stdlib | None |
| **Windows** | Plugin dir: `%APPDATA%\mcp-sysinfo\plugins\` | Python stdlib | None |
| **All** | Define plugin interface class | Python stdlib | None |

---

### Custom Tool Registration
Add new MCP tools dynamically at runtime.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Plugins return tool definitions | pip | MCP SDK |
| **All** | Server registers dynamically | pip | MCP SDK |
| **All** | Hot-reload via `watchdog` | pip | `pip install watchdog` |

---

### Webhook Receivers
Accept external data and events.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `aiohttp` HTTP endpoint | pip | `pip install aiohttp` |
| **All** | `fastapi` HTTP endpoint | pip | `pip install fastapi uvicorn` |
| **All** | Store events, trigger actions | Python stdlib | None |

---

### Metric Transformers
User-defined aggregations and calculations.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Expression language for computed metrics | Python stdlib | None |
| **All** | `numexpr` for fast evaluation | pip | `pip install numexpr` |
| **All** | Custom parser | pip | `pip install pyparsing` |

---

## Multi-Host Features

### Agent Mode
Lightweight agent for remote hosts.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Minimal agent: metrics + HTTP/gRPC push | pip | `pip install psutil httpx` |
| **macOS** | Minimal agent: metrics + HTTP/gRPC push | pip | `pip install psutil httpx` |
| **Windows** | Agent or Windows Service | pip | `pip install psutil httpx pywin32` |
| **All** | Configurable push interval | Python stdlib | None |

---

### Central Aggregation
Collect and correlate metrics from multiple machines.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `fastapi`/`aiohttp` central server | pip | `pip install fastapi` |
| **All** | Store in PostgreSQL | External | PostgreSQL server |
| **All** | Store in TimescaleDB | External | TimescaleDB server |
| **All** | Query across hosts with SQL | External | Database client |

---

### Fleet Comparison
Compare metrics across hosts, find outliers.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | SQL queries across host data | External | Database |
| **All** | Z-score per host for outliers | pip | `pip install numpy scipy` |

---

### Inventory Management
Hardware/software inventory tracking.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `dmidecode` for hardware | apt | `apt install dmidecode` (root) |
| **Linux** | `lshw` for hardware | apt | `apt install lshw` |
| **Linux** | `lscpu` | Built-in | None |
| **Linux** | Package list via apt/rpm | Built-in | None |
| **macOS** | `system_profiler` | Built-in | None |
| **macOS** | Apps + brew packages | Built-in + brew | None |
| **Windows** | WMI `Win32_ComputerSystem` | Built-in | None |
| **Windows** | WMI `Win32_Processor` | Built-in | None |
| **Windows** | Registry + `Get-Package` | Built-in | None |
