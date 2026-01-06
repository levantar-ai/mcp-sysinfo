# MCP System Info Server - Overview

A read-only security diagnostics platform using the Model Context Protocol (MCP) for AI-assisted incident triage.

## Document Structure

| Document | Description |
|----------|-------------|
| [00-overview.md](00-overview.md) | This file - project overview, rationale, and quick start |
| [01-tier1-core-monitoring.md](01-tier1-core-monitoring.md) | Core diagnostics, log access, system metrics |
| [02-tier2-analytics.md](02-tier2-analytics.md) | Historical data, trends, anomaly detection |
| [03-tier3-automation.md](03-tier3-automation.md) | Alerts, auto-remediation, process management |
| [04-tier4-security.md](04-tier4-security.md) | Security analysis, compliance, forensics |
| [05-tier5-integration.md](05-tier5-integration.md) | Platform integrations, plugins, multi-host |
| [06-tier6-llm-features.md](06-tier6-llm-features.md) | LLM-optimized features, diagnostics, documentation |

---

## Why an MCP Server vs. Direct Shell Commands?

### 1. Security & Sandboxing

| Approach | Risk Level |
|----------|------------|
| Direct shell access | **High** - AI can run arbitrary commands |
| MCP Server | **Low** - Controlled interface, vetted operations only |

### 2. Structured Output

```json
{
  "cpu_percent": 45.2,
  "memory": {"total": 16000000000, "available": 8000000000},
  "load_average": [1.2, 0.8, 0.5]
}
```

vs. parsing unpredictable shell output.

### 3. Performance

| Aspect | Direct Commands | MCP Server |
|--------|-----------------|------------|
| Process spawning | New process per command | Single long-running process |
| Caching | None | Built-in TTL caching |
| Overhead | High | Low (10-100x faster) |

### 4. Cross-Platform Consistency

Same API across Linux, macOS, and Windows.

### 5. Additional Benefits

- **Aggregation**: Derived metrics, correlations
- **Rate Limiting**: Prevent resource abuse
- **Audit Trail**: Log all requests
- **Stateful**: Track metrics over sessions
- **Integration Ready**: Prometheus, Grafana, etc.

---

## Implementation Phases

| Phase | Features | Effort |
|-------|----------|--------|
| **1.0** | Basic 7 tools (CPU, memory, disk, network, processes, uptime, temp) | Low |
| **1.1** | Log access (journal, syslog, auth, app logs) | Low |
| **1.2** | System hooks (deep introspection) | Medium |
| **1.3** | SBOM & software inventory | Medium |
| **2.0** | GPU, containers, analytics | Medium |
| **3.0** | Alerts, security, multi-host | High |

---

## Core MCP Tools (MVP)

```python
get_cpu_info(per_cpu: bool = False) -> CpuInfo
get_memory_info() -> MemoryInfo
get_disk_info(path: str = None) -> DiskInfo
get_network_info(interface: str = None) -> NetworkInfo
get_process_list(sort_by: str = "cpu", limit: int = 10) -> ProcessList
get_system_uptime() -> UptimeInfo
get_temperature_info() -> TemperatureInfo
```

## MCP Resources

```
system://overview    - Comprehensive system summary
system://processes   - Current process list
system://health      - Health score and issues
system://alerts      - Active alerts
system://history/{m} - Historical data for metric
```

---

## Technology Stack

| Component | Recommendation | Rationale |
|-----------|----------------|-----------|
| System metrics | `psutil` | Cross-platform, comprehensive |
| GPU metrics | `pynvml`, `pyamdgpuinfo` | Native GPU bindings |
| Storage | `DuckDB` or `SQLite` | Embedded, no dependencies |
| Anomaly detection | `scikit-learn` | Simple, effective |
| Container metrics | `docker` SDK | Official SDK |
| MCP framework | `mcp` SDK | Official Anthropic SDK |
| File watching | `watchdog` | Cross-platform |
| HTTP | `httpx` | Modern async |

---

## Availability Legend

Each tier document uses this legend for availability:

| Symbol | Meaning |
|--------|---------|
| **Built-in** | Available by default, no installation needed |
| **Python stdlib** | Part of Python standard library |
| **pip install X** | Requires installing Python package X |
| **apt/brew/choco** | Requires system package installation |
| **Kernel/OS** | Requires OS-level feature or config |
| **Root/Admin** | Requires elevated privileges |
| **N/A** | Not available on this platform |

---

## Getting Started

1. Start with MVP - 7 basic tools wrapping `psutil`
2. Add structured JSON responses with consistent schemas
3. Implement TTL caching to prevent redundant system calls
4. Add configuration via environment variables
5. Write tests using mocked system data
6. Iterate towards v1.0 with historical storage

**Key insight**: Each tier builds on the previous one. Grow organically.
