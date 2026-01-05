# Enhanced Diagnostics

Phase 2 queries for GPU and container monitoring.

## GPU Diagnostics

### get_gpu_info

Get comprehensive GPU information including memory usage, utilization, temperature, and running processes.

**Scope:** `enhanced`

**Parameters:** None

**Supported Vendors:**

| Vendor | Linux | macOS | Windows | Detection Method |
|--------|:-----:|:-----:|:-------:|-----------------|
| NVIDIA | :white_check_mark: | :white_check_mark: | :white_check_mark: | nvidia-smi |
| AMD | :white_check_mark: | :x: | :white_check_mark: | sysfs/WMI |
| Intel | :white_check_mark: | :x: | :white_check_mark: | sysfs/WMI |
| Apple Silicon | :x: | :white_check_mark: | :x: | system_profiler |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `index` | int | GPU index |
| `name` | string | GPU model name |
| `vendor` | string | nvidia, amd, intel, apple |
| `driver` | string | Driver version |
| `memory_total` | uint64 | Total VRAM in bytes |
| `memory_used` | uint64 | Used VRAM in bytes |
| `memory_free` | uint64 | Free VRAM in bytes |
| `utilization` | float64 | GPU utilization percentage |
| `memory_utilization` | float64 | Memory utilization percentage |
| `temperature` | float64 | Temperature in Celsius |
| `fan_speed` | int | Fan speed percentage |
| `power_draw` | float64 | Power draw in watts |
| `power_limit` | float64 | Power limit in watts |
| `clock_graphics` | int | Graphics clock in MHz |
| `clock_memory` | int | Memory clock in MHz |
| `processes` | array | Processes using the GPU |

**Example:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_gpu_info"
  }
}
```

---

## Container Metrics

### get_container_stats

Get real-time CPU, memory, network, and I/O statistics for Docker/Podman containers.

**Scope:** `enhanced`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `container_id` | string | No | Container ID or name (returns all running containers if not specified) |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Container ID |
| `name` | string | Container name |
| `cpu_percent` | float64 | CPU usage percentage |
| `memory_usage` | uint64 | Memory usage in bytes |
| `memory_limit` | uint64 | Memory limit in bytes |
| `memory_percent` | float64 | Memory usage percentage |
| `network_rx_bytes` | uint64 | Network bytes received |
| `network_tx_bytes` | uint64 | Network bytes sent |
| `block_read_bytes` | uint64 | Block I/O read bytes |
| `block_write_bytes` | uint64 | Block I/O write bytes |
| `pids` | int | Number of processes |

**Example:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_container_stats",
    "arguments": {
      "container_id": "nginx"
    }
  }
}
```

---

### get_container_logs

Get logs from a Docker/Podman container with timestamp parsing and stream separation.

**Scope:** `enhanced`

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `container_id` | string | Yes | Container ID or name |
| `lines` | int | No | Number of lines to return (default 100) |
| `since` | string | No | Return logs since timestamp (RFC3339 or Unix) |

**Response fields:**

| Field | Type | Description |
|-------|------|-------------|
| `container_id` | string | Container ID |
| `name` | string | Container name |
| `logs` | array | Log entries |
| `logs[].timestamp` | time | Log entry timestamp |
| `logs[].stream` | string | stdout or stderr |
| `logs[].message` | string | Log message |
| `count` | int | Number of log entries |
| `truncated` | bool | Whether logs were truncated |

**Example:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_container_logs",
    "arguments": {
      "container_id": "nginx",
      "lines": 50
    }
  }
}
```
