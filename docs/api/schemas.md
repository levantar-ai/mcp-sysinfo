# Response Schemas

All query responses follow consistent JSON schemas.

## Common Fields

All responses include:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | ISO 8601 timestamp of data collection |

## Core Metrics

### get_cpu_info

```json
{
  "cpu_percent": 12.5,
  "cpu_count": 8,
  "cpu_freq_mhz": 2400.0,
  "load_average": [1.2, 0.8, 0.5],
  "model_name": "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz",
  "per_cpu": [
    {"cpu": 0, "percent": 15.2},
    {"cpu": 1, "percent": 10.1}
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### get_memory_info

```json
{
  "total_bytes": 17179869184,
  "used_bytes": 8589934592,
  "available_bytes": 8589934592,
  "percent_used": 50.0,
  "swap_total": 4294967296,
  "swap_used": 1073741824,
  "swap_percent": 25.0,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### get_disk_info

```json
{
  "partitions": [
    {
      "device": "/dev/sda1",
      "mountpoint": "/",
      "fstype": "ext4",
      "total_bytes": 107374182400,
      "used_bytes": 53687091200,
      "free_bytes": 53687091200,
      "percent_used": 50.0
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### get_network_info

```json
{
  "interfaces": [
    {
      "name": "eth0",
      "mac_address": "00:11:22:33:44:55",
      "addresses": [
        {"ip": "192.168.1.100", "netmask": "255.255.255.0"}
      ],
      "bytes_sent": 1073741824,
      "bytes_recv": 2147483648,
      "packets_sent": 1000000,
      "packets_recv": 2000000,
      "is_up": true
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### get_processes

```json
{
  "processes": [
    {
      "pid": 1234,
      "name": "chrome",
      "username": "user",
      "cpu_percent": 15.2,
      "memory_percent": 5.1,
      "memory_rss_bytes": 524288000,
      "status": "running",
      "create_time": "2024-01-15T08:00:00Z",
      "cmdline": "/usr/bin/chrome --flag"
    }
  ],
  "count": 150,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### get_uptime

```json
{
  "uptime_seconds": 345600,
  "uptime_human": "4 days, 0 hours, 0 minutes",
  "boot_time": "2024-01-11T10:30:00Z",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### get_temperature

```json
{
  "sensors": [
    {
      "name": "coretemp",
      "label": "Core 0",
      "current_celsius": 45.0,
      "high_celsius": 80.0,
      "critical_celsius": 100.0
    }
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Error Responses

Query errors include structured error information:

```json
{
  "error": {
    "code": -32000,
    "message": "Failed to read CPU info",
    "data": {
      "query": "get_cpu_info",
      "platform": "linux",
      "details": "permission denied"
    }
  }
}
```

## Null vs Empty

| Scenario | Response |
|----------|----------|
| Query succeeds, no data | Empty array `[]` or empty object `{}` |
| Query not supported on platform | Empty array `[]` or empty object `{}` |
| Query fails | Error response |

This ensures clients can always parse responses consistently.
