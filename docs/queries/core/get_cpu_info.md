# get_cpu_info

Returns CPU usage, frequency, load average, and core information.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :white_check_mark: | :white_check_mark: |

## Scope

This query is in the `core` scope.


## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `per_cpu` | boolean | No | `false` | Include per-CPU breakdown |



## Example

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_cpu_info"
  }
}
```

### Response

```json
{
  "cpu_count": 8,
  "cpu_freq_mhz": 2400,
  "cpu_percent": 12.5,
  "load_average": [
    1.2,
    0.8,
    0.5
  ],
  "model_name": "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Implementation

- **Linux**: Native implementation using procfs/sysfs
- **macOS**: Native implementation using sysctl/IOKit
- **Windows**: Native implementation using WMI/Registry


---

*Documentation auto-generated on 2025-12-14*
