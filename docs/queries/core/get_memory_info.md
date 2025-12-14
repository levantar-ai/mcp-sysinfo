# get_memory_info

Returns memory usage including total, used, available, and swap.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :white_check_mark: | :white_check_mark: |

## Scope

This query is in the `core` scope.



## Example

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_memory_info"
  }
}
```

### Response

```json
{
  "available_bytes": 8589934592,
  "percent_used": 50,
  "swap_total": 4294967296,
  "swap_used": 1073741824,
  "timestamp": "2024-01-15T10:30:00Z",
  "total_bytes": 17179869184,
  "used_bytes": 8589934592
}
```

## Implementation

- **Linux**: Native implementation using procfs/sysfs
- **macOS**: Native implementation using sysctl/IOKit
- **Windows**: Native implementation using WMI/Registry


---

*Documentation auto-generated on 2025-12-14*
