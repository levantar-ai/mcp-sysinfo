# get_uptime

Returns system uptime and boot time.

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
    "name": "get_uptime"
  }
}
```

### Response

```json
{
  "boot_time": "2024-01-14T10:30:00Z",
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime_human": "1 day, 0 hours, 0 minutes",
  "uptime_seconds": 86400
}
```

## Implementation

- **Linux**: Native implementation using procfs/sysfs
- **macOS**: Native implementation using sysctl/IOKit
- **Windows**: Native implementation using WMI/Registry


---

*Documentation auto-generated on 2025-12-14*
