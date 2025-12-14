# get_block_devices

Returns block device topology.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :warning: | :white_check_mark: |

## Scope

This query is in the `hooks` scope.



## Example

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_block_devices"
  }
}
```

### Response

```json
{
  "result": "...",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Implementation

- **Linux**: Native implementation using procfs/sysfs
- **macOS**: Partial support
- **Windows**: Native implementation using WMI/Registry


---

*Documentation auto-generated on 2025-12-14*
