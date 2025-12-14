# get_temperature

Returns hardware temperature sensor readings.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :warning: | :warning: |

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
    "name": "get_temperature"
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
- **Windows**: Partial support


---

*Documentation auto-generated on 2025-12-14*
