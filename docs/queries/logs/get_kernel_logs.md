# get_kernel_logs

Returns kernel ring buffer (dmesg) messages.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :white_check_mark: | :x: |

## Scope

This query is in the `logs` scope.


## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `lines` | integer | No | `100` | Number of lines to return |



## Example

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_kernel_logs"
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
- **macOS**: Native implementation using sysctl/IOKit


---

*Documentation auto-generated on 2025-12-14*
