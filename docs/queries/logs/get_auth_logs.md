# get_auth_logs

Returns authentication and security logs. Requires sensitive scope.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :white_check_mark: | :x: |

## Scope

This query is in the `sensitive` scope and is **disabled by default**.


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
    "name": "get_auth_logs"
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
