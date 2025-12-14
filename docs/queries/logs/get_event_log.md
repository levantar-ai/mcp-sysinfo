# get_event_log

Returns Windows Event Log entries.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :x: | :x: | :white_check_mark: |

## Scope

This query is in the `logs` scope.


## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `log` | string | No | `System` | Log name: System, Application, Security |
| `count` | integer | No | `100` | Number of entries to return |



## Example

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_event_log"
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

- **Windows**: Native implementation using WMI/Registry


---

*Documentation auto-generated on 2025-12-14*
