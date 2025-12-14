# get_journal_logs

Returns systemd journal logs with filtering options.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :x: | :x: |

## Scope

This query is in the `logs` scope.


## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `unit` | string | No | - | Filter by systemd unit |
| `priority` | string | No | - | Minimum priority (emerg, alert, crit, err, warning, notice, info, debug) |
| `since` | string | No | - | Show entries since timestamp |
| `lines` | integer | No | `100` | Number of lines to return |



## Example

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_journal_logs"
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


---

*Documentation auto-generated on 2025-12-14*
