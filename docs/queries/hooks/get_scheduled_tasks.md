# get_scheduled_tasks

Returns Windows Task Scheduler tasks.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :x: | :x: | :white_check_mark: |

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
    "name": "get_scheduled_tasks"
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
