# get_ipc_resources

Returns System V IPC resources (semaphores, shared memory, message queues).

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :warning: | :x: |

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
    "name": "get_ipc_resources"
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


---

*Documentation auto-generated on 2025-12-14*
