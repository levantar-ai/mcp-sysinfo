# get_path_executables

Returns executables found in PATH directories.

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| :white_check_mark: | :white_check_mark: | :white_check_mark: |

## Scope

This query is in the `sbom` scope.



## Example

### Request

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_path_executables"
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
- **Windows**: Native implementation using WMI/Registry


---

*Documentation auto-generated on 2025-12-14*
