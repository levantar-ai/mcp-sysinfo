# JSON-RPC API

MCP System Info implements the [JSON-RPC 2.0](https://www.jsonrpc.org/specification) protocol for communication.

> **OpenAPI Specification**: A machine-readable API specification is available at [`api/openapi.yaml`](../../api/openapi.yaml).

## Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_cpu_info",
    "arguments": {
      "per_cpu": true
    }
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jsonrpc` | string | Yes | Must be "2.0" |
| `id` | number/string | Yes | Request identifier |
| `method` | string | Yes | Method name |
| `params` | object | No | Method parameters |

## Response Format

### Success

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"cpu_percent\": 12.5, ...}"
      }
    ]
  }
}
```

### Error

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "Query 'get_auth_logs' requires scope 'sensitive' which is not enabled"
  }
}
```

## Error Codes

| Code | Meaning |
|------|---------|
| `-32700` | Parse error |
| `-32600` | Invalid request |
| `-32601` | Method not found |
| `-32602` | Invalid params |
| `-32603` | Internal error |
| `-32000` | Query execution error |

## MCP Methods

### tools/list

List available query tools.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list"
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "get_cpu_info",
        "description": "Returns CPU usage, frequency, load average, and core information.",
        "inputSchema": {
          "type": "object",
          "properties": {
            "per_cpu": {
              "type": "boolean",
              "description": "Include per-CPU breakdown"
            }
          }
        }
      }
    ]
  }
}
```

### tools/call

Execute a query tool.

**Request:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "get_processes",
    "arguments": {
      "top": 10,
      "sort_by": "cpu"
    }
  }
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "[{\"pid\": 1234, \"name\": \"chrome\", ...}]"
      }
    ]
  }
}
```

## HTTP Endpoint

When running in HTTP mode, send requests to the root endpoint:

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_uptime"}}'
```

## Batch Requests

JSON-RPC batch requests are supported:

```json
[
  {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "get_cpu_info"}},
  {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "get_memory_info"}}
]
```

Response:

```json
[
  {"jsonrpc": "2.0", "id": 1, "result": {...}},
  {"jsonrpc": "2.0", "id": 2, "result": {...}}
]
```
