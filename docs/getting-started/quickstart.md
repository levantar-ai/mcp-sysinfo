# Quick Start

## Docker (Fastest Way to Try)

```bash
# Clone the repository
git clone https://github.com/levantar-ai/mcp-sysinfo
cd mcp-sysinfo

# Start the HTTP server on port 8080
docker compose up mcp-sysinfo-http

# In another terminal, test it
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_uptime"}}'
```

For full system access (privileged mode):

```bash
docker compose --profile privileged up mcp-sysinfo-privileged
```

## Building from Source

```bash
# Clone and build
git clone https://github.com/levantar-ai/mcp-sysinfo
cd mcp-sysinfo
go build -o mcp-sysinfo ./cmd/mcp-sysinfo
```

## Running the Server

### Stdio Mode (MCP Clients)

For use with Claude Desktop and other MCP clients:

```bash
./mcp-sysinfo
```

The server communicates via JSON-RPC over stdin/stdout.

### Direct Query Mode

Run queries directly from the command line:

```bash
# Get CPU information
./mcp-sysinfo --query get_cpu_info --json

# Get top 10 processes by CPU usage
./mcp-sysinfo --query get_processes --json --top 10

# Get memory information
./mcp-sysinfo --query get_memory_info --json
```

### HTTP Mode

Start an HTTP server for remote access:

```bash
./mcp-sysinfo --http :8080 --token your-secret-token
```

Then query via HTTP:

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "get_cpu_info"}
  }'
```

## Configuring Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sysinfo": {
      "command": "/path/to/mcp-sysinfo",
      "args": []
    }
  }
}
```

## Available Queries

List all available queries:

```bash
./mcp-sysinfo --list
```

See the [Query Reference](../queries/index.md) for detailed documentation of all 51 queries.

## Example Output

```bash
$ ./mcp-sysinfo --query get_uptime --json
```

```json
{
  "uptime_seconds": 345600,
  "uptime_human": "4 days, 0 hours, 0 minutes",
  "boot_time": "2024-01-11T10:30:00Z",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Example Clients

We provide example clients in Go and Python to help you get started:

```bash
# Go client
go run examples/go/main.go --query get_cpu_info

# Python client
pip install requests
python examples/python/mcp_client.py --query get_cpu_info
```

See the [examples/](https://github.com/levantar-ai/mcp-sysinfo/tree/main/examples) directory for full source code.

## Next Steps

- [Configuration](configuration.md) - Enable sensitive queries, configure scopes
- [Security](../security/index.md) - Authentication and deployment options
- [API Reference](../api/jsonrpc.md) - Full JSON-RPC API documentation
