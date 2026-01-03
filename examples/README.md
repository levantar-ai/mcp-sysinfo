# Example Clients

This directory contains example clients demonstrating how to interact with MCP System Info.

## Go Client

```bash
cd go

# Run with default settings (http://localhost:8080)
go run main.go

# List all available tools
go run main.go -list

# Run a specific query
go run main.go -query get_cpu_info

# With authentication
go run main.go -url http://localhost:8080 -token your-token -query get_processes
```

## Python Client

Requires Python 3.10+ and the `requests` library:

```bash
cd python

# Install dependencies
pip install requests

# Run with default settings (http://localhost:8080)
python mcp_client.py

# List all available tools
python mcp_client.py --list

# Run a specific query
python mcp_client.py --query get_cpu_info

# With authentication
python mcp_client.py --url http://localhost:8080 --token your-token --query get_processes
```

## Example Output

```json
{
  "uptime_seconds": 345600,
  "uptime_human": "4 days, 0 hours, 0 minutes",
  "boot_time": "2024-01-11T10:30:00Z",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Using with Docker

Start the server:

```bash
# From the repository root
docker compose up mcp-sysinfo-http
```

Then run the clients:

```bash
# Go
go run examples/go/main.go

# Python
python examples/python/mcp_client.py
```
