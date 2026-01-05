# Quick Start

## Installation

### Download Pre-built Binary

Download the latest release for your platform from [GitHub Releases](https://github.com/levantar-ai/mcp-sysinfo/releases):

| Platform | Binary |
|----------|--------|
| Linux (x64) | `mcp-sysinfo-linux-amd64` |
| Linux (ARM64) | `mcp-sysinfo-linux-arm64` |
| macOS (Intel) | `mcp-sysinfo-darwin-amd64` |
| macOS (Apple Silicon) | `mcp-sysinfo-darwin-arm64` |
| Windows (x64) | `mcp-sysinfo-windows-amd64.exe` |

```bash
# Linux/macOS
chmod +x mcp-sysinfo-*
./mcp-sysinfo-linux-amd64 --version

# Windows (PowerShell)
.\mcp-sysinfo-windows-amd64.exe --version
```

### Building from Source

```bash
git clone https://github.com/levantar-ai/mcp-sysinfo
cd mcp-sysinfo
go build -o mcp-sysinfo ./cmd/mcp-sysinfo
```

---

## Claude Code Integration

### Local Machine (Stdio Mode)

Add mcp-sysinfo to Claude Code for local system diagnostics:

**Linux/macOS:**

```bash
claude mcp add --transport stdio sysinfo -- /path/to/mcp-sysinfo
```

**Windows (PowerShell):**

```powershell
claude mcp add --transport stdio sysinfo -- C:\path\to\mcp-sysinfo-windows-amd64.exe
```

**With sensitive queries enabled:**

```bash
claude mcp add --transport stdio sysinfo -- /path/to/mcp-sysinfo --scope sensitive
```

### Remote Machine (HTTP Mode)

Connect Claude Code to mcp-sysinfo running on a remote machine (e.g., a Windows VM).

#### Windows VM Setup

**Step 1: Download the binary on the Windows VM**

```powershell
# Download from GitHub releases
Invoke-WebRequest -Uri "https://github.com/levantar-ai/mcp-sysinfo/releases/latest/download/mcp-sysinfo-windows-amd64.exe" -OutFile "mcp-sysinfo.exe"

# Verify it works
.\mcp-sysinfo.exe --version
.\mcp-sysinfo.exe --query get_cpu_info --json
```

**Step 2: Start the HTTP server on the Windows VM**

```powershell
# Basic (core queries only)
.\mcp-sysinfo.exe --http :8080 --token my-secret-token

# With all scopes including sensitive queries
.\mcp-sysinfo.exe --http :8080 --token my-secret-token --scope sensitive
```

**Step 3: Open Windows Firewall (if needed)**

```powershell
New-NetFirewallRule -DisplayName "MCP SysInfo" -Direction Inbound -Port 8080 -Protocol TCP -Action Allow
```

**Step 4: Get the VM's IP address**

```powershell
# Find the VM's IP
ipconfig | findstr /i "IPv4"
```

#### Host Machine Setup (Claude Code)

**Step 5: Add to Claude Code on your host machine**

```bash
# Replace 10.211.55.x with your VM's actual IP address
claude mcp add --transport http sysinfo-windows http://10.211.55.x:8080 \
  --header "Authorization: Bearer my-secret-token"
```

**Step 6: Verify the connection**

```bash
# List configured servers
claude mcp list

# Inside Claude Code, check status
/mcp
```

Now Claude Code can query your Windows VM for system diagnostics including:
- `get_cpu_info`, `get_memory_info`, `get_disk_info`, `get_processes`
- `get_registry_key`, `get_event_log`, `get_firewall_rules`
- `get_scheduled_tasks`, `get_startup_items`, `get_loaded_drivers`
- ...and 110+ more Windows-compatible queries

### Project-Shared Configuration

For team projects, add to `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "sysinfo": {
      "type": "stdio",
      "command": "/usr/local/bin/mcp-sysinfo",
      "args": ["--scope", "core,logs"]
    },
    "sysinfo-windows-vm": {
      "type": "http",
      "url": "http://192.168.1.100:8080",
      "headers": {
        "Authorization": "Bearer ${SYSINFO_TOKEN}"
      }
    }
  }
}
```

### Verify Configuration

```bash
# List configured MCP servers
claude mcp list

# Check server status (inside Claude Code)
/mcp
```

---

## Docker (Quick Demo)

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

---

## Direct Query Mode

Run queries directly from the command line (useful for testing):

```bash
# Get CPU information
./mcp-sysinfo --query get_cpu_info --json

# Get top 10 processes by CPU usage
./mcp-sysinfo --query get_processes --json --top 10

# Get memory information
./mcp-sysinfo --query get_memory_info --json

# Windows
.\mcp-sysinfo-windows-amd64.exe --query get_cpu_info --json
```

---

## HTTP Mode

Start an HTTP server for remote access or integration with other tools:

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

---

## Claude Desktop Integration

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

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

---

## Available Queries

List all available queries:

```bash
./mcp-sysinfo --list
```

See the [Query Reference](../queries/index.md) for detailed documentation of all 120 queries.

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
