# Security Scopes

Queries are organized into security scopes based on the sensitivity of the data they expose.

## Scope Levels

| Scope | Risk | Default | Description |
|-------|------|---------|-------------|
| `core` | Low | Enabled | Basic system metrics |
| `logs` | Medium | Enabled | System logs (excluding auth) |
| `hooks` | Medium | Enabled | Services, network config |
| `sbom` | Medium | Enabled | Package inventory |
| `sensitive` | **High** | **Disabled** | Security-critical data |

## Core Scope

Low-risk system metrics safe for any environment.

**Queries:**

- `get_cpu_info` - CPU usage and frequency
- `get_memory_info` - Memory utilization
- `get_disk_info` - Disk partitions and usage
- `get_network_info` - Network interfaces
- `get_processes` - Process list
- `get_uptime` - System uptime
- `get_temperature` - Hardware temperatures

## Logs Scope

System log access, excluding authentication logs.

**Queries:**

- `get_journal_logs` - Systemd journal (Linux)
- `get_syslog` - Traditional syslog
- `get_kernel_logs` - Kernel ring buffer
- `get_app_logs` - Application logs
- `get_event_log` - Windows Event Log

## Hooks Scope

Deep system introspection for diagnostics.

**Queries:** 31 queries including scheduled tasks, kernel modules, network configuration, filesystem mounts, hardware info, and more.

## SBOM Scope

Software inventory for asset management.

**Queries:**

- `get_system_packages` - OS packages (apt, yum, brew, etc.)
- `get_path_executables` - Executables in PATH
- `get_python_packages` - Python pip packages
- `get_node_packages` - Node.js npm packages
- `get_go_modules` - Go module cache
- `get_rust_packages` - Rust cargo crates
- `get_ruby_gems` - Ruby gems

## Sensitive Scope

Security-critical data requiring explicit opt-in.

!!! danger "High Risk"
    These queries can expose credentials, authentication configuration, and security policy. Only enable in trusted, isolated environments.

**Queries:**

- `get_auth_logs` - Authentication logs (failed logins, sudo usage)
- `get_ssh_config` - SSH server configuration
- `get_sudo_config` - Sudoers configuration

### Enabling Sensitive Scope

```bash
# Command line
./mcp-sysinfo --enable-sensitive

# Environment variable
export MCP_SYSINFO_SCOPES=core,logs,hooks,sbom,sensitive
```

## Custom Scope Configuration

Enable specific scopes only:

```bash
# Core only
./mcp-sysinfo --scopes core

# Core and logs
./mcp-sysinfo --scopes core,logs

# All including sensitive
./mcp-sysinfo --scopes core,logs,hooks,sbom,sensitive
```

## Scope Enforcement

Queries outside enabled scopes return an error:

```json
{
  "error": {
    "code": -32600,
    "message": "Query 'get_auth_logs' requires scope 'sensitive' which is not enabled"
  }
}
```
