# Cross-Platform Architecture

MCP System Info provides consistent behavior across Linux, macOS, and Windows using native OS APIs.

## Platform API Matrix

| Domain | Linux | macOS | Windows |
|--------|-------|-------|---------|
| Processes | `/proc` | `sysctl`, `libproc` | WMI, ToolHelp |
| CPU | `/proc/stat`, `/proc/cpuinfo` | `sysctl` | WMI, PDH |
| Memory | `/proc/meminfo` | `sysctl` | GlobalMemoryStatusEx |
| Disk | `/proc/mounts`, `statfs` | `statfs` | GetDiskFreeSpaceEx |
| Network | `/proc/net`, netlink | `sysctl`, `getifaddrs` | GetAdaptersAddresses |
| Kernel | `sysinfo`, `/proc/sys` | `sysctl` | VerifyVersionInfo |
| Services | D-Bus (systemd) | `launchctl` | SCManager |
| Packages | dpkg, rpm, pacman | pkgutil, brew | Registry |
| Temperature | hwmon, thermal zones | SMC | WMI |
| Firewall | iptables, nftables | pf | Windows Firewall API |

## Implementation Patterns

### Build Tags

Platform-specific code uses Go build tags:

```go
// file_linux.go
//go:build linux

package queries

func getCPUInfo() (*CPUInfo, error) {
    // Linux-specific implementation using /proc
}
```

### Common Interface

All queries implement a common interface:

```go
type QueryHandler interface {
    Name() string
    Description() string
    Scope() string
    Execute(params map[string]any) (any, error)
}
```

### Fallback Behavior

When a feature isn't available on a platform:

| Strategy | Behavior |
|----------|----------|
| **Empty Result** | Return empty array/object with success |
| **Partial Data** | Return available fields, omit unavailable |
| **Not Supported** | Return error with "not supported on platform" |

Example:

```go
func getKernelModules() ([]Module, error) {
    // This is Linux-only
    if runtime.GOOS != "linux" {
        return nil, nil  // Return empty, not error
    }
    // Linux implementation
}
```

## Linux Implementation

### Data Sources

| Source | Data |
|--------|------|
| `/proc/stat` | CPU statistics |
| `/proc/meminfo` | Memory statistics |
| `/proc/[pid]/*` | Process information |
| `/proc/net/*` | Network statistics |
| `/sys/class/*` | Hardware information |
| `/sys/fs/cgroup` | Cgroup resource limits |
| `/etc/*` | Configuration files |

### Privileges

Most queries work without root. Some require elevated privileges:

- Reading other users' process details
- Accessing certain `/proc` files
- Reading system logs

## macOS Implementation

### Data Sources

| Source | Data |
|--------|------|
| `sysctl` | System statistics, kernel info |
| `libproc` | Process information |
| `IOKit` | Hardware, power, sensors |
| `FSEvents` | Filesystem events |
| `/var/log` | System logs |

### Limitations

- **Temperature**: Requires SMC access (may need root)
- **Kernel modules**: macOS uses kexts, different model
- **Cgroups/namespaces**: Not available (macOS uses different isolation)

## Windows Implementation

### Data Sources

| Source | Data |
|--------|------|
| WMI | Most system information |
| PDH | Performance counters |
| Registry | Configuration, installed software |
| Event Log API | Windows Event Logs |
| ToolHelp | Process enumeration |

### Queries Specific to Windows

- `get_event_log` - Windows Event Log
- `get_scheduled_tasks` - Task Scheduler

### Queries Not Available on Windows

- `get_journal_logs` - Systemd is Linux-only
- `get_cgroups` - Linux-only
- `get_namespaces` - Linux-only
- `get_capabilities` - Linux-only

## Testing

Cross-platform testing uses:

1. **Unit tests**: Run on all platforms in CI
2. **Build smoke tests**: Verify compilation on all targets
3. **Integration tests**: Platform-specific test suites

CI matrix:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest, windows-latest]
```
