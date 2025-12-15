# Audit Logging

MCP System Info provides an industry-leading audit logging system for security and compliance requirements. The audit system is **opt-in** and must be explicitly enabled.

## Features

- **JSON Lines Format**: Each audit event is a self-contained JSON object on its own line
- **Tamper-Evident**: SHA-256 hash chain and sequence numbers detect modifications
- **Immutable Append-Only**: Uses `O_APPEND` flag for atomic, append-only writes
- **Async Buffered Writing**: High-performance buffering with configurable flush intervals
- **File Rotation**: Automatic rotation by size with gzip compression
- **Provider Architecture**: Extensible design for custom backends (SIEM, remote logging, etc.)

## Quick Start

### Enable Audit Logging

```bash
# Basic audit logging
mcp-sysinfo --audit --audit-output /var/log/mcp-sysinfo/audit.jsonl

# With custom settings
mcp-sysinfo --audit \
    --audit-output /var/log/mcp-sysinfo/audit.jsonl \
    --audit-buffer-size 200 \
    --audit-flush-interval 10s \
    --audit-max-file-size 50000000 \
    --audit-max-files 20

# High-integrity mode (synchronous writes)
mcp-sysinfo --audit \
    --audit-output /var/log/mcp-sysinfo/audit.jsonl \
    --audit-sync-write
```

### Verify Audit Log Integrity

```bash
# Verify hash chain integrity
mcp-sysinfo --audit-verify --audit-output /var/log/mcp-sysinfo/audit.jsonl
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--audit` | `false` | Enable audit logging |
| `--audit-output` | `/var/log/mcp-sysinfo/audit.jsonl` | Audit log file path |
| `--audit-buffer-size` | `100` | Number of events to buffer (0 for synchronous) |
| `--audit-flush-interval` | `5s` | How often to flush buffered events |
| `--audit-max-file-size` | `100MB` | Max file size before rotation |
| `--audit-max-files` | `10` | Max rotated files to keep |
| `--audit-sync-write` | `false` | Force fsync after each write |
| `--audit-verify` | `false` | Verify audit log and exit |

## Event Format

Each audit event is a JSON object with the following fields:

```json
{
  "timestamp": "2024-01-15T10:30:45.123456789Z",
  "seq": 42,
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "correlation_id": "req-123",
  "action": "tools/call",
  "resource": "get_cpu_info",
  "identity": "user@example.com",
  "client_ip": "192.168.1.100",
  "params": {"detailed": true},
  "result": "success",
  "error": "",
  "duration_ns": 15000000,
  "metadata": {"version": "1.0"},
  "prev_hash": "abc123...",
  "hash": "def456..."
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | RFC3339Nano | When the event occurred (UTC) |
| `seq` | uint64 | Monotonically increasing sequence number |
| `event_id` | UUID | Unique identifier for this event |
| `correlation_id` | string | Links related events (e.g., request/response pairs) |
| `action` | string | Operation performed (e.g., `tools/call`, `auth/login`) |
| `resource` | string | What was accessed (e.g., `get_cpu_info`) |
| `identity` | string | Who performed the action (from JWT sub claim) |
| `client_ip` | string | Client's IP address |
| `params` | object | Input parameters for the action |
| `result` | enum | Outcome: `success`, `error`, or `denied` |
| `error` | string | Error details if result is `error` |
| `duration_ns` | int64 | How long the action took (nanoseconds) |
| `metadata` | object | Additional context |
| `prev_hash` | string | Hash of previous event (chain integrity) |
| `hash` | string | SHA-256 hash of this event |

## Tamper Evidence

### Hash Chain

Each event includes:

1. **Sequence Number** (`seq`): Monotonically increasing, detects deleted events
2. **Previous Hash** (`prev_hash`): Links to the previous event's hash
3. **Event Hash** (`hash`): SHA-256 hash of all fields except the hash itself

This creates an immutable chain where any modification is detectable:

```
Event 1:  hash="abc..."
          |
          v
Event 2:  prev_hash="abc...", hash="def..."
          |
          v
Event 3:  prev_hash="def...", hash="ghi..."
```

### Verification

Use `--audit-verify` to validate the entire chain:

```bash
$ mcp-sysinfo --audit-verify --audit-output /var/log/mcp-sysinfo/audit.jsonl
Audit verification OK: 1523 events verified

# If tampered:
$ mcp-sysinfo --audit-verify --audit-output /var/log/mcp-sysinfo/audit.jsonl
Audit verification FAILED: hash chain broken at event 847 (seq=847)
```

### Append-Only Writes

The audit system uses `O_APPEND` flag which ensures:

- Writes are atomic at the OS level
- Each write appends to the end of the file
- No overwrites possible even with concurrent access

## Events Logged

### Tool Invocations

Every MCP tool call is logged:

```json
{
  "action": "tools/call",
  "resource": "get_cpu_info",
  "identity": "user@example.com",
  "params": {"detailed": true},
  "result": "success",
  "duration_ns": 15000000
}
```

### Authentication Events

When using HTTP transport with OAuth/OIDC:

```json
{
  "action": "auth/token_validation",
  "identity": "user@example.com",
  "client_ip": "192.168.1.100",
  "result": "success",
  "metadata": {
    "client_id": "mcp-client",
    "scopes": ["core", "logs"]
  }
}
```

### Failed Authentication

```json
{
  "action": "auth/token_validation",
  "client_ip": "192.168.1.100",
  "result": "denied",
  "metadata": {
    "error": "token expired"
  }
}
```

## File Rotation

When the audit file reaches `--audit-max-file-size`:

1. Current file is flushed and synced
2. File is renamed with timestamp: `audit.jsonl.20240115-103045`
3. Rotated file is compressed to `.gz` in background
4. New empty file is created
5. Old files beyond `--audit-max-files` are deleted

```bash
$ ls -la /var/log/mcp-sysinfo/
-rw-r----- 1 root root  15M Jan 15 10:30 audit.jsonl
-rw-r----- 1 root root 2.5M Jan 14 23:45 audit.jsonl.20240114-234500.gz
-rw-r----- 1 root root 2.4M Jan 14 12:30 audit.jsonl.20240114-123000.gz
```

## Performance Modes

### Default (Async Buffered)

Best for most deployments:

```bash
mcp-sysinfo --audit \
    --audit-buffer-size 100 \
    --audit-flush-interval 5s
```

- Events are buffered in memory
- Flushed every 5 seconds or when buffer fills
- Very low latency impact on tool calls

### High-Throughput

For high-volume environments:

```bash
mcp-sysinfo --audit \
    --audit-buffer-size 1000 \
    --audit-flush-interval 30s
```

- Larger buffer reduces disk I/O
- Longer flush interval batches more writes
- Risk: more events lost on crash

### High-Integrity

For compliance-critical deployments:

```bash
mcp-sysinfo --audit \
    --audit-buffer-size 0 \
    --audit-sync-write
```

- Synchronous writes (no buffering)
- fsync after each event
- Maximum durability, higher latency

## Provider Architecture

The audit system uses a provider interface for extensibility:

```go
type Provider interface {
    Name() string
    Write(ctx context.Context, event *Event) error
    Flush(ctx context.Context) error
    Close() error
    Verify(ctx context.Context) (int, error)
}
```

### Built-in Providers

- **default**: Local file-based JSON Lines with hash chain

### Custom Providers

Implement the `Provider` interface for:

- Remote SIEM systems (Splunk, Elastic, etc.)
- Cloud logging (CloudWatch, Stackdriver, etc.)
- Blockchain-based immutable storage
- Custom compliance systems

Register with:

```go
audit.RegisterProvider("myProvider", NewMyProvider)
```

## Programmatic Usage

### Basic Logging

```go
import "github.com/levantar-ai/mcp-sysinfo/internal/audit"

// Enable audit logging
audit.Enable("/var/log/audit.jsonl")

// Log an event
audit.Log(audit.Event{
    Action:   "tools/call",
    Resource: "get_cpu_info",
    Identity: "user@example.com",
    Result:   audit.ResultSuccess,
})

// Convenience functions
audit.LogSuccess("tools/call", "get_cpu_info", "user@example.com")
audit.LogError("tools/call", "get_cpu_info", "user@example.com", err)
audit.LogDenied("tools/call", "get_sensitive", "user@example.com", "scope required")
```

### Event Builder

```go
err := audit.NewEvent("tools/call").
    WithResource("get_cpu_info").
    WithIdentity("user@example.com").
    WithClientIP("192.168.1.100").
    WithParams(map[string]interface{}{"detailed": true}).
    WithDuration(15 * time.Millisecond).
    Success()
```

### Tool Call Logging

```go
audit.LogToolCall(
    "get_cpu_info",                    // tool name
    map[string]interface{}{"x": 1},    // params
    "user@example.com",                // identity
    "192.168.1.100",                   // client IP
    15*time.Millisecond,               // duration
    audit.ResultSuccess,               // result
    "",                                // error message
)
```

### Authentication Logging

```go
audit.LogAuth(
    "login",                           // action
    "user@example.com",                // identity
    "192.168.1.100",                   // client IP
    audit.ResultSuccess,               // result
    map[string]interface{}{            // metadata
        "method": "oauth",
    },
)
```

## Security Considerations

### File Permissions

The audit file is created with mode `0640`:

```bash
# Recommended ownership
chown root:adm /var/log/mcp-sysinfo/audit.jsonl
chmod 640 /var/log/mcp-sysinfo/audit.jsonl
```

### Directory Permissions

The audit directory is created with mode `0750`:

```bash
chown root:adm /var/log/mcp-sysinfo
chmod 750 /var/log/mcp-sysinfo
```

### Log Forwarding

For production deployments, forward audit logs to a centralized SIEM:

```bash
# Example: Forward with rsyslog
$ModLoad imfile
$InputFileName /var/log/mcp-sysinfo/audit.jsonl
$InputFileTag mcp-audit:
$InputFileStateFile mcp-audit-state
$InputFileSeverity info
$InputFileFacility local0
$InputRunFileMonitor
```

### Sensitive Data

The audit system logs:
- Tool names and parameters (may contain queries)
- User identities and IPs
- Error messages

Consider:
- Enabling redaction (`--redact`) to sanitize parameters
- Encrypting audit logs at rest
- Restricting access to audit files

## Compliance

The audit system supports:

- **SOC 2 Type II**: Complete audit trail of all access
- **ISO 27001**: Security event logging requirements
- **HIPAA**: Access logging for protected health information
- **PCI-DSS**: Audit trail requirements for payment systems
- **GDPR**: Data access logging requirements

### Retention

Configure retention based on compliance requirements:

| Standard | Minimum Retention |
|----------|------------------|
| SOC 2 | 1 year |
| PCI-DSS | 1 year |
| HIPAA | 6 years |
| GDPR | Duration of processing + 3 years |

Set `--audit-max-files` appropriately for your retention policy.

## Troubleshooting

### Audit File Not Created

```bash
# Check directory exists and is writable
ls -la /var/log/mcp-sysinfo/

# Check process has write permission
sudo -u mcp-user touch /var/log/mcp-sysinfo/test
```

### Verification Fails

```bash
# Check for file corruption
file /var/log/mcp-sysinfo/audit.jsonl

# Try to parse each line
cat /var/log/mcp-sysinfo/audit.jsonl | jq -c '.' > /dev/null
```

### High Latency

```bash
# Use async mode instead of sync
mcp-sysinfo --audit --audit-buffer-size 100

# Don't use --audit-sync-write in production unless required
```

### Missing Events

If events are missing after crash:

1. Events in buffer may be lost
2. Use `--audit-sync-write` for guaranteed durability
3. Or use `--audit-buffer-size 0` for synchronous writes
