# Security Architecture

MCP System Info is a **security product first**, diagnostics tool second. Every design decision prioritizes defense-in-depth, minimal attack surface, and explicit trust boundaries.

## Threat Model

### What We Protect Against

| Threat | Mitigation |
|--------|------------|
| Credential/secret exfiltration via queries | Query classification + redaction + disabled-by-default |
| Unauthorized remote access | Localhost-only default + explicit remote enablement |
| Resource exhaustion / DoS | Hard limits on output size, runtime, concurrency |
| Replay attacks | JWT with short TTL + JTI cache + audience binding |
| Privilege escalation | Read-only operations, no arbitrary command execution |
| Data exfil via verbose output | Output size caps + field-level redaction |
| Arbitrary command injection | Allowlisted commands only, parameterized, no raw user input |

### What This Is NOT

- NOT a replacement for network segmentation
- NOT a way to grant shell access to AI agents
- NOT a defense against a compromised host (requires host-level security as foundation)
- NOT a secrets manager (use Vault, AWS Secrets Manager, etc.)

### Command Execution Model

**We do NOT provide arbitrary shell access.** The server executes a fixed set of allowlisted system commands (`ps`, `netstat`, `df`, etc.) with:

- **No raw command strings** - Commands are hardcoded, not constructed from input
- **Parameterized arguments only** - User input maps to structured parameters, never concatenated into commands
- **No shell interpolation** - Commands executed directly via `exec`, not through a shell
- **Output parsing, not passthrough** - Raw command output is parsed into structured JSON
- **Locale hardening** - Commands run with `LC_ALL=C` to ensure consistent, predictable output across systems
- **No recursive filesystem searches** - No grep/find/recursive scan primitives exist in the API

```
User Input              What Happens                      What Does NOT Happen
─────────────────────────────────────────────────────────────────────────────────
get_processes           exec(["ps", "aux"])               sh -c "ps aux"
  sort_by: "cpu"        → parsed, sorted by CPU field     user input in command
  limit: 10             → array sliced to 10              ; rm -rf / injection
```

---

## Transport Security

### Transport Options (Pick One)

| Transport | Default | Use Case | Security Level |
|-----------|---------|----------|----------------|
| **stdio** | Yes | Local MCP client (Claude Desktop, etc.) | Highest - no network |
| **Unix socket** | No | Local multi-process, containers | High - filesystem ACLs |
| **Named pipe** | No | Windows local IPC | High - Windows ACLs |
| **HTTP + mTLS** | No | Remote access, Teleport, bastion | High - mutual TLS required |
| **SSH tunnel** | No | Ad-hoc remote access | High - SSH provides auth |

### Default: stdio (No Network Exposure)

```yaml
# config.yaml
transport: stdio  # Default - no network listener
```

The server reads from stdin and writes to stdout. No TCP/UDP ports opened. This is the **only** transport enabled by default.

**stdio Security Model**: Authentication is not required because OS-level controls apply:
- Only processes that can spawn the binary can interact with it
- Parent process controls who can write to stdin / read from stdout
- **Recommendation**: Run under a dedicated service account (`mcp-sysinfo`) and restrict binary execution via file permissions (`chmod 750`, owned by `root:mcp-sysinfo`)

### Unix Socket (Linux/macOS)

```yaml
transport: unix
socket:
  path: /var/run/mcp-sysinfo.sock
  mode: 0600  # Owner read/write only
  owner: mcp-sysinfo
  group: mcp-sysinfo
```

Socket permissions enforced by filesystem. Only processes with access to the socket file can connect.

### Named Pipe (Windows)

```yaml
transport: pipe
pipe:
  name: \\.\pipe\mcp-sysinfo
  acl: "D:(A;;GA;;;BA)"  # Administrators only
```

### HTTP + mTLS (Remote Access)

```yaml
transport: https
tls:
  bind: 127.0.0.1:8443      # Localhost only by default
  # bind: 0.0.0.0:8443      # Explicit opt-in for remote

  # Server certificate
  cert: /etc/mcp-sysinfo/server.crt
  key: /etc/mcp-sysinfo/server.key

  # Client authentication (REQUIRED for remote)
  client_ca: /etc/mcp-sysinfo/client-ca.crt
  require_client_cert: true  # mTLS enforced

  # Allowed client certificate subjects (allowlist)
  allowed_subjects:
    - "CN=teleport-proxy.example.com"
    - "CN=bastion.internal"
```

**No plaintext HTTP. Ever.** The server refuses to start with `transport: http`.

### Network Exposure Guardrails

The server enforces safety checks on bind address:

| Bind Address | Requirements |
|--------------|--------------|
| `127.0.0.1` / `::1` | mTLS recommended, auth recommended |
| `0.0.0.0` / `::` | **mTLS required** + **auth required** (server refuses otherwise) |
| Private IP | mTLS required, auth required |

```yaml
# This configuration will FAIL to start:
transport: https
tls:
  bind: 0.0.0.0:8443
  require_client_cert: false  # ERROR: must be true for non-localhost
auth:
  enabled: false              # ERROR: must be true for non-localhost
```

This prevents accidental wide-open exposure.

---

## Authentication

### Authentication Requirements by Transport

| Transport | Auth Required | Default |
|-----------|---------------|---------|
| stdio | No | Disabled |
| unix socket | No | Disabled (recommended: enable) |
| named pipe | No | Disabled (recommended: enable) |
| https | **Yes** | **Required** (server refuses to start without) |

### JWT Authentication

```yaml
auth:
  enabled: true

  jwt:
    # Issuer validation
    issuer: "https://auth.example.com"
    audience: "mcp-sysinfo"

    # Key source (pick one)
    jwks_uri: "https://auth.example.com/.well-known/jwks.json"
    # OR
    public_key: /etc/mcp-sysinfo/jwt-public.pem
    # OR (not recommended for production)
    secret: ${MCP_JWT_SECRET}  # HMAC - env var only, never in file

    # Token constraints
    max_ttl: 300           # 5 minutes max
    require_exp: true      # Reject tokens without expiry
    require_iat: true      # Reject tokens without issued-at
    clock_skew: 30         # Seconds of allowed clock drift

    # Replay prevention (JTI caching)
    require_jti: true            # Require unique token ID
    jti_cache_ttl: 600           # Cache JTI for 10 minutes
    jti_cache_max_entries: 10000 # Max cached JTIs (LRU eviction)
    jti_cache_max_memory_mb: 10  # Memory cap for JTI cache
```

### JTI Cache Considerations

The JTI (JWT ID) cache prevents token replay but introduces statefulness:

| Deployment | Behavior |
|------------|----------|
| Single instance | JTI cache is local; replay prevention works |
| Multiple instances | Each instance has separate cache; token can replay to different instance |
| Clustered (Redis) | Shared cache; replay prevention works across instances |

```yaml
auth:
  jwt:
    jti_cache:
      backend: memory          # memory (default) or redis
      # Redis backend for clustered deployments
      redis:
        addr: "redis:6379"
        password: ${REDIS_PASSWORD}
        db: 0
        key_prefix: "mcp-sysinfo:jti:"
```

**DoS protection**: The cache has bounded size (`jti_cache_max_entries`) with LRU eviction. Attackers cannot bloat the cache by spamming unique JTIs.

### JWT Claims to Scopes

```yaml
auth:
  scope_claim: "mcp_scopes"  # Claim containing scopes array

  # Alternative: derive scopes from roles
  role_claim: "roles"
  role_mapping:
    admin: ["core", "logs", "hooks", "sbom", "sensitive"]
    operator: ["core", "logs", "hooks"]
    viewer: ["core"]
```

### Example JWT Payload

```json
{
  "iss": "https://auth.example.com",
  "aud": "mcp-sysinfo",
  "sub": "user@example.com",
  "exp": 1702400000,
  "iat": 1702399700,
  "jti": "unique-token-id-12345",
  "mcp_scopes": ["core", "logs"]
}
```

### Key Rotation

```yaml
auth:
  jwt:
    jwks_uri: "https://auth.example.com/.well-known/jwks.json"
    jwks_refresh_interval: 3600  # Re-fetch keys hourly
    jwks_min_refresh: 300        # But not more than every 5 min

    # Startup behavior when JWKS is unreachable
    jwks_startup_policy: fail_closed  # DEFAULT: fail_closed

    # Options:
    # - fail_closed: Refuse to start if JWKS unreachable (RECOMMENDED)
    # - fail_open_cached: Start with cached keys if available, fail if no cache
    #   cache_max_age_hours: 24  # Max age of cached keys to accept
```

**Default: fail_closed**. The server refuses to start if it cannot fetch signing keys. This ensures no requests are accepted with unverifiable tokens.

For high-availability deployments, `fail_open_cached` allows startup with previously-cached keys (up to `cache_max_age_hours` old), but logs a warning and continues attempting JWKS refresh.

For file-based keys, use a sidecar or cron job to rotate:

```bash
# Key rotation script (run via cron/systemd timer)
mv /etc/mcp-sysinfo/jwt-public.pem /etc/mcp-sysinfo/jwt-public.pem.old
cp /secure/new-jwt-public.pem /etc/mcp-sysinfo/jwt-public.pem
systemctl reload mcp-sysinfo
```

---

## Rate Limiting

### Rate Limit Keying

Rate limits are enforced **per-identity**, not globally:

```yaml
rate_limit:
  # Identity key (in order of precedence)
  # 1. JWT subject claim (jwt_sub)
  # 2. mTLS certificate subject (CN)
  # 3. Client IP (fallback)
  key_by: ["jwt_sub", "mtls_subject", "ip"]

  # Global limits (across all identities)
  global:
    requests_per_second: 100
    burst: 50

  # Per-identity limits
  per_identity:
    requests_per_minute: 60
    requests_per_hour: 1000
    burst: 10

  # Stricter limits for sensitive/log queries
  sensitive_queries:
    requests_per_minute: 10
    requests_per_hour: 100

  log_queries:
    requests_per_minute: 20
    requests_per_hour: 200
```

### Rate Limit Response

When rate limited, the server returns:

```json
{
  "error": "rate_limited",
  "retry_after_seconds": 45,
  "limit": "per_identity:requests_per_minute",
  "identity": "user@example.com"
}
```

---

## Query Classification & Scopes

### Query Categories

| Scope | Description | Default | Risk Level |
|-------|-------------|---------|------------|
| `core` | CPU, memory, disk, network, processes, uptime, temperature | Enabled | Low |
| `logs_system` | Kernel logs, systemd journal, syslog | Enabled | Medium |
| `logs_app` | Application-specific logs (often contain secrets/PII) | Enabled | Medium-High |
| `hooks` | Scheduled tasks, kernel modules, network config, mounts | Enabled | Medium |
| `sbom` | Package lists, container images, dependencies | Enabled | Medium |
| `sensitive` | Auth logs, env vars, user accounts, SSH/sudo config, open files | **Disabled** | High |

**Note on logs**: Logs are enabled by default but are **time-bounded** (max 24h) and **truncated** (max 1000 lines). Application logs (`logs_app`) are separated because they often contain leaked credentials, PII, or tokens. In high-sensitivity environments, disable `logs_app` or restrict to specific paths:

```yaml
scopes:
  logs_app:
    enabled: true
    allowed_paths:
      - /var/log/nginx/*.log
      - /var/log/myapp/*.log
    denied_paths:
      - /var/log/myapp/debug.log  # Contains request bodies
```

### Sensitive Queries (Disabled by Default)

These queries can expose credentials, PII, or security-relevant configuration:

| Query | Risk | Data Exposed | Default |
|-------|------|--------------|---------|
| `get_env_vars` | Critical | AWS keys, DB passwords, API tokens | **Always denied** |
| `get_auth_logs` | High | Usernames, IPs, access patterns | Disabled |
| `get_event_log` (Security) | High | Authentication events, policy changes | Disabled |
| `get_user_accounts` | High | Local users, groups, shell paths | Disabled |
| `get_sudo_config` | High | Privilege escalation paths | Disabled |
| `get_ssh_config` | High | Auth methods, allowed keys, forwarding | Disabled |
| `get_open_files` | High | File paths, process details, potential content | Disabled |

**Note**: `get_open_files` is in the `sensitive` scope (not `hooks`) because file paths can reveal sensitive information and can be used for reconnaissance. Even with parameter requirements, it remains high-risk.

### Parameter Requirements for Dangerous Queries

Some queries require parameters to prevent bulk data extraction:

```yaml
queries:
  parameter_requirements:
    # get_open_files cannot list everything - must be targeted
    get_open_files:
      require_one_of: ["pid", "path_prefix", "user"]
      deny_all: true  # No "list all open files"

    # get_env_vars is too dangerous - always denied
    get_env_vars:
      always_deny: true
      message: "Environment variables may contain secrets. Use a secrets manager."

    # get_auth_logs must be time-bounded
    get_auth_logs:
      require: ["max_age_hours"]
      max_values:
        max_age_hours: 24  # Cannot request more than 24h
```

### Enabling Sensitive Queries

Requires explicit configuration AND appropriate JWT scope:

```yaml
queries:
  sensitive:
    enabled: true
    # Allowed queries (allowlist - not all sensitive queries)
    allow:
      - get_user_accounts
      - get_auth_logs
    # Still blocked even with sensitive scope
    deny:
      - get_env_vars  # Too dangerous, use secrets manager
```

### Query-to-Scope Mapping

```yaml
scopes:
  core:
    - get_cpu_info
    - get_memory_info
    - get_disk_info
    - get_network_info
    - get_processes
    - get_uptime
    - get_temperature

  logs_system:
    - get_journal_logs
    - get_syslog
    - get_kernel_logs

  logs_app:
    - get_app_logs

  hooks:
    - get_cron_jobs
    - get_kernel_modules
    - get_listening_ports
    - get_dns_config
    # ... etc

  sensitive:
    - get_auth_logs
    - get_event_log
    - get_user_accounts
    - get_sudo_config
    - get_ssh_config
    - get_open_files  # Always sensitive, even with params
```

---

## Output Security

### Redaction Strategy

Redaction is **best-effort defense-in-depth**, not a guarantee. It combines multiple layers:

```
                    ┌─────────────────────────────────────┐
                    │          Query Output               │
                    └─────────────────────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │  1. Structured Field Redaction │
                    │     (*.password, *.token, etc) │
                    └───────────────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │  2. Regex Pattern Redaction    │
                    │     (AWS keys, connection str) │
                    │     Bounded: max 1MB scanned   │
                    └───────────────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │  3. Output Size Limits         │
                    │     (Truncate if too large)    │
                    └───────────────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │       Final Output             │
                    └───────────────────────────────┘
```

### Redaction Configuration

```yaml
redaction:
  enabled: true

  # 1. Structured field redaction (fast, reliable)
  fields:
    - "*.password"
    - "*.secret"
    - "*.token"
    - "*.api_key"
    - "*.private_key"
    - "env.AWS_*"
    - "env.DATABASE_*"
    - "env.*_PASSWORD"
    - "env.*_SECRET"
    - "env.*_TOKEN"

  # 2. Regex pattern redaction (slower, best-effort)
  patterns:
    - name: aws_access_key
      pattern: '(?i)(AKIA[0-9A-Z]{16})'
      replacement: "[REDACTED:AWS_ACCESS_KEY]"

    - name: aws_secret_key
      pattern: '(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}'
      replacement: "aws_secret_access_key=[REDACTED]"

    - name: generic_secret
      pattern: '(?i)(password|passwd|secret|token|apikey|api_key)\s*[=:]\s*\S+'
      replacement: "$1=[REDACTED]"

    - name: bearer_token
      pattern: '(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*'
      replacement: "Bearer [REDACTED]"

    - name: private_key_block
      pattern: '-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----'
      replacement: "[REDACTED:PRIVATE_KEY]"

    - name: connection_string
      pattern: '(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^@\s]+@'
      replacement: "$1://[REDACTED]@"

  # Redaction limits (prevent CPU exhaustion)
  limits:
    max_input_bytes: 1048576    # Only scan first 1MB
    max_regex_time_ms: 100      # Timeout per pattern
    fail_action: truncate       # truncate | pass | error
```

**Important**: Redaction is best-effort. Secrets can appear in unexpected formats. Defense-in-depth means:
1. Don't enable `get_env_vars`
2. Use strict output limits
3. Limit log query time windows
4. Monitor audit logs for sensitive data access

### Output Limits

Hard caps to prevent data exfiltration:

```yaml
limits:
  # Per-query limits (HARD ENFORCEMENT)
  max_output_bytes: 1048576     # 1 MB max response
  max_output_lines: 10000       # 10K lines max
  max_array_items: 1000         # Max items in any array

  # Log-specific limits
  logs:
    max_lines: 1000             # Max log lines per query
    max_age_hours: 24           # Only last 24h of logs
    max_bytes_per_file: 10485760  # 10MB per log file

  # Process list limits
  processes:
    max_count: 500              # Max processes returned
    max_cmdline_length: 1024    # Truncate long command lines
```

---

## Resource Limits

### Enforcement Levels

| Limit Type | Enforcement | How |
|------------|-------------|-----|
| Query timeout | **Hard** | Context cancellation |
| Max output bytes | **Hard** | Truncation |
| Max concurrent queries | **Hard** | Semaphore |
| Rate limiting | **Hard** | Request rejection |
| CPU percent | Best-effort | `nice`/priority (platform-dependent) |
| Memory | Best-effort | Monitoring + abort (platform-dependent) |

### Configuration

```yaml
resources:
  # HARD LIMITS (always enforced)
  query_timeout_ms: 5000        # 5 seconds max per query
  max_output_bytes: 1048576     # 1 MB max output
  max_concurrent_queries: 5     # Max parallel queries

  # BEST-EFFORT LIMITS (platform-dependent)
  nice_level: 10                # Unix nice value (lower priority)
  io_priority: idle             # Linux: idle, best-effort, realtime
  memory_limit_mb: 100          # Soft limit, monitored

  # Per-impact-level timeouts
  timeouts:
    minimal: 100      # ms
    low: 1000         # ms
    medium: 5000      # ms
    high: 0           # blocked
```

### Query Impact Classification

| Impact | Timeout | Concurrency | Example Queries |
|--------|---------|-------------|-----------------|
| Minimal | 100ms | Unlimited | `get_uptime`, `get_cpu_info` |
| Low | 1s | 10 | `get_memory_info`, `get_disk_info` |
| Medium | 5s | 3 | `get_processes`, `get_journal_logs` |
| High | - | **Blocked** | Full filesystem scans, unbounded searches |

Queries self-declare their impact level. Server enforces limits.

---

## Audit Logging

### Default: Enabled

Audit logging is **enabled by default** (local file, low volume). This aligns with "security product first" positioning.

```yaml
audit:
  enabled: true  # DEFAULT: true
  path: /var/log/mcp-sysinfo/audit.jsonl
```

### Audit Log Format

JSON Lines format, one event per line:

```json
{
  "ts": "2024-12-12T10:30:45.123Z",
  "event": "query",
  "query": "get_cpu_info",
  "params": {"per_cpu": true},
  "client": {
    "transport": "https",
    "ip": "10.0.1.50",
    "mtls_subject": "CN=teleport-proxy.example.com",
    "jwt_sub": "user@example.com",
    "scopes": ["core", "logs"]
  },
  "result": "success",
  "duration_ms": 12,
  "output_bytes": 2048,
  "redactions": 0
}
```

### Audit Events

| Event | Logged Data |
|-------|-------------|
| `startup` | Config hash, version, transport, enabled features |
| `auth_success` | Client identity, scopes granted |
| `auth_failure` | Reason, client IP, attempted identity |
| `query` | Query name, params, result, duration, output size |
| `query_denied` | Query, reason (scope, disabled, rate limit, missing params) |
| `redaction` | Query, count of redactions (not the values) |
| `rate_limited` | Identity, limit exceeded, retry_after |
| `limit_exceeded` | Limit type, query, threshold |
| `config_reload` | Changed settings (not sensitive values) |
| `shutdown` | Reason, uptime |

### Audit Configuration

```yaml
audit:
  enabled: true
  path: /var/log/mcp-sysinfo/audit.jsonl

  # Rotation
  max_size_mb: 100
  max_files: 10
  compress: true

  # What to log
  log_params: true             # Log query parameters
  log_output_size: true        # Log response size
  log_client_ip: true          # Log client IP
  log_redaction_count: true    # Log how many redactions (not values)

  # Privacy controls
  anonymize_identity: false    # Set true to hash jwt_sub/client identifiers
  identity_hash_salt: ${AUDIT_HASH_SALT}  # Required if anonymize_identity=true

  # Integrity (optional)
  hmac_signing: false          # Sign each audit line with HMAC
  hmac_key: ${AUDIT_HMAC_KEY}  # Required if hmac_signing=true

  # Syslog forwarding
  syslog:
    enabled: false             # Enable for production
    facility: auth
    tag: mcp-sysinfo
    network: udp
    addr: "syslog.internal:514"
```

### Audit Log Security

**Privacy**: If audit logs may be shared or analyzed by third parties, enable `anonymize_identity` to hash user identifiers (one-way, salted).

**Tamper resistance**:
- **Append-only**: Configure the log directory with append-only attributes (`chattr +a` on Linux) or use an append-only filesystem
- **Forward immediately**: Enable syslog forwarding to a remote SIEM; local logs can be tampered with by a compromised host
- **HMAC signing** (optional): Each audit line includes an HMAC, creating a lightweight integrity chain. Tampering breaks the chain.

```json
{
  "ts": "2024-12-12T10:30:45.123Z",
  "event": "query",
  ...
  "_hmac": "sha256:a1b2c3d4..."
}
```

---

## Configuration Integrity

### Config File Security

```yaml
# Required: config file must have restricted permissions
# Server refuses to start if permissions are too open

config:
  # Linux/macOS: file must be owned by root or service user
  # and not world-readable (max 0640)
  required_mode: "0640"
  required_owner: ["root", "mcp-sysinfo"]
```

The server checks config file permissions at startup:

```
ERROR: Config file /etc/mcp-sysinfo/config.yaml has mode 0644, required 0640 or stricter
ERROR: Config file owned by nobody, required root or mcp-sysinfo
```

### Environment Variable Handling

```yaml
config:
  # Environment variables can override SOME settings
  env_override:
    allowed:
      - MCP_LOG_LEVEL
      - MCP_BIND_ADDRESS  # Only for non-production
    denied:
      - MCP_JWT_SECRET    # Must be in file or JWKS
      - MCP_DISABLE_AUTH  # Cannot disable auth via env
```

### Config Reload

```yaml
config:
  # Hot reload behavior
  reload:
    enabled: true
    signal: SIGHUP
    # What can be reloaded without restart
    hot_reloadable:
      - rate_limit.*
      - audit.*
      - redaction.patterns
    # What requires restart
    requires_restart:
      - transport
      - auth.jwt.issuer
      - auth.jwt.audience
      - tls.*
```

### Fail-Closed Behavior

The server refuses to start if security configuration is invalid:

| Condition | Behavior |
|-----------|----------|
| `transport: https` but no TLS cert | **Refuse to start** |
| `auth.enabled: true` but no keys configured | **Refuse to start** |
| Config file world-readable | **Refuse to start** |
| JWKS URI unreachable at startup | **Refuse to start** (default) or use cached keys (if configured) |
| Invalid redaction regex | **Refuse to start** |
| `bind: 0.0.0.0` without mTLS + auth | **Refuse to start** |

```yaml
config:
  # Startup behavior
  fail_closed: true  # DEFAULT: true
  # If false, logs warnings but continues (NOT RECOMMENDED)
```

---

## Supply Chain Security

### Signed Releases

All releases are signed:

```bash
# Verify signature (cosign)
cosign verify-blob \
  --signature mcp-sysinfo-linux-amd64.sig \
  --certificate mcp-sysinfo-linux-amd64.crt \
  mcp-sysinfo-linux-amd64

# Verify signature (GPG)
gpg --verify mcp-sysinfo-linux-amd64.asc mcp-sysinfo-linux-amd64
```

### SBOM for This Binary

Each release includes an SBOM (Software Bill of Materials):

```bash
# CycloneDX format
mcp-sysinfo-linux-amd64.cdx.json

# SPDX format
mcp-sysinfo-linux-amd64.spdx.json
```

### Reproducible Builds

Builds are reproducible from source:

```bash
# Verify build
git checkout v1.0.0
go build -trimpath -ldflags="-s -w" -o mcp-sysinfo ./cmd/mcp-sysinfo
sha256sum mcp-sysinfo
# Should match published checksum
```

### Update Policy

- **No auto-update**: The binary never phones home or updates itself
- **No telemetry**: No usage data collected
- **Explicit upgrades only**: Operators control when to upgrade

```yaml
# There is no update configuration - by design
```

### Dependency Policy

- **Minimal dependencies**: Only Go standard library where possible
- **Vendored**: All dependencies vendored in repository
- **Audited**: Dependencies reviewed for security issues
- **Pinned**: Exact versions, not ranges

---

## Deployment Models

### Model 1: Local Only (Default)

```
┌──────────────────────────────────────┐
│           Local Machine              │
│  ┌────────────┐    ┌──────────────┐  │
│  │ MCP Client │───▶│ mcp-sysinfo  │  │
│  │ (Claude)   │stdio│   (server)   │  │
│  └────────────┘    └──────────────┘  │
└──────────────────────────────────────┘
```

No network. No auth needed. Filesystem permissions protect the binary.

### Model 2: SSH Tunnel (Ad-hoc Remote)

```
┌─────────────┐      SSH      ┌─────────────────────────────┐
│ Workstation │──────────────▶│       Remote Server         │
│             │               │  ┌──────────────────────┐   │
│ Claude CLI  │═══════════════│▶▶│ mcp-sysinfo (stdio)  │   │
│             │  stdin/stdout │  └──────────────────────┘   │
└─────────────┘               └─────────────────────────────┘
```

```bash
# SSH config enables MCP over SSH
ssh user@server "mcp-sysinfo --transport stdio"
```

SSH provides authentication. Server runs in stdio mode.

### Model 3: Teleport MCP Integration

```
┌─────────────┐         ┌─────────────────┐         ┌─────────────────┐
│ MCP Client  │────────▶│ Teleport Proxy  │────────▶│  Target Host    │
│             │  HTTPS  │                 │  tunnel │                 │
│             │         │ - Auth (SSO)    │         │  mcp-sysinfo    │
│             │         │ - RBAC          │         │  (stdio/socket) │
│             │         │ - Audit         │         │                 │
└─────────────┘         └─────────────────┘         └─────────────────┘
```

Teleport handles:
- SSO authentication (OIDC, SAML, GitHub, etc.)
- RBAC for which hosts/queries are allowed
- Session recording and audit
- Certificate-based identity

Configuration:

```yaml
# teleport role
kind: role
metadata:
  name: mcp-diagnostics
spec:
  allow:
    mcp_servers:
      - labels:
          env: production
        commands:
          - get_cpu_info
          - get_memory_info
          - get_disk_info
          - get_processes
      # Sensitive queries require different role
```

### Model 4: mTLS Direct (Service-to-Service)

```
┌─────────────────┐         mTLS          ┌──────────────────┐
│ Orchestrator    │──────────────────────▶│   Target Host    │
│ (Automation)    │                       │                  │
│                 │  Client Cert          │  mcp-sysinfo     │
│                 │  + JWT in header      │  :8443           │
└─────────────────┘                       └──────────────────┘
```

For automation systems that need to query multiple hosts:

```yaml
# Server config
transport: https
tls:
  bind: 0.0.0.0:8443
  cert: /etc/mcp-sysinfo/server.crt
  key: /etc/mcp-sysinfo/server.key
  client_ca: /etc/mcp-sysinfo/client-ca.crt
  require_client_cert: true

auth:
  enabled: true
  jwt:
    issuer: "https://auth.internal"
    audience: "mcp-sysinfo"
```

---

## Hardening Checklist

### Minimum Production Requirements

- [ ] Non-default transport if remote access needed
- [ ] mTLS enabled with client certificate verification
- [ ] JWT authentication with short TTL (< 5 minutes)
- [ ] Sensitive scope disabled (unless explicitly needed)
- [ ] Audit logging enabled with remote forwarding
- [ ] Resource limits configured
- [ ] Redaction patterns reviewed and extended
- [ ] Bind address restricted (not 0.0.0.0 unless intended)
- [ ] Config file permissions verified (0640 or stricter)

### Recommended

- [ ] JWKS endpoint for key rotation
- [ ] JTI caching with Redis for clustered deployments
- [ ] Syslog forwarding to SIEM
- [ ] File integrity monitoring on config files
- [ ] Separate service account with minimal privileges
- [ ] Network segmentation (management VLAN)
- [ ] Verify release signatures before deployment

### Periodic Review

- [ ] Monthly: Review audit logs for anomalies
- [ ] Monthly: Rotate JWT signing keys
- [ ] Quarterly: Review query allowlists
- [ ] Quarterly: Update redaction patterns
- [ ] On release: Verify signatures, review changelog

---

## Comparison: Default vs Production Config

| Setting | Default | Production |
|---------|---------|------------|
| Transport | stdio | https or socket |
| Network bind | N/A | 127.0.0.1 or internal only |
| TLS | N/A | mTLS required |
| JWT auth | Disabled (stdio) | Required (https) |
| JWT TTL | N/A | 300s max |
| Sensitive queries | Disabled | Disabled (or explicit allow) |
| `logs_system` scope | Enabled | Enabled (time-bounded) |
| `logs_app` scope | Enabled | Review: disable or restrict paths |
| Redaction | Enabled | Enabled + custom patterns |
| Audit logging | **Enabled** | Enabled + syslog forward |
| Audit identity | Plain | Consider `anonymize_identity` |
| Max output | 1MB | Per-environment |
| Rate limit | Per-identity | Per-identity + stricter for sensitive |
| Config file mode | 0640 required | 0640 required |
| JWKS startup | fail_closed | fail_closed (or fail_open_cached for HA) |

---

## Security Contacts

Report security vulnerabilities to: security@example.com

PGP key for encrypted reports: [link to key]

We follow coordinated disclosure. Please allow 90 days for fixes before public disclosure.
