# Security Architecture

MCP System Info is a **security product first**, diagnostics tool second. Every design decision prioritizes defense-in-depth, minimal attack surface, and explicit trust boundaries.

## Threat Model

### What We Protect Against

| Threat | Mitigation |
|--------|------------|
| Credential/secret exfiltration via queries | Query classification + redaction + disabled-by-default |
| Unauthorized remote access | Localhost-only default + explicit remote enablement |
| Resource exhaustion / DoS | Hard limits on output size, runtime, concurrency |
| Replay attacks | JWT with short TTL + nonce + audience binding |
| Privilege escalation | Read-only operations + no shell execution |
| Data exfil via verbose output | Output size caps + field-level redaction |

### What This Is NOT

- NOT a replacement for network segmentation
- NOT a way to grant shell access to AI agents
- Requires proper host-level security as foundation

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

---

## Authentication

### JWT Authentication

Required for HTTP transport. Optional but recommended for socket transport.

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

    # Replay prevention
    require_jti: true      # Require unique token ID
    jti_cache_ttl: 600     # Cache JTI for 10 minutes
```

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
```

For file-based keys, use a sidecar or cron job to rotate:

```bash
# Key rotation script (run via cron/systemd timer)
mv /etc/mcp-sysinfo/jwt-public.pem /etc/mcp-sysinfo/jwt-public.pem.old
cp /secure/new-jwt-public.pem /etc/mcp-sysinfo/jwt-public.pem
systemctl reload mcp-sysinfo
```

---

## Query Classification & Scopes

### Query Categories

| Scope | Description | Default | Risk Level |
|-------|-------------|---------|------------|
| `core` | CPU, memory, disk, network, processes, uptime, temperature | Enabled | Low |
| `logs` | System logs, application logs, kernel logs | Enabled | Medium |
| `hooks` | Scheduled tasks, kernel modules, network config, mounts | Enabled | Medium |
| `sbom` | Package lists, container images, dependencies | Enabled | Medium |
| `sensitive` | Auth logs, env vars, user accounts, SSH config, sudo config | **Disabled** | High |

### Sensitive Queries (Disabled by Default)

These queries can expose credentials, PII, or security-relevant configuration:

| Query | Risk | Data Exposed |
|-------|------|--------------|
| `get_env_vars` | Critical | AWS keys, DB passwords, API tokens |
| `get_auth_logs` | High | Usernames, IPs, access patterns |
| `get_event_log` (Security) | High | Authentication events, policy changes |
| `get_user_accounts` | High | Local users, groups, shell paths |
| `get_sudo_config` | High | Privilege escalation paths |
| `get_ssh_config` | High | Auth methods, allowed keys, forwarding |
| `get_open_files` | Medium | File paths, potential content via path |

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

  logs:
    - get_journal_logs
    - get_syslog
    - get_app_logs
    - get_kernel_logs

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
    - get_env_vars  # Only if explicitly allowed
```

---

## Output Security

### Automatic Redaction

Sensitive patterns are redacted in ALL query output:

```yaml
redaction:
  enabled: true

  patterns:
    # Credentials
    - name: aws_key
      pattern: '(?i)(AKIA[0-9A-Z]{16})'
      replacement: "[REDACTED:AWS_KEY]"

    - name: password_field
      pattern: '(?i)(password|passwd|secret|token|key)\s*[=:]\s*\S+'
      replacement: "$1=[REDACTED]"

    - name: bearer_token
      pattern: '(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*'
      replacement: "Bearer [REDACTED]"

    - name: private_key
      pattern: '-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----'
      replacement: "[REDACTED:PRIVATE_KEY]"

    - name: connection_string
      pattern: '(?i)(mysql|postgres|mongodb|redis)://[^@]+@'
      replacement: "$1://[REDACTED]@"

  # Field-level redaction (in structured output)
  fields:
    - "*.password"
    - "*.secret"
    - "*.token"
    - "*.api_key"
    - "env.AWS_*"
    - "env.DATABASE_*"
```

### Output Limits

Hard caps to prevent data exfiltration via verbose queries:

```yaml
limits:
  # Per-query limits
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

### Per-Query Budgets

```yaml
resources:
  # Query execution limits
  query_timeout: 5000           # 5 seconds max per query
  query_cpu_percent: 10         # Max CPU during query
  query_memory_mb: 50           # Max additional memory

  # Concurrent execution
  max_concurrent_queries: 5     # Max parallel queries

  # Rate limiting
  rate_limit:
    requests_per_minute: 60
    requests_per_hour: 1000
    burst: 10
```

### Query Impact Classification

| Impact | Timeout | CPU | Memory | Concurrency |
|--------|---------|-----|--------|-------------|
| Minimal | 100ms | 1% | 1MB | Unlimited |
| Low | 1s | 5% | 10MB | 10 |
| Medium | 5s | 10% | 50MB | 3 |
| High | - | - | - | **Blocked** |

Queries self-declare their impact level. Server enforces limits.

---

## Audit Logging

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
    "subject": "CN=teleport-proxy.example.com",
    "jwt_sub": "user@example.com"
  },
  "result": "success",
  "duration_ms": 12,
  "output_bytes": 2048
}
```

### Audit Events

| Event | Logged Data |
|-------|-------------|
| `auth_success` | Client identity, scopes granted |
| `auth_failure` | Reason, client IP, attempted identity |
| `query` | Query name, params, result, duration |
| `query_denied` | Query, reason (scope, disabled, rate limit) |
| `redaction` | Query, field/pattern redacted (not the data) |
| `limit_exceeded` | Limit type, query, threshold |
| `config_reload` | Changed settings |

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
  log_redactions: true         # Log what was redacted (not values)

  # Syslog forwarding
  syslog:
    enabled: true
    facility: auth
    tag: mcp-sysinfo
```

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

### Recommended

- [ ] JWKS endpoint for key rotation
- [ ] JTI (token ID) caching for replay prevention
- [ ] Syslog forwarding to SIEM
- [ ] File integrity monitoring on config files
- [ ] Separate service account with minimal privileges
- [ ] Network segmentation (management VLAN)

### Periodic Review

- [ ] Monthly: Review audit logs for anomalies
- [ ] Monthly: Rotate JWT signing keys
- [ ] Quarterly: Review query allowlists
- [ ] Quarterly: Update redaction patterns

---

## Comparison: Default vs Production Config

| Setting | Default | Production |
|---------|---------|------------|
| Transport | stdio | https or socket |
| Network bind | N/A | 127.0.0.1 or internal only |
| TLS | N/A | mTLS required |
| JWT auth | Disabled | Required |
| JWT TTL | N/A | 300s max |
| Sensitive queries | Disabled | Disabled (or explicit allow) |
| Redaction | Enabled | Enabled + custom patterns |
| Audit logging | Disabled | Enabled + syslog forward |
| Max output | 1MB | Per-environment |
| Rate limit | None | 60/min |

---

## Security Contacts

Report security vulnerabilities to: security@example.com

PGP key for encrypted reports: [link to key]
