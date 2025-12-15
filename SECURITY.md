# Security Architecture

MCP System Info is a **security product first**, diagnostics tool second. Every design decision prioritizes defense-in-depth, minimal attack surface, and explicit trust boundaries.

> **Legend**: ✅ Implemented | 🚧 Planned | ❌ Not Planned

---

## Threat Model

### What We Protect Against

| Threat | Mitigation | Status |
|--------|------------|--------|
| Credential/secret exfiltration via queries | Query classification + redaction + disabled-by-default | ✅ |
| Unauthorized remote access | Localhost-only default + explicit remote enablement | ✅ |
| Resource exhaustion / DoS | Hard limits on output size, runtime, concurrency | 🚧 Planned |
| Replay attacks | JWT with short TTL + JTI cache + audience binding | 🚧 JTI cache planned |
| Privilege escalation | Read-only operations, no arbitrary command execution | ✅ |
| Data exfil via verbose output | Output size caps + field-level redaction | ✅ Redaction implemented |
| Arbitrary command injection | Allowlisted commands only, parameterized, no raw user input | ✅ |

### What This Is NOT

- NOT a replacement for network segmentation
- NOT a way to grant shell access to AI agents
- NOT a defense against a compromised host (requires host-level security as foundation)
- NOT a secrets manager (use Vault, AWS Secrets Manager, etc.)

### Command Execution Model ✅

**We do NOT provide arbitrary shell access.** The server executes a fixed set of allowlisted system commands (`ps`, `netstat`, `df`, etc.) with:

- **No raw command strings** - Commands are hardcoded, not constructed from input
- **Parameterized arguments only** - User input maps to structured parameters, never concatenated into commands
- **No shell interpolation** - Commands executed directly via `exec`, not through a shell
- **Output parsing, not passthrough** - Raw command output is parsed into structured JSON
- **Locale hardening** - Commands run with `LC_ALL=C` on Unix to ensure consistent output
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

### Transport Options

| Transport | Status | Use Case | Security Level |
|-----------|--------|----------|----------------|
| **stdio** | ✅ | Local MCP client (Claude Desktop, etc.) | Highest - no network |
| **HTTP/HTTPS** | ✅ | Remote access with OAuth/OIDC | High - auth required |
| **Unix socket** | 🚧 | Local multi-process, containers | High - filesystem ACLs |
| **Named pipe** | 🚧 | Windows local IPC | High - Windows ACLs |
| **SSH tunnel** | ✅ | Ad-hoc remote access | High - SSH provides auth |

### Default: stdio (No Network Exposure) ✅

```bash
# Default - no network listener
mcp-sysinfo
```

The server reads from stdin and writes to stdout. No TCP/UDP ports opened. This is the **only** transport enabled by default.

**stdio Security Model**: Authentication is not required because OS-level controls apply:
- Only processes that can spawn the binary can interact with it
- Parent process controls who can write to stdin / read from stdout

### HTTP Transport ✅

```bash
# HTTP transport with authentication
mcp-sysinfo --transport http --listen 127.0.0.1:8080

# With TLS
mcp-sysinfo --transport http \
    --listen 0.0.0.0:8443 \
    --tls-cert /etc/mcp/cert.pem \
    --tls-key /etc/mcp/key.pem
```

### Network Exposure Guardrails 🚧

> **Not yet implemented.** Currently the server will start on any bind address. Future versions will enforce:

| Bind Address | Requirements |
|--------------|--------------|
| `127.0.0.1` / `::1` | Auth recommended |
| `0.0.0.0` / `::` | **Auth required** (server refuses otherwise) |

---

## Authentication

### Authentication Requirements by Transport

| Transport | Auth Required | Status |
|-----------|---------------|--------|
| stdio | No | ✅ |
| HTTP (localhost) | Recommended | ✅ |
| HTTP (remote) | **Required** | ✅ |

### Authentication Methods ✅

The HTTP transport supports two authentication methods:

| Method | Use Case | Token Validation | Status |
|--------|----------|------------------|--------|
| **OIDC** | Enterprise IdP (Okta, Azure AD, etc.) | Local JWT validation via JWKS | ✅ |
| **OAuth Introspection** | Custom/internal auth servers | Per-request introspection call | ✅ |

Both methods follow OAuth 2.1 / MCP Authorization spec with Bearer tokens.

### Option 1: OIDC (Enterprise IdP Integration) ✅

OIDC validates tokens locally using public keys from the IdP's JWKS endpoint.

```bash
mcp-sysinfo --transport http \
    --listen 0.0.0.0:8443 \
    --tls-cert /etc/mcp/cert.pem \
    --tls-key /etc/mcp/key.pem \
    --oidc-issuer https://enterprise.okta.com \
    --oidc-audience mcp-sysinfo
```

**Supported OIDC Providers:**
- Okta
- Azure AD (Entra ID)
- Auth0
- Keycloak
- Google Workspace
- Any OIDC-compliant provider

**How it works:**

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  AI Client  │────▶│   MCP Server    │     │  Enterprise IdP  │
│             │     │                 │     │  (Okta, etc.)    │
│             │     │  1. Fetch JWKS  │────▶│                  │
│             │     │  2. Cache keys  │◀────│  /.well-known/   │
│ Bearer JWT  │────▶│  3. Validate    │     │  jwks.json       │
│             │     │     locally     │     │                  │
└─────────────┘     └─────────────────┘     └──────────────────┘
```

The MCP server:
1. Discovers JWKS URI from `/.well-known/openid-configuration`
2. Fetches and caches public keys (1 hour TTL)
3. Validates JWT signature, issuer, audience, and expiration locally
4. No per-request call to the IdP (better performance)

### Option 2: OAuth Token Introspection ✅

Token introspection validates tokens by calling the authorization server's `/introspect` endpoint.

```bash
mcp-sysinfo --transport http \
    --listen 0.0.0.0:8443 \
    --tls-cert /etc/mcp/cert.pem \
    --tls-key /etc/mcp/key.pem \
    --auth-server https://auth.internal.com \
    --client-id mcp-sysinfo \
    --client-secret $MCP_CLIENT_SECRET
```

**How it works:**

```
┌─────────────┐     ┌─────────────────┐     ┌──────────────────┐
│  AI Client  │────▶│   MCP Server    │     │   Auth Server    │
│             │     │                 │     │                  │
│ Bearer JWT  │────▶│  POST /introspect│───▶│  Validate token  │
│             │     │  {token: "..."}  │◀───│  {active: true}  │
│             │     │                 │     │                  │
└─────────────┘     └─────────────────┘     └──────────────────┘
```

### Built-in Token Server ✅

For development or environments without an existing IdP:

```bash
# Start the token server
mcp-token-server serve \
    --listen 127.0.0.1:8444 \
    --issuer http://localhost:8444 \
    --audience mcp-sysinfo \
    --clients /etc/mcp/clients.json

# Start MCP server with introspection
mcp-sysinfo --transport http \
    --listen 127.0.0.1:8080 \
    --auth-server http://127.0.0.1:8444 \
    --client-id mcp-sysinfo \
    --client-secret $SECRET
```

The token server provides:
- OAuth 2.1 client credentials flow
- JWKS endpoint for OIDC validation
- Token introspection endpoint
- Automatic RSA key generation and rotation

### Replay Prevention (JTI Caching) 🚧

> **Not yet implemented.** Future versions will support JTI caching to prevent token replay.

### mTLS Client Certificates 🚧

> **Not yet implemented.** Future versions will support mutual TLS for client authentication.

---

## Rate Limiting 🚧

> **Not yet implemented.** Future versions will support per-identity rate limiting.

Planned features:
- Per-identity rate limits (keyed by JWT subject)
- Stricter limits for sensitive queries
- Configurable burst allowances

---

## Query Classification & Scopes

### Query Categories ✅

| Scope | Description | Status |
|-------|-------------|--------|
| `core` | CPU, memory, disk, network, processes, uptime, temperature | ✅ |
| `logs` | System and application logs | ✅ |
| `hooks` | Scheduled tasks, kernel modules, network config, mounts | ✅ |
| `sensitive` | Auth logs | ✅ |

Scopes are extracted from JWT tokens (from `scope` or `scp` claims) and checked at tool invocation time.

### Scope Enforcement 🚧

> **Partially implemented.** Scopes are registered per-tool but enforcement is not yet active. Currently all authenticated requests can access all tools.

---

## Output Security ✅

### Redaction

Automatic redaction of sensitive data is available via the provider-based redaction system. Redaction is **opt-in** and disabled by default.

```bash
# Enable redaction with default provider
mcp-sysinfo --redact

# Enable with GitGuardian provider
mcp-sysinfo --redact --redact-provider gitguardian
```

**Available Providers:**

| Provider | Description |
|----------|-------------|
| `default` | Built-in pattern matching (fast, offline) |
| `gitguardian` | GitGuardian integration (350+ detectors, API or CLI) |

**Detection Methods:**

1. **Field-Level** - Redacts values with sensitive field names (`password`, `secret`, `token`, `key`, `auth`, `credential`)

2. **Pattern-Based** - Redacts values matching sensitive patterns regardless of field name:
   - Connection strings with credentials
   - AWS keys and secrets
   - JWT tokens, GitHub tokens, Slack tokens, Stripe keys
   - Private keys (PEM format)
   - And 350+ more patterns with GitGuardian provider

See [docs/security/redaction.md](docs/security/redaction.md) for full documentation.

### Output Limits 🚧

> **Not implemented.** No hard caps on output size. Large queries (e.g., process lists, logs) return full results.

---

## Resource Limits 🚧

> **Not implemented.** No query timeouts, concurrency limits, or resource caps.

Planned features:
- Query timeout enforcement
- Max concurrent queries
- Output size limits

---

## Audit Logging ✅

MCP System Info provides comprehensive audit logging for security and compliance. See [docs/security/audit.md](docs/security/audit.md) for complete documentation.

### Features

- **JSON Lines format**: Each event is a self-contained JSON object
- **Tamper-evident**: SHA-256 hash chain and sequence numbers detect modifications
- **Immutable append-only**: Uses `O_APPEND` for atomic writes
- **Async buffered writing**: High performance with configurable flush
- **File rotation**: Automatic rotation with gzip compression

### Quick Start

```bash
# Enable audit logging
mcp-sysinfo --audit --audit-output /var/log/mcp-sysinfo/audit.jsonl

# High-integrity mode
mcp-sysinfo --audit --audit-sync-write

# Verify audit log integrity
mcp-sysinfo --audit-verify --audit-output /var/log/mcp-sysinfo/audit.jsonl
```

### Events Logged

- All tool invocations with identity, parameters, and duration
- Authentication success and failure events
- Access denials

### Sample Event

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "seq": 42,
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "action": "tools/call",
  "resource": "get_cpu_info",
  "identity": "user@example.com",
  "result": "success",
  "duration_ns": 15000000,
  "prev_hash": "abc123...",
  "hash": "def456..."
}
```

---

## Configuration 🚧

### Config File Support

> **Not implemented.** All configuration is via CLI flags. YAML config file support is planned.

### Hot Reload

> **Not implemented.** Server must be restarted for configuration changes.

---

## Deployment Models

### Model 1: Local Only (Default) ✅

```
┌──────────────────────────────────────┐
│           Local Machine              │
│  ┌────────────┐    ┌──────────────┐  │
│  │ MCP Client │───▶│ mcp-sysinfo  │  │
│  │ (Claude)   │stdio│   (server)   │  │
│  └────────────┘    └──────────────┘  │
└──────────────────────────────────────┘
```

No network exposure; OS-level controls apply.

### Model 2: HTTP with OIDC ✅

```
┌─────────────┐         ┌─────────────────┐         ┌─────────────────┐
│ MCP Client  │────────▶│   MCP Server    │◀───────▶│  Enterprise IdP │
│             │  HTTPS  │                 │  JWKS   │  (Okta, etc.)   │
│ Bearer JWT  │────────▶│  --oidc-issuer  │         │                 │
└─────────────┘         └─────────────────┘         └─────────────────┘
```

### Model 3: SSH Tunnel ✅

```
┌─────────────┐      SSH      ┌─────────────────────────────┐
│ Workstation │──────────────▶│       Remote Server         │
│             │               │  ┌──────────────────────┐   │
│ Claude CLI  │═══════════════│▶▶│ mcp-sysinfo (stdio)  │   │
│             │  stdin/stdout │  └──────────────────────┘   │
└─────────────┘               └─────────────────────────────┘
```

```bash
ssh user@server "mcp-sysinfo --transport stdio"
```

### Model 4: Teleport MCP Integration 🚧

> **Integration documented but not tested.** Should work with Teleport's MCP support.

---

## Hardening Checklist

### Currently Available

- [x] Use stdio transport for local-only access
- [x] Enable OIDC or OAuth authentication for HTTP transport
- [x] Use TLS for HTTP transport in production
- [x] Restrict `--listen` to localhost when possible

### Planned Features

- [x] Enable audit logging
- [ ] Configure rate limits
- [ ] Enable output redaction
- [ ] Set resource limits
- [ ] Use mTLS for service-to-service

---

## Implementation Status Summary

| Feature | Status |
|---------|--------|
| stdio transport | ✅ |
| HTTP transport | ✅ |
| TLS support | ✅ |
| OIDC authentication | ✅ |
| OAuth introspection | ✅ |
| Built-in token server | ✅ |
| Scope registration | ✅ |
| Scope enforcement | 🚧 |
| Unix socket transport | 🚧 |
| mTLS client certs | 🚧 |
| Rate limiting | 🚧 |
| Output redaction | ✅ |
| Output limits | 🚧 |
| Resource limits | 🚧 |
| Audit logging | ✅ |
| JTI replay prevention | 🚧 |
| Config file support | 🚧 |
| Hot reload | 🚧 |

---

## Security Contacts

Report security vulnerabilities to: security@example.com

We follow coordinated disclosure. Please allow 90 days for fixes before public disclosure.
