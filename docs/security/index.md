# Security

MCP System Info is designed with security as a first-class concern. It provides structured, auditable access to system state without granting shell access to AI agents.

## Security Model

| Traditional AI Shell Access | MCP System Info |
|----------------------------|-----------------|
| AI can run arbitrary commands | Constrained to vetted read-only queries |
| Output parsing is fragile | Structured JSON with consistent schemas |
| No audit trail | Every query logged with identity |
| Secrets leak via env/history | Automatic redaction of credentials |
| Resource impact unbounded | Hard limits on CPU, memory, time |

## Key Security Features

### Read-Only by Design

All queries are strictly read-only. There are no commands that modify system state, write files, or execute arbitrary code.

### Automatic Redaction

Sensitive values can be automatically redacted from output. Redaction is **opt-in** and supports multiple providers:

```bash
# Enable with default provider
mcp-sysinfo --redact

# Enable with GitGuardian
mcp-sysinfo --redact --redact-provider gitguardian
```

**Detection Methods:**

- **Field-Level** - Redacts values with sensitive field names (`password`, `secret`, `token`, `key`, `auth`, `credential`)
- **Pattern-Based** - Redacts values matching sensitive patterns (connection strings, AWS keys, JWT tokens, private keys, etc.)

**Available Providers:**

- `default` - Built-in pattern matching (fast, offline, no dependencies)
- `gitguardian` - GitGuardian integration with 350+ secret detectors

See [Redaction](redaction.md) for full documentation.

### Scoped Access

Queries are organized into security scopes. Sensitive queries (auth logs, SSH config, sudoers) are disabled by default and require explicit opt-in.

### Audit Logging

Every query is logged with:

- Timestamp
- Query name and parameters
- Client identity
- Duration

### Resource Limits

Hard limits prevent resource exhaustion:

- CPU: 10% per query
- Memory: 100MB per query
- Time: 30 seconds per query

## Documentation

- [Authentication](authentication.md) - Token-based authentication
- [Scopes](scopes.md) - Security scope system
- [Deployment](deployment.md) - Production deployment patterns

## Threat Model

MCP System Info is designed to be safe for use with AI agents that:

1. May be compromised or manipulated
2. May make excessive requests
3. May attempt to access sensitive data

The server assumes all clients are potentially hostile and enforces restrictions at the protocol level.

## Reporting Security Issues

Report security vulnerabilities via GitHub Security Advisories or email security@levantar.ai.
