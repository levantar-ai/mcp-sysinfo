# SaaS Agent Mode

MCP System Info can run as a managed agent that registers with a SaaS backend. This mode automatically handles TLS certificate generation, registration, and JWT validation.

## Overview

```
┌─────────────────┐                    ┌─────────────────────┐
│  Customer's     │                    │   Your SaaS         │
│  Infrastructure │                    │                     │
│                 │                    │  ┌───────────────┐  │
│  ┌───────────┐  │   1. Register      │  │ Agent API     │  │
│  │   Agent   │──┼──── (API key + ───▶│  │               │  │
│  │           │  │      public cert)  │  └───────┬───────┘  │
│  │           │◄─┼── 2. JWKS URL ─────│          │          │
│  │           │  │                    │          │          │
│  │  (HTTPS)  │◄─┼── 3. MCP calls ────│  ┌───────▼───────┐  │
│  │           │──┼── 4. Responses ───▶│  │ Orchestrator  │  │
│  └───────────┘  │      (JWT auth)    │  └───────────────┘  │
│                 │                    │                     │
└─────────────────┘                    └─────────────────────┘
```

## Quick Start

```bash
# Run agent with SaaS registration
./mcp-sysinfo --transport http \
  --listen 0.0.0.0:8443 \
  --saas-url https://api.your-saas.com \
  --api-key sk_live_abc123...
```

## What Happens Automatically

1. **Certificate Generation**: On first run, a self-signed ECDSA certificate is generated and stored in `~/.mcp-sysinfo/`

2. **Registration**: The agent registers with the SaaS backend, sending:
   - API key for authentication
   - Public certificate (for SaaS to trust agent's TLS)
   - Callback URL (where SaaS can reach the agent)

3. **JWKS Caching**: The agent fetches and caches the SaaS's JWKS for validating incoming JWTs

4. **HTTPS Server**: Starts listening with the auto-generated certificate

## Configuration

| Flag | Env Var | Description |
|------|---------|-------------|
| `--saas-url` | - | SaaS backend URL for registration |
| `--api-key` | `MCP_SYSINFO_API_KEY` | API key for authentication |
| `--callback-url` | - | URL where SaaS can reach agent (auto-detected) |
| `--config-dir` | - | Config directory (default: `~/.mcp-sysinfo`) |
| `--listen` | - | Listen address (default: `127.0.0.1:8080`) |

## Files Created

```
~/.mcp-sysinfo/
├── agent.crt          # Auto-generated TLS certificate
├── agent.key          # Private key (mode 0600)
└── registration.json  # Registration state
```

## Security Model

### Agent Side
- Auto-generated ECDSA P-256 certificate (1 year validity)
- Certificate regenerated if expiring within 24 hours
- Private key stored with restrictive permissions (0600)
- JWT validation using cached JWKS from SaaS

### SaaS Side
- Trusts agent's self-signed cert (pinned from registration)
- Signs JWTs for authentication
- Provides JWKS endpoint for agents

### Communication
- All traffic over TLS
- SaaS validates agent cert (pinned)
- Agent validates SaaS JWT (via JWKS)

## Registration API

The agent expects the SaaS to implement:

### `POST /v1/agents/register`

Request:
```json
{
  "callback_url": "https://10.0.0.5:8443",
  "public_cert": "-----BEGIN CERTIFICATE-----\n..."
}
```

Headers:
```
Authorization: Bearer <api_key>
Content-Type: application/json
```

Response:
```json
{
  "agent_id": "agent_abc123",
  "jwks_url": "https://api.your-saas.com/.well-known/jwks.json"
}
```

### `DELETE /v1/agents/{agent_id}`

Deregisters the agent (called on shutdown if needed).

## JWT Claims

The agent expects JWTs from the SaaS to include:

| Claim | Description |
|-------|-------------|
| `sub` | Subject (user or service identifier) |
| `exp` | Expiration time (required) |
| `scope` or `scp` | Scopes (space-separated or array) |
| `tenant_id` | Optional tenant identifier |

## Troubleshooting

### Certificate Issues

```bash
# View certificate details
openssl x509 -in ~/.mcp-sysinfo/agent.crt -text -noout

# Force regeneration (delete existing)
rm ~/.mcp-sysinfo/agent.crt ~/.mcp-sysinfo/agent.key
```

### Registration Issues

```bash
# Check registration state
cat ~/.mcp-sysinfo/registration.json

# Force re-registration (delete state)
rm ~/.mcp-sysinfo/registration.json
```

### Connection Issues

Ensure the callback URL is reachable from the SaaS:
- Firewall allows inbound on the listen port
- NAT/port forwarding configured if behind router
- Correct IP/hostname in `--callback-url`
