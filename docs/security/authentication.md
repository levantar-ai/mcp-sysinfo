# Authentication

## Stdio Mode (Default)

In stdio mode (the default), authentication is handled by the MCP client. The server trusts the client identity provided in the MCP protocol.

```bash
# Default mode - authentication handled by MCP client
./mcp-sysinfo
```

## HTTP Mode

HTTP mode supports three authentication methods:

### Bearer Token (Simple)

For simple deployments, use a shared secret token:

```bash
# Start server with token
./mcp-sysinfo --transport http --listen :8080 --token your-secret-token

# Or via environment variable
export MCP_SYSINFO_TOKEN=your-secret-token
./mcp-sysinfo --transport http --listen :8080
```

Query with authentication:

```bash
curl -X POST http://localhost:8080/ \
  -H "Authorization: Bearer your-secret-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_cpu_info"}}'
```

### Token Requirements

Tokens should be:

- At least 32 characters
- Cryptographically random
- Unique per deployment

Generate a secure token:

```bash
openssl rand -base64 32
```

### OIDC Authentication (Enterprise)

For enterprise deployments with an identity provider (Okta, Azure AD, Auth0):

```bash
./mcp-sysinfo --transport http \
  --listen 0.0.0.0:8443 \
  --oidc-issuer https://enterprise.okta.com \
  --oidc-audience mcp-sysinfo \
  --tls-cert /etc/mcp/cert.pem \
  --tls-key /etc/mcp/key.pem
```

### OAuth Token Introspection

For custom authorization servers:

```bash
./mcp-sysinfo --transport http \
  --listen 0.0.0.0:8443 \
  --auth-server https://auth.example.com \
  --client-id mcp-sysinfo \
  --client-secret SECRET
```

### No Authentication (Development Only)

For local development only:

```bash
./mcp-sysinfo --transport http --listen 127.0.0.1:8080
```

> **Warning:** Never expose unauthenticated HTTP servers to untrusted networks.

## Client Identity

Client identity is tracked in audit logs:

| Mode | Auth Method | Identity Source |
|------|-------------|-----------------|
| Stdio | - | MCP client metadata |
| HTTP | Bearer token | "bearer-token" (static) |
| HTTP | OIDC | JWT subject claim |
| HTTP | OAuth | Token introspection subject |
| HTTP | None | Client IP address |

## Recommendations

1. **Use stdio mode** when possible (client handles auth)
2. **Use bearer token** for simple remote access (with TLS)
3. **Use OIDC** for enterprise deployments with existing IdP
4. **Use TLS** always in HTTP mode for encryption
5. **Rotate tokens** regularly in HTTP mode

## Future Authentication

Planned authentication methods:

- [ ] mTLS (mutual TLS)
- [ ] API key rotation
