# Authentication

## Stdio Mode

In stdio mode (the default), authentication is handled by the MCP client. The server trusts the client identity provided in the MCP protocol.

## HTTP Mode

HTTP mode requires bearer token authentication:

```bash
# Start server with token
./mcp-sysinfo --http :8080 --token your-secret-token

# Query with authentication
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

### Token from Environment

Set the token via environment variable:

```bash
export MCP_SYSINFO_TOKEN=your-secret-token
./mcp-sysinfo --http :8080
```

## Client Identity

Client identity is tracked in audit logs:

| Mode | Identity Source |
|------|-----------------|
| Stdio | MCP client metadata |
| HTTP | Bearer token (hashed) |

## Recommendations

1. **Use stdio mode** when possible (client handles auth)
2. **Rotate tokens** regularly in HTTP mode
3. **Use TLS** in front of HTTP mode for encryption
4. **Restrict network access** to trusted clients only

## Future Authentication

Planned authentication methods:

- [ ] mTLS (mutual TLS)
- [ ] OAuth 2.0 / OIDC
- [ ] API key rotation
