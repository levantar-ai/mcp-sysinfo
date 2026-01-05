# Deployment

## Deployment Patterns

### Local MCP Client (Recommended)

For Claude Desktop and similar MCP clients:

```json
{
  "mcpServers": {
    "sysinfo": {
      "command": "/usr/local/bin/mcp-sysinfo",
      "args": []
    }
  }
}
```

This is the most secure pattern:

- No network exposure
- Client handles authentication
- Process isolation per session

### Systemd Service

For long-running HTTP mode deployments:

```ini
# /etc/systemd/system/mcp-sysinfo.service
[Unit]
Description=MCP System Info Server
After=network.target

[Service]
Type=simple
User=mcp-sysinfo
Group=mcp-sysinfo
ExecStart=/usr/local/bin/mcp-sysinfo --transport http --listen 127.0.0.1:8080
Environment=MCP_SYSINFO_TOKEN=your-secret-token
Environment=MCP_SYSINFO_AUDIT_LOG=/var/log/mcp-sysinfo/audit.jsonl
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable mcp-sysinfo
sudo systemctl start mcp-sysinfo
```

### Docker Container

```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o mcp-sysinfo ./cmd/mcp-sysinfo

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/mcp-sysinfo /usr/local/bin/
ENTRYPOINT ["mcp-sysinfo"]
```

Run with host access for system metrics:

```bash
docker run -d \
  --name mcp-sysinfo \
  --pid=host \
  --network=host \
  -v /proc:/host/proc:ro \
  -v /sys:/host/sys:ro \
  -e MCP_SYSINFO_TOKEN=your-token \
  mcp-sysinfo --http :8080
```

### Reverse Proxy with TLS

For production HTTP deployments, use a reverse proxy:

```nginx
# /etc/nginx/conf.d/mcp-sysinfo.conf
server {
    listen 443 ssl http2;
    server_name sysinfo.example.com;

    ssl_certificate /etc/ssl/certs/sysinfo.crt;
    ssl_certificate_key /etc/ssl/private/sysinfo.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Checklist

- [ ] Use stdio mode when possible (no network exposure)
- [ ] Generate cryptographically random tokens
- [ ] Enable TLS for HTTP mode
- [ ] Restrict network access to trusted IPs
- [ ] Enable audit logging
- [ ] Run as unprivileged user
- [ ] Use systemd security hardening
- [ ] Keep sensitive scope disabled unless needed
- [ ] Monitor audit logs for anomalies
- [ ] Rotate tokens regularly

## Monitoring

### Health Check

```bash
curl http://localhost:8080/health
```

### Metrics

Prometheus metrics endpoint (planned):

```bash
curl http://localhost:8080/metrics
```

### Audit Log Analysis

```bash
# Query frequency
cat /var/log/mcp-sysinfo/audit.jsonl | jq -r '.query' | sort | uniq -c | sort -rn

# Slow queries
cat /var/log/mcp-sysinfo/audit.jsonl | jq 'select(.duration_ms > 1000)'
```
