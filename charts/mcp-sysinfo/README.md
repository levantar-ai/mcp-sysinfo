# MCP System Info Helm Chart

Deploy MCP System Info to Kubernetes.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+

## Installation

```bash
# Add the Helm repository (when published)
helm repo add mcp-sysinfo https://levantar-ai.github.io/mcp-sysinfo

# Install the chart
helm install my-release mcp-sysinfo/mcp-sysinfo
```

Or install from local source:

```bash
helm install my-release ./charts/mcp-sysinfo
```

## Uninstallation

```bash
helm uninstall my-release
```

## Configuration

The following table lists the configurable parameters and their default values.

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `1` |
| `image.repository` | Image repository | `ghcr.io/levantar-ai/mcp-sysinfo` |
| `image.tag` | Image tag | `""` (uses appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `ingress.enabled` | Enable ingress | `false` |
| `resources.limits.cpu` | CPU limit | `200m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `mcp.auth.enabled` | Enable authentication | `false` |
| `mcp.auth.oidc.enabled` | Enable OIDC auth | `false` |
| `mcp.auth.oauth.enabled` | Enable OAuth auth | `false` |
| `metrics.enabled` | Enable Prometheus metrics | `true` |
| `metrics.serviceMonitor.enabled` | Create ServiceMonitor | `false` |
| `hostPaths.proc.enabled` | Mount /proc | `true` |
| `hostPaths.sys.enabled` | Mount /sys | `true` |

## Examples

### Basic Installation

```bash
helm install mcp-sysinfo ./charts/mcp-sysinfo
```

### With OIDC Authentication

```bash
helm install mcp-sysinfo ./charts/mcp-sysinfo \
  --set mcp.auth.enabled=true \
  --set mcp.auth.oidc.enabled=true \
  --set mcp.auth.oidc.issuer=https://your-idp.example.com \
  --set mcp.auth.oidc.audience=mcp-sysinfo
```

### With Prometheus Monitoring

```bash
helm install mcp-sysinfo ./charts/mcp-sysinfo \
  --set metrics.enabled=true \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.labels.release=prometheus
```

### With Ingress

```bash
helm install mcp-sysinfo ./charts/mcp-sysinfo \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=mcp.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```

## Security Considerations

1. **Authentication**: Enable OIDC or OAuth authentication for production deployments
2. **Sensitive Scope**: The `sensitive` scope is disabled by default for security
3. **Host Paths**: /proc and /sys are mounted read-only for system info collection
4. **Security Context**: Runs as non-root with restricted capabilities

## Troubleshooting

### Check pod status

```bash
kubectl get pods -l app.kubernetes.io/name=mcp-sysinfo
```

### View logs

```bash
kubectl logs -l app.kubernetes.io/name=mcp-sysinfo
```

### Test connectivity

```bash
kubectl port-forward svc/mcp-sysinfo 8080:8080
curl http://localhost:8080/health
```
