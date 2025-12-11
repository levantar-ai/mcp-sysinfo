# MCP System Info

A comprehensive system monitoring and management server using the Model Context Protocol (MCP).

## Features

- **Cross-platform**: Linux, macOS, and Windows support
- **Real-time metrics**: CPU, memory, disk, network, processes
- **Advanced monitoring**: GPU, containers, temperatures
- **Analytics**: Historical data, trends, anomaly detection
- **Automation**: Alerts, auto-remediation, webhooks
- **Security**: Port scanning, file integrity, compliance checks
- **LLM-optimized**: Health scoring, diagnostics, recommendations

## Quick Start

```bash
# Build
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Run
./mcp-sysinfo
```

## Development

### Prerequisites

- Go 1.22+
- Platform-specific tools (see docs)

### Testing

```bash
# Unit tests
go test -v ./...

# Integration tests (requires real OS)
INTEGRATION_TEST=true go test -v -tags=integration ./test/integration/...
```

### Building

```bash
# Current platform
go build ./cmd/mcp-sysinfo

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o mcp-sysinfo-linux ./cmd/mcp-sysinfo
GOOS=darwin GOARCH=arm64 go build -o mcp-sysinfo-darwin ./cmd/mcp-sysinfo
GOOS=windows GOARCH=amd64 go build -o mcp-sysinfo.exe ./cmd/mcp-sysinfo
```

## Documentation

See the [docs/](docs/) directory:

- [Overview](docs/00-overview.md)
- [Tier 1: Core Monitoring](docs/01-tier1-core-monitoring.md)
- [Tier 2: Analytics](docs/02-tier2-analytics.md)
- [Tier 3: Automation](docs/03-tier3-automation.md)
- [Tier 4: Security](docs/04-tier4-security.md)
- [Tier 5: Integration](docs/05-tier5-integration.md)
- [Tier 6: LLM Features](docs/06-tier6-llm-features.md)
- [Feature Support Matrix](docs/07-feature-support-matrix.md)

## Project Status

See [TODO.md](TODO.md) for the complete implementation checklist.

## License

MIT
