# Installation

## Prerequisites

- **Go 1.21+** (for building from source)
- **Git** (for cloning the repository)

## Building from Source

```bash
# Clone the repository
git clone https://github.com/levantar-ai/mcp-sysinfo.git
cd mcp-sysinfo

# Build the binary
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Verify the build
./mcp-sysinfo --version
```

## Pre-built Binaries

Download pre-built binaries from the [Releases page](https://github.com/levantar-ai/mcp-sysinfo/releases).

Available platforms:

| OS | Architecture | Binary |
|----|--------------|--------|
| Linux | amd64 | `mcp-sysinfo-linux-amd64` |
| Linux | arm64 | `mcp-sysinfo-linux-arm64` |
| macOS | amd64 | `mcp-sysinfo-darwin-amd64` |
| macOS | arm64 | `mcp-sysinfo-darwin-arm64` |
| Windows | amd64 | `mcp-sysinfo-windows-amd64.exe` |

## SLSA Provenance

All release binaries include [SLSA Level 3](https://slsa.dev/) provenance attestations for supply chain security. Verify downloads using:

```bash
slsa-verifier verify-artifact mcp-sysinfo-linux-amd64 \
  --provenance-path mcp-sysinfo-linux-amd64.intoto.jsonl \
  --source-uri github.com/levantar-ai/mcp-sysinfo
```

## Installing System-Wide

### Linux/macOS

```bash
sudo mv mcp-sysinfo /usr/local/bin/
sudo chmod +x /usr/local/bin/mcp-sysinfo
```

### Windows

Move the binary to a directory in your PATH, or add its location to PATH.

## Next Steps

- [Quick Start](quickstart.md) - Run your first queries
- [Configuration](configuration.md) - Configure the server
