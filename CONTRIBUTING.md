# Contributing to MCP System Info

Thank you for your interest in contributing to MCP System Info! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

### Prerequisites

- Go 1.22 or later
- Git
- golangci-lint (for linting)
- gosec (for security scanning)

### Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/mcp-sysinfo.git
   cd mcp-sysinfo
   ```

2. Install development dependencies:
   ```bash
   go mod download
   ```

3. Install pre-commit hooks (lefthook):
   ```bash
   go install github.com/evilmartians/lefthook@latest
   lefthook install
   ```

4. Build the project:
   ```bash
   go build -o mcp-sysinfo ./cmd/mcp-sysinfo
   ```

5. Run tests:
   ```bash
   go test -v ./...
   ```

## Development Workflow

### Branching

- Create feature branches from `main`
- Use descriptive branch names: `feat/add-gpu-metrics`, `fix/memory-leak`, `docs/update-readme`

### Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/) for semantic versioning:

- `feat:` - New features (triggers minor release)
- `fix:` - Bug fixes (triggers patch release)
- `docs:` - Documentation changes
- `test:` - Adding or updating tests
- `refactor:` - Code refactoring without functional changes
- `chore:` - Maintenance tasks
- `BREAKING CHANGE:` - Breaking changes (triggers major release)

Examples:
```
feat: add GPU temperature monitoring for NVIDIA cards
fix: resolve memory leak in process collector
docs: update installation instructions for Windows
```

### Pull Request Process

1. Ensure your code passes all checks:
   ```bash
   golangci-lint run ./...
   gosec -quiet ./...
   go test -v -race ./...
   ```

2. Update documentation if you're changing behavior

3. Add tests for new functionality

4. Submit a pull request with:
   - Clear title following conventional commits
   - Description of changes
   - Link to related issues

## Adding New Queries

When adding a new system query:

1. **Create the collector** in the appropriate `internal/` package
2. **Implement for all platforms** (Linux, macOS, Windows):
   - Create `*_linux.go`, `*_darwin.go`, `*_windows.go` files
   - Use build tags: `//go:build linux`
   - Return empty results (not errors) for unsupported platforms
3. **Register the tool** in `internal/mcp/tools.go`
4. **Add CLI support** in `cmd/mcp-sysinfo/main.go`
5. **Write tests**:
   - Unit tests for parsing logic
   - Integration tests (guarded by `INTEGRATION_TEST=true`)
6. **Update TODO.md** with implementation status

### Cross-Platform Guidelines

- Use only native OS APIs and built-in tools
- No external dependencies or third-party binaries
- Ensure consistent output schema across platforms
- Use `LC_ALL=C` for consistent command output parsing

## Testing

### Unit Tests

```bash
go test -v ./...
```

### With Race Detection

```bash
go test -v -race -coverprofile=coverage.out ./...
```

### Integration Tests

```bash
INTEGRATION_TEST=true go test -v -tags=integration ./test/integration/...
```

### Single Test

```bash
go test -v -run TestFunctionName ./internal/cpu/...
```

## Security

### Security Considerations

This is a security-first project. When contributing:

- Never expose arbitrary command execution
- Use allowlisted, parameterized commands only
- Parse and validate all output before returning
- Consider redaction requirements for sensitive data
- Review the [Security Architecture](SECURITY.md)

### Reporting Vulnerabilities

See [SECURITY.md](SECURITY.md) for vulnerability reporting procedures.

## Architecture Overview

```
cmd/
├── mcp-sysinfo/     # Main MCP server binary
└── mcp-token-server/ # Development token server

internal/
├── mcp/             # MCP protocol implementation
├── cpu/             # CPU metrics collector
├── memory/          # Memory metrics collector
├── disk/            # Disk metrics collector
├── network/         # Network metrics collector
├── process/         # Process metrics collector
├── logs/            # Log collectors
└── ...              # Other collectors

pkg/
└── types/           # Shared types

test/
└── integration/     # Integration tests
```

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Use discussions for questions and ideas

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
