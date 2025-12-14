# Contributing

Thank you for your interest in contributing to MCP System Info!

## Development Setup

### Prerequisites

- Go 1.21 or later
- Git
- Make (optional, for convenience commands)

### Clone and Build

```bash
git clone https://github.com/levantar-ai/mcp-sysinfo.git
cd mcp-sysinfo
go build -o mcp-sysinfo ./cmd/mcp-sysinfo
```

### Run Tests

```bash
# All tests
go test ./...

# With coverage
go test -cover ./...

# Specific package
go test ./internal/core/...
```

### Run Linting

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run linter
golangci-lint run
```

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable and function names
- Add comments for exported functions
- Keep functions focused and small

## Adding a New Query

1. **Define the query** in the appropriate package (`internal/core`, `internal/hooks`, etc.)

2. **Implement platform-specific handlers** using build tags:

```go
// query_linux.go
//go:build linux

func queryImpl() (Result, error) {
    // Linux implementation
}
```

3. **Register the query** in `internal/mcp/tools.go`

4. **Add documentation** in `cmd/docgen/main.go`

5. **Add tests** for all supported platforms

6. **Update the query count** in README.md and docs

## Commit Messages

Use conventional commit format:

```
type(scope): description

- type: feat, fix, docs, refactor, test, chore
- scope: core, logs, hooks, sbom, mcp, ci
- description: imperative mood, lowercase
```

Examples:

```
feat(sbom): add Ruby gem scanner
fix(core): handle missing /proc/meminfo gracefully
docs: update installation instructions
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes
4. Run tests and linting
5. Commit with conventional message
6. Push and open a PR

### PR Checklist

- [ ] Tests pass on all platforms
- [ ] Linting passes
- [ ] Documentation updated
- [ ] Query count updated (if adding queries)
- [ ] No sensitive data in commits

## Security

- Never log or expose credentials
- Use the redaction system for sensitive values
- Test with sensitive scope disabled (default)
- Report security issues privately

## Architecture Guidelines

- **Read-only**: Never modify system state
- **Zero dependencies**: Use only standard library and native OS APIs
- **Structured output**: Return JSON, not text
- **Cross-platform**: Provide implementations for all three OSes when possible

## Questions?

- Open an issue for discussion
- Check existing issues for similar questions
