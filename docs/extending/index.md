# Extending MCP System Info

This section covers how to extend MCP System Info with custom functionality.

## Guides

- [Building Plugins](plugins.md) - Create custom plugins to add new diagnostic queries

## Overview

MCP System Info is designed to be extensible. The plugin architecture allows you to:

- Add custom diagnostic queries for your specific infrastructure
- Integrate with internal monitoring systems
- Support proprietary databases or services
- Create industry-specific diagnostic tools

## Plugin Architecture

Plugins are compiled into the binary at build time using Go's build tag system. This provides:

| Benefit | Description |
|---------|-------------|
| Security | No dynamic code execution or runtime loading |
| Performance | Zero plugin discovery/loading overhead |
| Type Safety | Compile-time interface validation |
| Simplicity | Standard Go build and test workflow |

## Getting Started

1. Read the [Building Plugins](plugins.md) guide
2. Review existing collectors in `internal/` for patterns
3. Check [Tool Schemas](../api/schemas.md) for InputSchema reference
4. Understand [Security Scopes](../security/scopes.md) for access control
