# Query Reference

MCP System Info provides **56 queries** across multiple categories for comprehensive system diagnostics.

!!! note "Auto-Generated"
    This documentation is automatically generated from the source code on each release.

## Query Categories

| Category | Queries | Description |
|----------|---------|-------------|
| [Core Metrics](core/index.md) | 7 | Fundamental system health: CPU, memory, disk, network, and processes. |
| [Log Access](logs/index.md) | 6 | System logs, journals, and event logs for diagnostics. |
| [System Hooks](hooks/index.md) | 36 | Deep system introspection: scheduled tasks, kernel, network config, security. |
| [Software Inventory](sbom/index.md) | 7 | Package managers, executables, and language-specific dependencies. |

## Platform Support

All queries are cross-platform with OS-specific backends:

| Symbol | Meaning |
|--------|---------|
| :white_check_mark: | Fully supported |
| :warning: | Partial support or different behavior |
| :x: | Not available on this platform |

## Query Scopes

| Scope | Risk | Default |
|-------|------|---------|
| `core` | Low | Enabled |
| `logs` | Medium | Enabled |
| `hooks` | Medium | Enabled |
| `sbom` | Medium | Enabled |
| `sensitive` | **High** | **Disabled** |

---

*Documentation auto-generated on 2025-12-14*
