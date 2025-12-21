# Query Reference

MCP System Info provides **117 queries** across multiple categories for comprehensive system diagnostics.

!!! note "Auto-Generated"
    This documentation is automatically generated from the source code on each release.

## Query Categories

| Category | Queries | Description |
|----------|---------|-------------|
| [Core Metrics](core/index.md) | 7 | Fundamental system health: CPU, memory, disk, network, and processes. |
| [Log Access](logs/index.md) | 6 | System logs, journals, and event logs for diagnostics. |
| [System Hooks](hooks/index.md) | 31 | Deep system introspection: scheduled tasks, kernel, network config, security. |
| [Software Inventory](sbom/index.md) | 31 | Package managers, executables, containers, SBOM export, vulnerability lookup. |
| [Application Discovery](hooks/index.md#application-discovery) | 2 | Discover installed applications and read config files. |
| [Triage & Summary](hooks/index.md#triage) | 25 | High-level queries for incident triage and security posture. |
| [Windows Enterprise](windows/index.md) | 15 | Windows-only: Registry, DCOM/COM, IIS web server. |

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
| `windows` | Medium | Enabled |
| `sensitive` | **High** | **Disabled** |

---

*Documentation auto-generated on 2025-12-21*
