# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Phase 1.2.5: Security Configuration tools (6 queries)
  - `get_env_vars` - System environment variables with sensitive value redaction
  - `get_user_accounts` - Local user accounts and groups
  - `get_sudo_config` - Sudo/privilege escalation configuration
  - `get_ssh_config` - SSH server and client configuration
  - `get_mac_status` - SELinux/AppArmor Mandatory Access Control status
  - `get_certificates` - SSL/TLS certificates from system trust store
- Integration tests for security tools (Linux, macOS, Windows)
- Updated feature support matrix with accurate query counts
- Phase 1.5: Triage & Summary queries (5 queries)
  - `get_os_info` - OS identification and version
  - `get_system_profile` - Hardware/VM summary
  - `get_service_manager_info` - Init system details
  - `get_cloud_environment` - Cloud provider detection
  - `get_language_runtime_versions` - Installed language runtimes
- Phase 1.3.5: Vulnerability lookup
  - `get_vulnerabilities_osv` - Query OSV API for known CVEs
- Phase 1.3.4: SBOM export formats
  - `get_sbom_cyclonedx` - Generate CycloneDX 1.4 JSON SBOM
  - `get_sbom_spdx` - Generate SPDX 2.3 JSON SBOM
- Phase 1.3.3: Container inventory
  - `get_docker_images` - List Docker/Podman images
  - `get_docker_containers` - List containers with state
  - `get_docker_image_history` - Image layer history
- Phase 1.3.2: Language package manager scanners
  - `get_python_packages` - Python pip packages
  - `get_node_packages` - Node.js npm packages
  - `get_go_modules` - Go module cache
  - `get_rust_packages` - Rust cargo crates
  - `get_ruby_gems` - Ruby gems
- Documentation site with MkDocs Material
- Auto-generated query documentation

### Changed

- CI unit tests now run only on Linux (smoke tests still run on all platforms)

### Fixed

- Integer overflow warnings in gosec (G115)
- Pre-commit hook configuration with lefthook
- Darwin build fix: use uname command instead of syscall.Uname

## [0.1.0] - 2024-01-15

### Added

- Initial release with 51 queries
- Phase 1.0: Core metrics (7 queries)
  - CPU, memory, disk, network, processes, uptime, temperature
- Phase 1.1: Log access (6 queries)
  - Journal logs, syslog, kernel logs, auth logs, app logs, Windows Event Log
- Phase 1.2: System hooks (31 queries)
  - Scheduled tasks, kernel modules, network config, filesystem, security, hardware
- Phase 1.3.1: Basic SBOM (2 queries)
  - System packages, PATH executables
- Stdio transport for MCP clients
- HTTP transport with bearer token auth
- Security scope system
- Automatic credential redaction
- Audit logging (JSON Lines)
- Resource limits (CPU, memory, time)
- SLSA Level 3 provenance for releases

### Security

- Sensitive queries disabled by default
- Automatic redaction of AWS keys, passwords, tokens
- Hard resource limits per query

## Version History

| Version | Date | Queries | Highlights |
|---------|------|---------|------------|
| 0.1.0 | 2024-01-15 | 51 | Initial release |

## Roadmap

See [TODO.md](https://github.com/levantar-ai/mcp-sysinfo/blob/main/TODO.md) for planned features:

- Phase 1.4: Container & Orchestration
- Phase 1.5: Triage & Summary Queries
- Phase 1.6: Windows Enterprise Features
- And more...
