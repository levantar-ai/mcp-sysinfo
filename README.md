# MCP System Info

<p align="center">
  <img src="images/logo.png?raw=true" alt="MCP System Info Logo" width="400">
</p>

[![CI](https://github.com/levantar-ai/mcp-sysinfo/actions/workflows/ci.yml/badge.svg)](https://github.com/levantar-ai/mcp-sysinfo/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Read-only AI diagnostics plane for secure incident triage and evidence capture.**

A security-first MCP server that provides structured, auditable access to system state without granting shell access to AI agents. Designed for production environments where you need AI-assisted di[...] 

## Why This Exists

| Traditional AI Shell Access | MCP System Info |
|----------------------------|-----------------|
| AI can run arbitrary commands | Constrained to vetted read-only queries |
| Output parsing is fragile | Structured JSON with consistent schemas |
| No audit trail | Every query logged with identity |
| Secrets leak via env/history | Automatic redaction of credentials |
| Resource impact unbounded | Hard limits on CPU, memory, time |

## Security Model

See **[SECURITY.md](SECURITY.md)** for the complete security architecture.

### Key Principles

| Principle | Implementation |
|-----------|----------------|
| **Defense in depth** | Transport security + auth + scopes + redaction + limits |
| **Localhost by default** | No network listener unless explicitly configured |
| **Sensitive queries disabled** | Auth logs, env vars, user accounts require opt-in |
| **Automatic redaction** | AWS keys, passwords, tokens stripped from output |
| **Audit everything** | JSON Lines audit log with client identity |

### Query Classification

| Scope | Risk | Default |
|-------|------|---------|
| `core` - CPU, memory, disk, network, processes | Low | Enabled |
| `logs` - System and application logs | Medium | Enabled |
| `hooks` - Scheduled tasks, kernel modules, network config | Medium | Enabled |
| `sbom` - Package inventory, container images | Medium | Enabled |
| `sensitive` - Auth logs, env vars, SSH/sudo config | **High** | **Disabled** |

### Deployment Options

| Model | Use Case |
|-------|----------|
| **stdio** (default) | Local MCP client (Claude Desktop) |
| **HTTP + OIDC** | Enterprise IdP (Okta, Azure AD, Auth0) |
| **HTTP + OAuth** | Custom auth server with token introspection |
| **SSH tunnel** | Remote access with existing SSH infrastructure |
| **Teleport MCP** | Enterprise SSO + RBAC + session recording |

---

## Query Reference

**Implemented: 134 queries | Planned: 159 queries | Total: 293 queries**

### Phase 1.0: Core Metrics (7/7)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_cpu_info` | Usage, frequency, load average, cores | ✅ | ✅ | ✅ |
| `get_memory_info` | Total, used, available, swap | ✅ | ✅ | ✅ |
| `get_disk_info` | Partitions, usage, I/O stats | ✅ | ✅ | ✅ |
| `get_network_info` | Interfaces, I/O, connections | ✅ | ✅ | ✅ |
| `get_processes` | Process list, top by CPU/memory | ✅ | ✅ | ✅ |
| `get_uptime` | Boot time, uptime duration | ✅ | ✅ | ✅ |
| `get_temperature` | Hardware temperature sensors | ✅ | ⚠️ | ⚠️ |

### Phase 1.1: Log Access (6/6)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_journal_logs` | Systemd journal | ✅ | - | - |
| `get_syslog` | Traditional syslog | ✅ | ✅ | - |
| `get_kernel_logs` | Kernel/dmesg logs | ✅ | ✅ | - |
| `get_auth_logs` | Authentication logs (sensitive) | ✅ | ✅ | - |
| `get_app_logs` | Application-specific logs | ✅ | ✅ | ✅ |
| `get_event_log` | Windows Event Log | - | - | ✅ |

### Phase 1.2: System Hooks + Security (37/37)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_scheduled_tasks` | Task Scheduler / at jobs / launchd | ✅ | ✅ | ✅ |
| `get_cron_jobs` | Cron entries | ✅ | ✅ | - |
| `get_startup_items` | Startup programs and services | ✅ | ✅ | ✅ |
| `get_systemd_services` | Systemd service status | ✅ | - | - |
| `get_kernel_modules` | Loaded kernel modules | ✅ | ✅ | - |
| `get_loaded_drivers` | Device drivers | ✅ | ✅ | ✅ |
| `get_dns_servers` | Configured DNS servers | ✅ | ✅ | ✅ |
| `get_routes` | Routing table | ✅ | ✅ | ✅ |
| `get_firewall_rules` | Firewall rules | ✅ | ✅ | ✅ |
| `get_listening_ports` | Listening network ports | ✅ | ✅ | ✅ |
| `get_arp_table` | ARP table entries | ✅ | ✅ | ✅ |
| `get_network_stats` | Network stack statistics | ✅ | ✅ | ✅ |
| `get_mounts` | Mounted filesystems | ✅ | ✅ | ✅ |
| `get_disk_io` | Disk I/O statistics | ✅ | ✅ | ✅ |
| `get_open_files` | Open file descriptors | ✅ | ✅ | ✅ |
| `get_inode_usage` | Inode usage | ✅ | ✅ | - |
| `get_hardware_info` | System/BIOS/motherboard info | ✅ | ✅ | ✅ |
| `get_usb_devices` | Connected USB devices | ✅ | ✅ | ✅ |
| `get_pci_devices` | PCI devices | ✅ | ✅ | ✅ |
| `get_block_devices` | Block device topology | ✅ | ✅ | ✅ |
| `get_process_environ` | Process environment variables | ✅ | - | - |
| `get_ipc_resources` | IPC resources (shm, sem, msg) | ✅ | - | - |
| `get_namespaces` | Linux namespaces | ✅ | - | - |
| `get_cgroups` | Cgroup limits and usage | ✅ | - | - |
| `get_capabilities` | Process capabilities | ✅ | - | - |
| `get_vm_info` | VM/container detection | ✅ | ✅ | ✅ |
| `get_timezone` | Timezone and locale info | ✅ | ✅ | ✅ |
| `get_ntp_status` | NTP synchronization status | ✅ | ✅ | ✅ |
| `get_core_dumps` | Core dump information | ✅ | ✅ | ✅ |
| `get_power_state` | Power/battery state | ✅ | ✅ | ✅ |
| `get_numa_topology` | NUMA topology | ✅ | - | - |
| `get_env_vars` | Environment variables (redacted) | ✅ | ✅ | ✅ |
| `get_user_accounts` | User accounts and groups | ✅ | ✅ | ✅ |
| `get_sudo_config` | Sudo configuration | ✅ | ✅ | - |
| `get_ssh_config` | SSH daemon configuration | ✅ | ✅ | ✅ |
| `get_mac_status` | SELinux/AppArmor status | ✅ | - | - |
| `get_certificates` | System certificates | ✅ | ✅ | ✅ |

### Phase 1.3: Software Inventory ✅ (31/31)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_path_executables` | Executables in PATH directories | ✅ | ✅ | ✅ |
| `get_system_packages` | Installed system packages | ✅ | ✅ | ✅ |
| `get_python_packages` | Python packages from site-packages | ✅ | ✅ | ✅ |
| `get_node_packages` | Global Node.js packages | ✅ | ✅ | ✅ |
| `get_go_modules` | Go modules from GOPATH/pkg/mod | ✅ | ✅ | ✅ |
| `get_rust_packages` | Rust crates from .cargo/registry | ✅ | ✅ | ✅ |
| `get_ruby_gems` | Ruby gems from specifications | ✅ | ✅ | ✅ |
| `get_maven_packages` | Java/Maven packages from ~/.m2 | ✅ | ✅ | ✅ |
| `get_php_packages` | PHP packages from Composer | ✅ | ✅ | ✅ |
| `get_dotnet_packages` | .NET/NuGet packages | ✅ | ✅ | ✅ |
| `get_macos_applications` | Installed macOS applications | - | ✅ | - |
| `get_windows_hotfixes` | Windows hotfixes/updates | - | - | ✅ |
| `get_snap_packages` | Snap packages | ✅ | - | - |
| `get_flatpak_packages` | Flatpak packages | ✅ | - | - |
| `get_homebrew_casks` | Homebrew Casks (macOS GUI apps) | - | ✅ | - |
| `get_scoop_packages` | Scoop packages | - | - | ✅ |
| `get_windows_programs` | Windows programs from registry | - | - | ✅ |
| `get_windows_features` | Windows optional features | - | - | ✅ |
| `get_sbom_cyclonedx` | SBOM export (CycloneDX format) | ✅ | ✅ | ✅ |
| `get_sbom_spdx` | SBOM export (SPDX format) | ✅ | ✅ | ✅ |
| `get_vulnerabilities_osv` | Query OSV for vulnerabilities | ✅ | ✅ | ✅ |
| `get_vulnerabilities_debian` | Query Debian Security Tracker | ✅ | - | - |
| `get_vulnerabilities_nvd` | Query NVD for vulnerabilities | ✅ | ✅ | ✅ |
| `get_docker_images` | Docker images list | ✅ | ✅ | ✅ |
| `get_docker_containers` | Docker containers list | ✅ | ✅ | ✅ |
| `get_docker_image_history` | Docker image layer history | ✅ | ✅ | ✅ |
| `get_npm_lock` | Parse package-lock.json | ✅ | ✅ | ✅ |
| `get_pip_lock` | Parse requirements.txt/Pipfile.lock | ✅ | ✅ | ✅ |
| `get_cargo_lock` | Parse Cargo.lock | ✅ | ✅ | ✅ |
| `get_go_sum` | Parse go.sum | ✅ | ✅ | ✅ |
| `get_gemfile_lock` | Parse Gemfile.lock | ✅ | ✅ | ✅ |

### Phase 1.4: Application Discovery ✅ (2/2)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_applications` | Discover installed/running apps (web servers, databases, etc.) | ✅ | ✅ | ✅ |
| `get_app_config` | Read config files with sensitive data redaction | ✅ | ✅ | ✅ |

### Phase 1.5: Triage & Summary ✅ (25/25)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_os_info` | OS version, build, kernel, platform | ✅ | ✅ | ✅ |
| `get_system_profile` | CPU/RAM/disk/network summary | ✅ | ✅ | ✅ |
| `get_service_manager_info` | Service manager status | ✅ | ✅ | ✅ |
| `get_cloud_environment` | Cloud provider detection (AWS/GCP/Azure) | ✅ | ✅ | ✅ |
| `get_language_runtime_versions` | Python/Node/Go/Ruby/Java/etc versions | ✅ | ✅ | ✅ |
| `get_recent_reboots` | Recent reboot/shutdown events | ✅ | ✅ | ✅ |
| `get_service_failures_24h` | Failed services in last 24 hours | ✅ | ✅ | ✅ |
| `get_kernel_errors_24h` | Kernel errors in last 24 hours | ✅ | ✅ | ✅ |
| `get_oom_events` | Out-of-memory events | ✅ | ✅ | ✅ |
| `get_resource_incidents` | CPU/memory/disk resource spikes | ✅ | ✅ | ✅ |
| `get_config_changes_24h` | Package/config changes in 24h | ✅ | ✅ | ✅ |
| `get_failed_units` | Failed systemd/launchd/services | ✅ | ✅ | ✅ |
| `get_pending_timers` | Pending scheduled jobs | ✅ | ✅ | ✅ |
| `get_enabled_services` | All enabled/auto-start services | ✅ | ✅ | ✅ |
| `get_pending_updates` | Available system updates | ✅ | ✅ | ✅ |
| `get_security_basics` | Firewall, AV, updates status | ✅ | ✅ | ✅ |
| `get_admin_account_summary` | Users with admin/sudo privileges | ✅ | ✅ | ✅ |
| `get_exposed_services_summary` | Services listening on external interfaces | ✅ | ✅ | ✅ |
| `get_ssh_security_summary` | SSH configuration security | ✅ | ✅ | ✅ |
| `get_resource_limits` | System resource limits (ulimits) | ✅ | ✅ | ✅ |
| `get_installed_package_summary` | Package counts by manager | ✅ | ✅ | ✅ |
| `get_fs_health_summary` | Filesystem health and usage | ✅ | ✅ | ✅ |
| `get_incident_triage_snapshot` | Combined triage summary | ✅ | ✅ | ✅ |
| `get_security_posture_snapshot` | Security posture summary | ✅ | ✅ | ✅ |
| `get_full_system_snapshot` | Complete system snapshot | ✅ | ✅ | ✅ |

### Phase 1.6: Windows Enterprise Features ✅ (15/15)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_registry_key` | Read registry key and values | - | - | ✅ |
| `get_registry_tree` | Enumerate subkeys recursively | - | - | ✅ |
| `get_registry_security` | Key permissions and ownership | - | - | ✅ |
| `get_dcom_applications` | List registered DCOM apps | - | - | ✅ |
| `get_dcom_permissions` | DCOM launch/access permissions | - | - | ✅ |
| `get_dcom_identities` | DCOM RunAs identities per app | - | - | ✅ |
| `get_com_security_defaults` | Machine-wide COM security | - | - | ✅ |
| `get_iis_sites` | List all IIS websites | - | - | ✅ |
| `get_iis_app_pools` | Application pool configuration | - | - | ✅ |
| `get_iis_bindings` | Site bindings (ports, SSL, hostnames) | - | - | ✅ |
| `get_iis_virtual_dirs` | Virtual directories and applications | - | - | ✅ |
| `get_iis_handlers` | Handler mappings | - | - | ✅ |
| `get_iis_modules` | Installed IIS modules | - | - | ✅ |
| `get_iis_ssl_certs` | SSL certificate bindings | - | - | ✅ |
| `get_iis_auth_config` | Authentication settings per site | - | - | ✅ |

### Phase 1.7: Deep IIS Configuration 📋 (0/36)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_iis_http_sys_listeners` | HTTP.sys listener endpoints and SSL bindings | - | - | 📋 |
| `get_iis_request_filtering` | Request filtering rules | - | - | 📋 |
| `get_iis_ip_security` | IP allow/deny rules | - | - | 📋 |
| `get_iis_url_authorization` | URL authorization rules | - | - | 📋 |
| `get_iis_isapi_filters` | ISAPI filters | - | - | 📋 |
| `get_iis_isapi_cgi_restrictions` | ISAPI/CGI restrictions | - | - | 📋 |
| `get_iis_url_rewrite` | URL rewrite rules | - | - | 📋 |
| `get_iis_redirect_rules` | HTTP redirect rules | - | - | 📋 |
| `get_iis_failed_request_rules` | Failed request tracing rules | - | - | 📋 |
| `get_iis_compression` | Static/dynamic compression | - | - | 📋 |
| `get_iis_output_caching` | Output caching rules | - | - | 📋 |
| `get_iis_static_content` | Static content config | - | - | 📋 |
| `get_iis_default_document` | Default document list | - | - | 📋 |
| `get_iis_directory_browse` | Directory browsing | - | - | 📋 |
| `get_iis_custom_headers` | Custom HTTP headers | - | - | 📋 |
| `get_iis_mime_types` | MIME type mappings | - | - | 📋 |
| `get_iis_error_pages` | Custom error pages | - | - | 📋 |
| `get_iis_cors_config` | CORS configuration | - | - | 📋 |
| `get_iis_apppool_recycling` | App pool recycling settings | - | - | 📋 |
| `get_iis_apppool_process_model` | App pool process model | - | - | 📋 |
| `get_iis_apppool_cpu` | CPU throttling settings | - | - | 📋 |
| `get_iis_apppool_failure` | Rapid-fail protection | - | - | 📋 |
| `get_iis_aspnet_compilation` | ASP.NET compilation | - | - | 📋 |
| `get_iis_aspnet_session` | ASP.NET session state | - | - | 📋 |
| `get_iis_aspnet_machinekey` | Machine key config | - | - | 📋 |
| `get_iis_aspnet_custom_errors` | ASP.NET custom errors | - | - | 📋 |
| `get_iis_aspnet_globalization` | Globalization settings | - | - | 📋 |
| `get_iis_logging` | W3C/IIS logging config | - | - | 📋 |
| `get_iis_log_fields` | Custom log fields | - | - | 📋 |
| `get_iis_failed_requests` | Failed request traces | - | - | 📋 |
| `get_iis_worker_processes` | Running w3wp processes | - | - | 📋 |
| `get_iis_site_state` | Site state and counters | - | - | 📋 |
| `get_iis_websocket` | WebSocket settings | - | - | 📋 |
| `get_iis_http2` | HTTP/2 settings | - | - | 📋 |
| `get_iis_request_limits` | Request size limits | - | - | 📋 |
| `get_iis_fastcgi` | FastCGI configuration | - | - | 📋 |

### Phase 1.8: Complete IIS Coverage 📋 (0/48)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_iis_config_effective_diff` | Effective config diff (defaults vs overrides) | - | - | 📋 |
| `get_iis_application_init` | Application initialization | - | - | 📋 |
| `get_iis_config_diff` | Config vs server defaults | - | - | 📋 |
| `get_iis_locked_sections` | Locked config sections | - | - | 📋 |
| `get_iis_delegation_rules` | Feature delegation | - | - | 📋 |
| `get_iis_ftp_sites` | FTP sites | - | - | 📋 |
| `get_iis_ftp_ssl` | FTP over SSL | - | - | 📋 |
| `get_iis_ftp_user_isolation` | FTP user isolation | - | - | 📋 |
| `get_iis_ftp_authorization` | FTP authorization | - | - | 📋 |
| `get_iis_ftp_ip_security` | FTP IP security | - | - | 📋 |
| `get_iis_ftp_logging` | FTP logging | - | - | 📋 |
| `get_iis_ftp_firewall` | FTP firewall settings | - | - | 📋 |
| `get_iis_asp_settings` | Classic ASP settings | - | - | 📋 |
| `get_iis_asp_session` | ASP session state | - | - | 📋 |
| `get_iis_asp_limits` | ASP limits | - | - | 📋 |
| `get_iis_asp_com_plus` | COM+ settings | - | - | 📋 |
| `get_iis_asp_cache` | ASP script cache | - | - | 📋 |
| `get_iis_server_farms` | Web farm definitions | - | - | 📋 |
| `get_iis_arr_cache` | ARR disk cache | - | - | 📋 |
| `get_iis_arr_health` | ARR health probes | - | - | 📋 |
| `get_iis_arr_affinity` | Session affinity | - | - | 📋 |
| `get_iis_arr_routing` | Reverse proxy rules | - | - | 📋 |
| `get_iis_arr_settings` | ARR proxy settings | - | - | 📋 |
| `get_iis_client_cert_mapping` | Client cert mapping | - | - | 📋 |
| `get_iis_aspnet_impersonation` | ASP.NET impersonation | - | - | 📋 |
| `get_iis_forms_auth` | Forms authentication | - | - | 📋 |
| `get_iis_hidden_segments` | Hidden URL segments | - | - | 📋 |
| `get_iis_webdav` | WebDAV authoring | - | - | 📋 |
| `get_iis_double_escaping` | Allow double escaping | - | - | 📋 |
| `get_iis_high_bit_chars` | Allow high bit chars | - | - | 📋 |
| `get_iis_query_strings` | Query string filtering | - | - | 📋 |
| `get_iis_file_extensions` | File extension rules | - | - | 📋 |
| `get_iis_kernel_cache` | HTTP.sys kernel cache | - | - | 📋 |
| *+ 15 more queries* | | - | - | 📋 |

### Phase 1.9: Platform Security Controls 🔄 (0/28)

Extended platform-specific security controls for endpoint security posture assessment.

#### Windows Security Controls (12 queries)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_windows_defender_status` | Defender RTP, signatures, tamper protection | - | - | 🔄 |
| `get_windows_firewall_profiles` | Firewall profile states (Domain/Private/Public) | - | - | 🔄 |
| `get_bitlocker_status` | BitLocker encryption status per volume | - | - | 🔄 |
| `get_windows_smb_shares` | SMB shares and permissions summary | - | - | 🔄 |
| `get_windows_rdp_config` | RDP enabled, NLA status, port config | - | - | 🔄 |
| `get_windows_winrm_config` | WinRM listener and auth config | - | - | 🔄 |
| `get_windows_applocker_policy` | AppLocker enforcement mode | - | - | 🔄 |
| `get_windows_wdac_status` | WDAC/Code Integrity policy state | - | - | 🔄 |
| `get_windows_local_security_policy` | Password, lockout, audit policy summary | - | - | 🔄 |
| `get_windows_gpo_applied` | Applied GPOs for computer scope | - | - | 🔄 |
| `get_windows_credential_guard` | Credential Guard/LSA protection status | - | - | 🔄 |
| `get_windows_update_health` | Update health, pending updates, WSUS/WUfB | - | - | 🔄 |

#### macOS Security Controls (8 queries)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_macos_filevault_status` | FileVault disk encryption status | - | 🔄 | - |
| `get_macos_gatekeeper_status` | Gatekeeper and notarization status | - | 🔄 | - |
| `get_macos_sip_status` | System Integrity Protection status | - | 🔄 | - |
| `get_macos_xprotect_status` | XProtect/MRT version and status | - | 🔄 | - |
| `get_macos_pf_rules` | Packet Filter status and rules summary | - | 🔄 | - |
| `get_macos_mdm_profiles` | Installed MDM configuration profiles | - | 🔄 | - |
| `get_macos_tcc_permissions` | TCC permissions summary (sensitive) | - | 🔄 | - |
| `get_macos_security_log_events` | Unified log security events | - | 🔄 | - |

#### Linux Security Controls (7 queries)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_linux_auditd_status` | auditd status and rule summary | 🔄 | - | - |
| `get_linux_kernel_lockdown` | Kernel lockdown mode | 🔄 | - | - |
| `get_linux_sysctl_security` | Key sysctl hardening values | 🔄 | - | - |
| `get_linux_firewall_backend` | Active firewall (nftables/iptables/ufw) | 🔄 | - | - |
| `get_linux_mac_detailed` | Detailed SELinux/AppArmor status | 🔄 | - | - |
| `get_linux_package_repos` | Package repository summary | 🔄 | - | - |
| `get_linux_auto_updates` | Unattended upgrades status | 🔄 | - | - |

#### Cross-Platform (1 query)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_vendor_services` | OS vendor services inventory | 🔄 | 🔄 | 🔄 |

### Phase 1.10: Extended Language Ecosystems 📋 (0/21)

Additional language runtimes and package manager support.

#### Global Package Managers (11 queries)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_perl_packages` | CPAN/cpanm modules | 📋 | 📋 | 📋 |
| `get_lua_packages` | LuaRocks packages | 📋 | 📋 | 📋 |
| `get_haskell_packages` | Cabal/Stack packages | 📋 | 📋 | 📋 |
| `get_swift_packages` | Swift Package Manager cache | 📋 | 📋 | - |
| `get_elixir_packages` | Hex/Mix packages | 📋 | 📋 | 📋 |
| `get_r_packages` | CRAN packages | 📋 | 📋 | 📋 |
| `get_julia_packages` | Julia Pkg packages | 📋 | 📋 | 📋 |
| `get_dart_packages` | Dart/Flutter pub cache | 📋 | 📋 | 📋 |
| `get_ocaml_packages` | OPAM packages | 📋 | 📋 | - |
| `get_conda_packages` | Conda environments and packages | 📋 | 📋 | 📋 |
| `get_gradle_packages` | Gradle dependency cache | 📋 | 📋 | 📋 |

#### Lock File Parsers (10 queries)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_yarn_lock` | Parse yarn.lock (Node.js Yarn) | 📋 | 📋 | 📋 |
| `get_pnpm_lock` | Parse pnpm-lock.yaml (Node.js pnpm) | 📋 | 📋 | 📋 |
| `get_poetry_lock` | Parse poetry.lock (Python Poetry) | 📋 | 📋 | 📋 |
| `get_composer_lock` | Parse composer.lock (PHP) | 📋 | 📋 | 📋 |
| `get_mix_lock` | Parse mix.lock (Elixir) | 📋 | 📋 | 📋 |
| `get_pubspec_lock` | Parse pubspec.lock (Dart/Flutter) | 📋 | 📋 | 📋 |
| `get_swift_resolved` | Parse Package.resolved (Swift) | 📋 | 📋 | - |
| `get_podfile_lock` | Parse Podfile.lock (CocoaPods) | - | 📋 | - |
| `get_gradle_lock` | Parse gradle.lockfile | 📋 | 📋 | 📋 |
| `get_conda_lock` | Parse conda-lock.yml | 📋 | 📋 | 📋 |

### Phase 2.0: Enhanced Diagnostics ✅ (6/6)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_gpu_info` | GPU details (memory, utilization, temp) | ✅ | ✅ | ✅ |
| `get_container_stats` | Real-time container resource stats | ✅ | ✅ | ✅ |
| `get_container_logs` | Container stdout/stderr logs | ✅ | ✅ | ✅ |
| `generate_system_report` | Full system diagnostic report | ✅ | ✅ | ✅ |
| `generate_iis_report` | IIS-specific diagnostic report | - | - | ✅ |
| `get_processes_sampled` | Accurate CPU% via time-delta sampling | ✅ | ✅ | ✅ |

### Phase 3: Storage Deep Dive ✅ (5/5)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_smart_health` | SMART disk health data | ✅ | ✅ | ✅ |
| `get_io_latency` | Disk I/O latency tracking | ✅ | ✅ | ✅ |
| `get_fs_events` | Filesystem event monitoring | ✅ | ✅ | ✅ |
| `get_mount_changes` | Mount point change detection | ✅ | ✅ | ✅ |
| `get_volume_status` | ZFS/LVM/RAID/Storage Spaces status | ✅ | ✅ | ✅ |

### Phase 4: Network Intelligence 📋 (0/5)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_connection_tracking` | Per-connection stats with process mapping | 📋 | 📋 | 📋 |
| `get_dns_stats` | DNS resolution statistics | 📋 | 📋 | 📋 |
| `get_firewall_deep` | Deep firewall rule inspection | 📋 | 📋 | 📋 |
| `get_wifi_metrics` | WiFi signal strength and quality | 📋 | 📋 | 📋 |
| `get_network_latency` | Network latency probes (ICMP/TCP/HTTP) | 📋 | 📋 | 📋 |

### Phase 5: Analytics & Trends 📋 (0/4)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_historical_metrics` | Historical CPU/memory/disk trends | 📋 | 📋 | 📋 |
| `get_anomaly_detection` | Detect anomalous patterns | 📋 | 📋 | 📋 |
| `get_capacity_forecast` | Capacity planning forecasts | 📋 | 📋 | 📋 |
| `get_trend_analysis` | Performance trend analysis | 📋 | 📋 | 📋 |

### Phase 6: Automation & Alerting 📋 (0/5)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `set_alert_threshold` | Configure alert thresholds | 📋 | 📋 | 📋 |
| `get_alert_status` | Current alert status | 📋 | 📋 | 📋 |
| `get_remediation_suggestions` | AI-generated fix suggestions | 📋 | 📋 | 📋 |
| `execute_safe_remediation` | Execute pre-approved fixes | 📋 | 📋 | 📋 |
| `get_runbook_recommendations` | Runbook recommendations | 📋 | 📋 | 📋 |

### Phase 7: Security & Compliance 📋 (0/5)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_security_scan` | Deep security vulnerability scan | 📋 | 📋 | 📋 |
| `get_compliance_check` | CIS/STIG compliance checking | 📋 | 📋 | 📋 |
| `get_forensic_snapshot` | Forensic data collection | 📋 | 📋 | 📋 |
| `get_audit_trail` | Security audit trail | 📋 | 📋 | 📋 |
| `get_hardening_recommendations` | Security hardening tips | 📋 | 📋 | 📋 |

### Phase 8: Integration & Plugins 📋 (0/4)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `get_prometheus_export` | Export metrics in Prometheus format | 📋 | 📋 | 📋 |
| `get_cloud_inventory` | Cloud resource inventory | 📋 | 📋 | 📋 |
| `get_multi_host_summary` | Multi-host aggregated view | 📋 | 📋 | 📋 |
| `get_plugin_status` | Custom plugin status | 📋 | 📋 | 📋 |

### Phase 9: LLM Features 📋 (0/3)

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
| `query_natural_language` | Natural language system queries | 📋 | 📋 | 📋 |
| `get_auto_diagnosis` | AI-powered auto-diagnosis | 📋 | 📋 | 📋 |
| `get_explanation` | Explain system state in plain English | 📋 | 📋 | 📋 |

---

## Quick Start

```bash
# Build
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Run (stdio mode - for MCP clients)
./mcp-sysinfo

# Run via SSH (remote host)
ssh user@server "mcp-sysinfo"
```

### Quick Start with Docker

```bash
# Clone and start HTTP server
git clone https://github.com/levantar-ai/mcp-sysinfo
cd mcp-sysinfo
docker compose up mcp-sysinfo-http

# Test it
curl -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_uptime"}}'
```

For privileged access (all system queries):

```bash
docker compose --profile privileged up mcp-sysinfo-privileged
```

See [examples/](examples/) for Go and Python client examples.

### Claude Code Integration

Add mcp-sysinfo to [Claude Code](https://claude.ai/code) for AI-powered system diagnostics:

**Local machine (stdio):**

```bash
# Linux/macOS
claude mcp add --transport stdio sysinfo -- /path/to/mcp-sysinfo

# Windows
claude mcp add --transport stdio sysinfo -- C:\path\to\mcp-sysinfo-windows-amd64.exe
```

**Remote Windows VM (HTTP):**

```powershell
# 1. On Windows VM: Download and start server with token auth
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://github.com/levantar-ai/mcp-sysinfo/releases/latest/download/mcp-sysinfo-windows-amd64" -OutFile "mcp-sysinfo.exe"
.\mcp-sysinfo.exe --transport http --listen 0.0.0.0:8080 --token my-secret-token

# 2. Open firewall if needed
New-NetFirewallRule -DisplayName "MCP SysInfo" -Direction Inbound -Port 8080 -Protocol TCP -Action Allow
```

```bash
# 3. On host: Connect Claude Code (replace IP with your VM's IP)
claude mcp add --transport http sysinfo-windows http://10.211.55.x:8080 \
  --header "Authorization: Bearer my-secret-token"
```

**Verify:**

```bash
claude mcp list   # List configured servers
/mcp              # Check status inside Claude Code
```

See [Quick Start](docs/getting-started/quickstart.md) for detailed setup instructions.

### Resource Impact

Every query respects strict budgets:

| Impact | CPU | Memory | Time | Behavior |
|--------|-----|--------|------|----------|
| Minimal | <1% | <1MB | <100ms | Always allowed |
| Low | <5% | <10MB | <1s | Default allowed |
| Medium | <10% | <50MB | <5s | Requires opt-in |
| High | - | - | - | **Blocked** |

---

## Installation

### Prerequisites

- Go 1.22+
- No external dependencies (uses only OS built-in tools)

### Build

```bash
# Clone
git clone https://github.com/yourorg/mcp-sysinfo
cd mcp-sysinfo

# Build for current platform
go build -o mcp-sysinfo ./cmd/mcp-sysinfo

# Cross-compile
GOOS=linux GOARCH=amd64 go build -o mcp-sysinfo-linux ./cmd/mcp-sysinfo
GOOS=darwin GOARCH=arm64 go build -o mcp-sysinfo-darwin ./cmd/mcp-sysinfo
GOOS=windows GOARCH=amd64 go build -o mcp-sysinfo.exe ./cmd/mcp-sysinfo
```

### Configure for Remote Access

See [SECURITY.md](SECURITY.md) for complete configuration reference.

```yaml
# /etc/mcp-sysinfo/config.yaml

# Transport: stdio (default), unix, pipe, https
transport: unix
socket:
  path: /var/run/mcp-sysinfo.sock
  mode: 0600

# Authentication (required for https)
auth:
  enabled: true
  jwt:
    issuer: "https://auth.example.com"
    audience: "mcp-sysinfo"
    jwks_uri: "https://auth.example.com/.well-known/jwks.json"

# Scopes
queries:
  sensitive:
    enabled: false  # Explicit opt-in required

# Audit
audit:
  enabled: true
  path: /var/log/mcp-sysinfo/audit.jsonl
```

---

## Teleport Integration

MCP System Info is designed to work with [Teleport's MCP support](https://goteleport.com/docs/machine-id/access-guides/mcp/):

```yaml
# Teleport role for MCP access
kind: role
metadata:
  name: mcp-diagnostics
spec:
  allow:
    mcp_servers:
      - labels:
          app: mcp-sysinfo
        commands:
          - get_cpu_info
          - get_memory_info
          - get_disk_info
          - get_processes
```

Teleport provides:
- SSO authentication (OIDC, SAML, GitHub)
- Role-based access control per query
- Session recording and audit
- Certificate-based host identity

---

## SSH Access

For ad-hoc remote access without additional infrastructure:

```bash
# Direct execution over SSH
ssh user@server "mcp-sysinfo --query get_cpu_info"

# Persistent session for MCP client
ssh -tt user@server "mcp-sysinfo --transport stdio"
```

SSH provides authentication. The server runs in stdio mode with no network listener.

---

## HTTP Transport with Authentication

For remote access with OAuth 2.1 / OIDC authentication:

### Option 1: OIDC (Enterprise IdP)

Integrate with your existing identity provider (Okta, Azure AD, Auth0, Keycloak):

```bash
# Run with OIDC authentication
mcp-sysinfo --transport http \
    --listen 0.0.0.0:8443 \
    --tls-cert /etc/mcp/cert.pem \
    --tls-key /etc/mcp/key.pem \
    --oidc-issuer https://enterprise.okta.com \
    --oidc-audience mcp-sysinfo
```

The MCP server fetches JWKS from the IdP and validates tokens locally.

### Option 2: OAuth Token Introspection

Use the built-in token server or any OAuth 2.1 authorization server:

```bash
# Start the built-in token server
mcp-token-server serve \
    --listen 127.0.0.1:8444 \
    --issuer http://localhost:8444 \
    --audience mcp-sysinfo \
    --clients /etc/mcp/clients.json

# Start MCP server with OAuth introspection
mcp-sysinfo --transport http \
    --listen 127.0.0.1:8080 \
    --auth-server http://127.0.0.1:8444 \
    --client-id mcp-sysinfo \
    --client-secret $SECRET
```

### Get a Token and Call the API

```bash
# Get access token (client credentials flow)
TOKEN=$(curl -s -X POST http://localhost:8444/token \
    -d "grant_type=client_credentials" \
    -d "client_id=myapp" \
    -d "client_secret=mysecret" \
    | jq -r '.access_token')

# Call MCP server with token
curl -X POST http://localhost:8080/ \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_uptime"}}'
```

### CLI Flags Reference

| Flag | Description |
|------|-------------|
| `--transport http` | Enable HTTP transport (default: stdio) |
| `--listen <addr>` | Listen address (default: 127.0.0.1:8080) |
| `--server-url <url>` | Public server URL for OAuth metadata |
| `--tls-cert <file>` | TLS certificate file |
| `--tls-key <file>` | TLS key file |
| `--oidc-issuer <url>` | OIDC issuer URL (e.g., https://okta.com) |
| `--oidc-audience <str>` | Expected JWT audience claim |
| `--auth-server <url>` | OAuth auth server for introspection |
| `--client-id <id>` | Client ID for introspection |
| `--client-secret <str>` | Client secret for introspection |

See [SECURITY.md](SECURITY.md) for complete authentication documentation.

---

## Testing

```bash
# Unit tests
go test -v ./...

# Integration tests (real OS calls)
INTEGRATION_TEST=true go test -v -tags=integration ./test/integration/...
```

---

## Documentation

| Document | Description |
|----------|-------------|
| **[SECURITY.md](SECURITY.md)** | Security architecture, auth, deployment |
| [docs/00-overview.md](docs/00-overview.md) | Architecture and design rationale |
| [docs/08-system-hooks.md](docs/08-system-hooks.md) | Phase 1.6: 31 deep introspection queries |
| [docs/09-sbom-inventory.md](docs/09-sbom-inventory.md) | Phase 1.7: Software inventory |
| [docs/10-query-profiles.md](docs/10-query-profiles.md) | Query profiles for efficient investigations |
| [docs/11-platform-native-features.md](docs/11-platform-native-features.md) | Platform-specific native APIs (WMI, procfs, IOKit) |
| [api/openapi.yaml](api/openapi.yaml) | OpenAPI 3.1 specification |
| [charts/mcp-sysinfo/](charts/mcp-sysinfo/) | Helm chart for Kubernetes |
| [examples/](examples/) | Go and Python client examples |

---

## Kubernetes Deployment

Deploy to Kubernetes using Helm:

```bash
# Install from local chart
helm install mcp-sysinfo ./charts/mcp-sysinfo

# With OIDC authentication
helm install mcp-sysinfo ./charts/mcp-sysinfo \
  --set mcp.auth.oidc.enabled=true \
  --set mcp.auth.oidc.issuer=https://your-idp.example.com \
  --set mcp.auth.oidc.audience=mcp-sysinfo

# With Prometheus ServiceMonitor
helm install mcp-sysinfo ./charts/mcp-sysinfo \
  --set metrics.serviceMonitor.enabled=true
```

See [charts/mcp-sysinfo/README.md](charts/mcp-sysinfo/README.md) for full configuration options.

---

## Prometheus Metrics

When running in HTTP mode, Prometheus metrics are available at `/metrics`:

```bash
curl http://localhost:8080/metrics
```

**Available metrics:**

| Metric | Description |
|--------|-------------|
| `mcp_sysinfo_http_requests_total` | Total HTTP requests by method, path, status |
| `mcp_sysinfo_http_request_duration_seconds` | Request latency histogram |
| `mcp_sysinfo_tool_calls_total` | Tool calls by name and scope |
| `mcp_sysinfo_tool_call_duration_seconds` | Tool execution latency |
| `mcp_sysinfo_tool_call_errors_total` | Tool errors by type |
| `mcp_sysinfo_auth_requests_total` | Authentication attempts |

---

## Project Status

| Phase | Focus | Progress | Queries |
|-------|-------|----------|---------|
| **1.0** | Core Metrics | ✅ Complete | 7/7 |
| **1.1** | Log Access | ✅ Complete | 6/6 |
| **1.2** | System Hooks + Security | ✅ Complete | 37/37 |
| **1.3** | SBOM & Inventory | ✅ Complete | 31/31 |
| **1.4** | App Discovery & Config | ✅ Complete | 2/2 |
| **1.5** | Triage & Summary | ✅ Complete | 25/25 |
| **1.6** | Windows Enterprise | ✅ Complete | 15/15 |
| **1.7** | Deep IIS Configuration | 📋 Planned | 0/36 |
| **1.8** | Complete IIS Coverage | 📋 Planned | 0/48 |
| **1.9** | Platform Security Controls | 🔄 In Progress | 0/28 |
| **1.10** | Extended Language Ecosystems | 📋 Planned | 0/21 |
| **2.0** | Enhanced Diagnostics | ✅ Complete | 6/6 |
| **3** | Storage Deep Dive | ✅ Complete | 5/5 |
| 4 | Network Intelligence | 📋 Planned | 0/5 |
| 5 | Analytics & Trends | 📋 Planned | 0/4 |
| 6 | Automation & Alerting | 📋 Planned | 0/5 |
| 7 | Security & Compliance | 📋 Planned | 0/5 |
| 8 | Integration & Plugins | 📋 Planned | 0/4 |
| 9 | LLM Features | 📋 Planned | 0/3 |

**Implemented: 134/293 queries (46%)**

### Cross-Platform Architecture

All queries are cross-platform (Linux, macOS, Windows) using only native OS APIs:

| Category | Linux | macOS | Windows |
|----------|-------|-------|---------|
| System Info | `/proc`, sysctl | sysctl, IOKit | WMI, Registry |
| Services | systemd, sysvinit | launchd | SCM, Event Log |
| Logs | journald, syslog | unified logs | Event Log |
| Firewall | iptables/nftables | pfctl | NetFirewallRule |

**No external dependencies required.** See [TODO.md](TODO.md) for full implementation details.

---

## License

levantar-ai/mcp-sysinfo is licensed under the GNU Affero General Public License v3 (AGPLv3).

We offer a commercial licensing option for enterprises who require a proprietary license (for example to embed this project into closed-source products, or to run closed modifications in a hosted service). If you are interested in enterprise licensing, support, or custom modules, please contact: sales@levantar.ai

For licensing questions, contact: licensing@levantar.ai
