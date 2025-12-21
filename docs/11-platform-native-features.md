# Platform-Native Features

Each platform offers unique introspection capabilities beyond generic metrics. This document details platform-specific queries that leverage native APIs and subsystems.

## Design Principles

- **Zero external dependencies** - Use only built-in OS tools and APIs
- **Structured output** - Parse native formats into consistent JSON
- **Locale hardening** - `LC_ALL=C` on Unix, invariant output on Windows
- **Read-only** - No modifications, only observation

---

## Windows-Specific Features

Windows offers rich introspection via WMI, COM, Registry, and Event Logs.

### WMI / CIM Queries

| Query | Description | WMI Class | Impact |
|-------|-------------|-----------|:------:|
| `get_wmi_os` | OS version, install date, serial | `Win32_OperatingSystem` | 🟢 |
| `get_wmi_bios` | BIOS vendor, version, serial | `Win32_BIOS` | 🟢 |
| `get_wmi_cpu` | Detailed CPU info | `Win32_Processor` | 🟢 |
| `get_wmi_disk` | Physical disk details | `Win32_DiskDrive` | 🟢 |
| `get_wmi_network_adapter` | NIC details, MAC, speed | `Win32_NetworkAdapter` | 🟢 |
| `get_wmi_services` | Service status, start mode | `Win32_Service` | 🟡 |
| `get_wmi_processes` | Detailed process info | `Win32_Process` | 🟡 |
| `get_wmi_startup` | Startup programs | `Win32_StartupCommand` | 🟢 |
| `get_wmi_shares` | Network shares | `Win32_Share` | 🟢 |
| `get_wmi_printers` | Installed printers | `Win32_Printer` | 🟢 |
| `get_wmi_hotfixes` | Installed updates | `Win32_QuickFixEngineering` | 🟡 |

**Implementation**: PowerShell `Get-CimInstance` or `Get-WmiObject`

```powershell
# Example: Get OS info
Get-CimInstance -ClassName Win32_OperatingSystem |
  Select-Object Caption, Version, InstallDate, SerialNumber
```

### COM / DCOM Registration

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_com_classes` | Registered COM classes | Registry CLSID | 🟡 |
| `get_dcom_apps` | DCOM application registrations | `dcomcnfg` / Registry | 🟡 |
| `get_com_servers` | In-process/out-of-process servers | Registry InProcServer32 | 🟡 |
| `get_typelibs` | Registered type libraries | Registry TypeLib | 🟢 |

**Registry Paths**:
- `HKLM\SOFTWARE\Classes\CLSID` - COM class registrations
- `HKLM\SOFTWARE\Classes\AppID` - DCOM applications
- `HKLM\SOFTWARE\Classes\TypeLib` - Type libraries

```powershell
# Example: List COM servers
Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" |
  Where-Object { $_.GetSubKeyNames() -contains "InProcServer32" } |
  ForEach-Object {
    $path = (Get-ItemProperty "$($_.PSPath)\InProcServer32").'(default)'
    [PSCustomObject]@{ CLSID = $_.PSChildName; Path = $path }
  }
```

### Windows Registry

| Query | Description | Hive | Impact |
|-------|-------------|------|:------:|
| `get_installed_software` | Installed programs | HKLM Uninstall | 🟢 |
| `get_run_keys` | Auto-run entries | HKLM/HKCU Run | 🟢 |
| `get_services_registry` | Service configurations | HKLM Services | 🟡 |
| `get_network_profiles` | Network location profiles | HKLM NetworkList | 🟢 |
| `get_usb_history` | USB device history | HKLM USBSTOR | 🟢 |
| `get_mru_lists` | Recent files/commands | HKCU MRU keys | 🟡 |
| `get_shell_extensions` | Shell extensions | HKLM ShellEx | 🟡 |
| `get_browser_helpers` | BHOs (IE extensions) | HKLM BHO | 🟢 |

**Security Note**: Registry queries can expose sensitive paths but not credentials. MRU lists may reveal user activity patterns.

```powershell
# Example: Auto-run entries
$paths = @(
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
$paths | ForEach-Object { Get-ItemProperty $_ }
```

### Windows Event Logs

| Query | Description | Log | Impact |
|-------|-------------|-----|:------:|
| `get_system_events` | System log (errors, warnings) | System | 🟡 |
| `get_application_events` | Application log | Application | 🟡 |
| `get_security_events` | Security log (logins, audit) | Security | 🔴 Sensitive |
| `get_powershell_events` | PowerShell execution log | PowerShell | 🟡 |
| `get_defender_events` | Windows Defender events | Defender | 🟡 |
| `get_task_scheduler_events` | Scheduled task history | TaskScheduler | 🟢 |
| `get_rdp_events` | RDP connection history | TerminalServices | 🔴 Sensitive |

**Implementation**: `wevtutil` or `Get-WinEvent`

```powershell
# Example: Recent system errors
Get-WinEvent -FilterHashtable @{
  LogName = 'System'
  Level = 2  # Error
  StartTime = (Get-Date).AddHours(-24)
} -MaxEvents 100
```

### Windows-Specific System State

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_windows_features` | Installed Windows features | DISM / `Get-WindowsFeature` | 🟡 |
| `get_optional_features` | Optional features status | `Get-WindowsOptionalFeature` | 🟡 |
| `get_appx_packages` | UWP/Store apps | `Get-AppxPackage` | 🟢 |
| `get_drivers` | Loaded drivers | `driverquery` | 🟢 |
| `get_certificates` | Certificate stores | `certutil` / CertStore | 🟡 |
| `get_gpo_result` | Applied Group Policy | `gpresult` | 🟡 |
| `get_local_admins` | Local administrators | `net localgroup` | 🟡 |
| `get_audit_policy` | Audit policy settings | `auditpol` | 🟢 |
| `get_firewall_profiles` | Firewall profile status | `netsh advfirewall` | 🟢 |
| `get_bitlocker_status` | BitLocker encryption status | `manage-bde` | 🟢 |

### IIS Web Server (Comprehensive)

Complete IIS introspection for enterprise web server diagnostics. **Phase 1.10** (implemented) provides core queries, **Phase 1.11** (planned) adds deep configuration access.

#### Phase 1.10 - Core IIS (Implemented ✅)

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_sites` | All websites with state | `Get-Website` | 🟢 |
| `get_iis_app_pools` | Application pool config | `Get-ChildItem IIS:\AppPools` | 🟢 |
| `get_iis_bindings` | Site bindings (ports, SSL, hostnames) | WebAdministration | 🟢 |
| `get_iis_virtual_dirs` | Virtual directories per site | `Get-WebVirtualDirectory` | 🟢 |
| `get_iis_handlers` | Handler mappings | `Get-WebHandler` | 🟢 |
| `get_iis_modules` | Global and managed modules | `Get-WebGlobalModule` | 🟢 |
| `get_iis_ssl_certs` | SSL certificate bindings | `netsh http show sslcert` | 🟢 |
| `get_iis_auth_config` | Authentication settings per site | WebConfiguration | 🟢 |

#### Phase 1.11 - Deep IIS Configuration (Planned 🚧)

**Security & Request Filtering**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_request_filtering` | Request filtering rules (verbs, extensions, URLs) | system.webServer/security/requestFiltering | 🟢 |
| `get_iis_ip_security` | IP allow/deny rules per site | system.webServer/security/ipSecurity | 🟡 |
| `get_iis_url_authorization` | URL authorization rules | system.webServer/security/authorization | 🟡 |
| `get_iis_isapi_filters` | ISAPI filters | system.webServer/isapiFilters | 🟢 |
| `get_iis_isapi_cgi_restrictions` | ISAPI/CGI restrictions | system.webServer/security/isapiCgiRestriction | 🟢 |

**URL Rewriting & Routing**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_url_rewrite` | URL rewrite rules | system.webServer/rewrite | 🟢 |
| `get_iis_redirect_rules` | HTTP redirect rules | system.webServer/httpRedirect | 🟢 |
| `get_iis_failed_request_rules` | Failed request tracing rules | system.webServer/tracing | 🟢 |

**Compression & Caching**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_compression` | Static/dynamic compression settings | system.webServer/httpCompression | 🟢 |
| `get_iis_output_caching` | Output caching rules | system.webServer/caching | 🟢 |
| `get_iis_static_content` | Static content configuration | system.webServer/staticContent | 🟢 |

**HTTP Settings**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_default_document` | Default document list | system.webServer/defaultDocument | 🟢 |
| `get_iis_directory_browse` | Directory browsing settings | system.webServer/directoryBrowse | 🟢 |
| `get_iis_custom_headers` | Custom HTTP response headers | system.webServer/httpProtocol | 🟢 |
| `get_iis_mime_types` | MIME type mappings | system.webServer/staticContent/mimeMap | 🟢 |
| `get_iis_error_pages` | Custom error pages | system.webServer/httpErrors | 🟢 |
| `get_iis_cors_config` | CORS configuration | system.webServer/cors | 🟢 |

**Application Pool Deep Config**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_apppool_recycling` | Recycling settings (time, memory, requests) | applicationPools/recycling | 🟢 |
| `get_iis_apppool_process_model` | Process model (identity, idle timeout, ping) | applicationPools/processModel | 🟡 |
| `get_iis_apppool_cpu` | CPU throttling settings | applicationPools/cpu | 🟢 |
| `get_iis_apppool_failure` | Rapid-fail protection settings | applicationPools/failure | 🟢 |

**ASP.NET Configuration**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_aspnet_compilation` | Compilation settings (debug, batch) | system.web/compilation | 🟢 |
| `get_iis_aspnet_session` | Session state configuration | system.web/sessionState | 🟡 |
| `get_iis_aspnet_machinekey` | Machine key configuration (validation/decryption) | system.web/machineKey | 🔴 Sensitive |
| `get_iis_aspnet_custom_errors` | ASP.NET custom errors | system.web/customErrors | 🟢 |
| `get_iis_aspnet_globalization` | Globalization settings | system.web/globalization | 🟢 |

**Diagnostics & Logging**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_logging` | W3C/IIS logging configuration | system.webServer/httpLogging | 🟢 |
| `get_iis_log_fields` | Custom log fields | system.applicationHost/log | 🟢 |
| `get_iis_failed_requests` | Failed request trace logs | FREB logs | 🟡 |
| `get_iis_worker_processes` | Currently running w3wp.exe processes | `Get-IISWorkerProcess` | 🟢 |
| `get_iis_site_state` | Detailed site state and counters | WMI IIsWebInfo | 🟢 |

**Advanced Features**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_websocket` | WebSocket protocol settings | system.webServer/webSocket | 🟢 |
| `get_iis_http2` | HTTP/2 settings | system.webServer/http2 | 🟢 |
| `get_iis_request_limits` | Request limits (maxContentLength, etc.) | system.webServer/security/requestFiltering/requestLimits | 🟢 |
| `get_iis_fastcgi` | FastCGI application configuration | system.webServer/fastCgi | 🟢 |
| `get_iis_application_init` | Application initialization settings | system.webServer/applicationInitialization | 🟢 |

**Configuration Comparison**

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_iis_config_diff` | Compare site config to server defaults | applicationHost.config diff | 🟢 |
| `get_iis_locked_sections` | Locked configuration sections | system.webServer/security/access | 🟢 |
| `get_iis_delegation_rules` | Feature delegation settings | administration.config | 🟢 |

**Total: 8 implemented + 35 planned = 43 IIS queries**

---

## Linux-Specific Features

Linux provides rich introspection via procfs, sysfs, systemd, and kernel interfaces.

### Procfs (/proc)

| Query | Description | Path | Impact |
|-------|-------------|------|:------:|
| `get_proc_meminfo` | Detailed memory stats | `/proc/meminfo` | 🟢 |
| `get_proc_cpuinfo` | CPU details per core | `/proc/cpuinfo` | 🟢 |
| `get_proc_loadavg` | Load average + running procs | `/proc/loadavg` | 🟢 |
| `get_proc_vmstat` | Virtual memory statistics | `/proc/vmstat` | 🟢 |
| `get_proc_diskstats` | Disk I/O statistics | `/proc/diskstats` | 🟢 |
| `get_proc_net_dev` | Network interface stats | `/proc/net/dev` | 🟢 |
| `get_proc_net_tcp` | TCP connection table | `/proc/net/tcp` | 🟡 |
| `get_proc_net_udp` | UDP endpoints | `/proc/net/udp` | 🟡 |
| `get_proc_mounts` | Mounted filesystems | `/proc/mounts` | 🟢 |
| `get_proc_modules` | Loaded kernel modules | `/proc/modules` | 🟢 |
| `get_proc_interrupts` | IRQ statistics | `/proc/interrupts` | 🟢 |
| `get_proc_cmdline` | Kernel boot parameters | `/proc/cmdline` | 🟢 |

**Per-Process** (requires PID parameter):

| Query | Description | Path | Impact |
|-------|-------------|------|:------:|
| `get_proc_status` | Process status/memory | `/proc/[pid]/status` | 🟢 |
| `get_proc_fd` | Open file descriptors | `/proc/[pid]/fd` | 🟡 |
| `get_proc_maps` | Memory mappings | `/proc/[pid]/maps` | 🟡 |
| `get_proc_environ` | Environment variables | `/proc/[pid]/environ` | 🔴 Sensitive |
| `get_proc_cgroup` | Cgroup membership | `/proc/[pid]/cgroup` | 🟢 |
| `get_proc_ns` | Namespace IDs | `/proc/[pid]/ns` | 🟢 |

### Sysfs (/sys)

| Query | Description | Path | Impact |
|-------|-------------|------|:------:|
| `get_sys_block` | Block device attributes | `/sys/block/` | 🟢 |
| `get_sys_class_net` | Network interface details | `/sys/class/net/` | 🟢 |
| `get_sys_thermal` | Thermal zones, temps | `/sys/class/thermal/` | 🟢 |
| `get_sys_power` | Power supply status | `/sys/class/power_supply/` | 🟢 |
| `get_sys_cpu` | CPU topology, frequency | `/sys/devices/system/cpu/` | 🟢 |
| `get_sys_memory` | Memory nodes (NUMA) | `/sys/devices/system/memory/` | 🟢 |
| `get_sys_dmi` | DMI/SMBIOS data | `/sys/class/dmi/id/` | 🟢 |
| `get_sys_scsi` | SCSI device info | `/sys/class/scsi_device/` | 🟢 |
| `get_sys_pci` | PCI device tree | `/sys/bus/pci/devices/` | 🟢 |
| `get_sys_usb` | USB device tree | `/sys/bus/usb/devices/` | 🟢 |

### Systemd

| Query | Description | Command | Impact |
|-------|-------------|---------|:------:|
| `get_systemd_units` | All unit status | `systemctl list-units` | 🟢 |
| `get_systemd_services` | Service unit status | `systemctl list-units --type=service` | 🟢 |
| `get_systemd_timers` | Timer units (cron replacement) | `systemctl list-timers` | 🟢 |
| `get_systemd_sockets` | Socket units | `systemctl list-sockets` | 🟢 |
| `get_systemd_targets` | Target units | `systemctl list-units --type=target` | 🟢 |
| `get_systemd_failed` | Failed units | `systemctl --failed` | 🟢 |
| `get_journald_logs` | Journal logs (structured) | `journalctl --output=json` | 🟡 |
| `get_journald_boot` | Boot log | `journalctl -b` | 🟡 |
| `get_systemd_analyze` | Boot timing analysis | `systemd-analyze` | 🟢 |
| `get_loginctl_sessions` | Login sessions | `loginctl list-sessions` | 🟢 |
| `get_loginctl_users` | Logged-in users | `loginctl list-users` | 🟢 |

```bash
# Example: Service status as JSON
systemctl show nginx.service --property=ActiveState,SubState,MainPID,MemoryCurrent
```

### Cgroups

| Query | Description | Path | Impact |
|-------|-------------|------|:------:|
| `get_cgroup_v2_controllers` | Available controllers | `/sys/fs/cgroup/cgroup.controllers` | 🟢 |
| `get_cgroup_memory` | Memory limits/usage | `/sys/fs/cgroup/.../memory.*` | 🟢 |
| `get_cgroup_cpu` | CPU limits/usage | `/sys/fs/cgroup/.../cpu.*` | 🟢 |
| `get_cgroup_io` | I/O limits/stats | `/sys/fs/cgroup/.../io.*` | 🟢 |
| `get_cgroup_pids` | PID limits | `/sys/fs/cgroup/.../pids.*` | 🟢 |

### Security Subsystems

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_selinux_status` | SELinux mode, policy | `sestatus` | 🟢 |
| `get_selinux_booleans` | SELinux booleans | `getsebool -a` | 🟢 |
| `get_apparmor_status` | AppArmor status | `aa-status` | 🟢 |
| `get_apparmor_profiles` | Loaded profiles | `/sys/kernel/security/apparmor/` | 🟢 |
| `get_capabilities` | Process capabilities | `capsh --print` | 🟢 |
| `get_seccomp_status` | Seccomp filter status | `/proc/[pid]/status` | 🟢 |
| `get_audit_rules` | Audit rules | `auditctl -l` | 🟡 |
| `get_pam_config` | PAM configuration | `/etc/pam.d/` | 🟢 |

### Linux-Specific System State

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_os_release` | Distribution info | `/etc/os-release` | 🟢 |
| `get_machine_id` | Machine identifier | `/etc/machine-id` | 🟢 |
| `get_hostname_info` | Hostname details | `hostnamectl` | 🟢 |
| `get_locale_info` | Locale settings | `localectl` | 🟢 |
| `get_timedatectl` | Time/timezone/NTP | `timedatectl` | 🟢 |
| `get_lsmod` | Loaded kernel modules | `lsmod` | 🟢 |
| `get_modinfo` | Module details | `modinfo [module]` | 🟢 |
| `get_sysctl` | Kernel parameters | `sysctl -a` | 🟡 |
| `get_limits` | Resource limits | `/etc/security/limits.conf` | 🟢 |
| `get_fstab` | Filesystem table | `/etc/fstab` | 🟢 |
| `get_crypttab` | Encrypted volumes | `/etc/crypttab` | 🟢 |
| `get_lvm_info` | LVM volumes | `lvs`, `vgs`, `pvs` | 🟢 |
| `get_mdadm_info` | Software RAID | `mdadm --detail` | 🟢 |
| `get_iptables` | iptables rules | `iptables-save` | 🟡 |
| `get_nftables` | nftables rules | `nft list ruleset` | 🟡 |
| `get_ss_summary` | Socket statistics | `ss -s` | 🟢 |

---

## macOS-Specific Features

macOS provides introspection via system_profiler, launchd, IOKit, and defaults.

### System Profiler

| Query | Description | Data Type | Impact |
|-------|-------------|-----------|:------:|
| `get_sp_hardware` | Hardware overview | `SPHardwareDataType` | 🟢 |
| `get_sp_software` | Software overview | `SPSoftwareDataType` | 🟢 |
| `get_sp_memory` | Memory modules | `SPMemoryDataType` | 🟢 |
| `get_sp_storage` | Storage devices | `SPStorageDataType` | 🟢 |
| `get_sp_nvme` | NVMe devices | `SPNVMeDataType` | 🟢 |
| `get_sp_network` | Network interfaces | `SPNetworkDataType` | 🟢 |
| `get_sp_wifi` | WiFi details | `SPAirPortDataType` | 🟢 |
| `get_sp_bluetooth` | Bluetooth devices | `SPBluetoothDataType` | 🟢 |
| `get_sp_usb` | USB devices | `SPUSBDataType` | 🟢 |
| `get_sp_thunderbolt` | Thunderbolt devices | `SPThunderboltDataType` | 🟢 |
| `get_sp_displays` | Display info | `SPDisplaysDataType` | 🟢 |
| `get_sp_audio` | Audio devices | `SPAudioDataType` | 🟢 |
| `get_sp_power` | Power/battery | `SPPowerDataType` | 🟢 |
| `get_sp_printers` | Printers | `SPPrintersDataType` | 🟢 |
| `get_sp_applications` | Installed applications | `SPApplicationsDataType` | 🟡 |
| `get_sp_extensions` | Kernel extensions | `SPExtensionsDataType` | 🟢 |
| `get_sp_frameworks` | Frameworks | `SPFrameworksDataType` | 🟡 |
| `get_sp_startup_items` | Startup items | `SPStartupItemDataType` | 🟢 |
| `get_sp_firewall` | Firewall status | `SPFirewallDataType` | 🟢 |

**Implementation**: `system_profiler -json [DataType]`

```bash
# Example: Hardware info as JSON
system_profiler SPHardwareDataType -json
```

### Launchd

| Query | Description | Command | Impact |
|-------|-------------|---------|:------:|
| `get_launchd_list` | All launchd jobs | `launchctl list` | 🟢 |
| `get_launchd_system` | System launch daemons | `/Library/LaunchDaemons/` | 🟢 |
| `get_launchd_agents` | Launch agents | `/Library/LaunchAgents/` | 🟢 |
| `get_launchd_user` | User launch agents | `~/Library/LaunchAgents/` | 🟢 |
| `get_launchd_job` | Job details | `launchctl print` | 🟢 |
| `get_launchd_disabled` | Disabled jobs | `launchctl print-disabled` | 🟢 |

```bash
# Example: List all running jobs
launchctl list | awk 'NR>1 {print $3, $1, $2}'
```

### macOS Security

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_sip_status` | System Integrity Protection | `csrutil status` | 🟢 |
| `get_gatekeeper_status` | Gatekeeper status | `spctl --status` | 🟢 |
| `get_filevault_status` | FileVault encryption | `fdesetup status` | 🟢 |
| `get_xprotect_version` | XProtect malware defs | Built-in paths | 🟢 |
| `get_mrt_version` | Malware Removal Tool | Built-in paths | 🟢 |
| `get_tcc_status` | Privacy permissions | `tccutil` / TCC.db | 🟡 |
| `get_keychain_list` | Keychain files | `security list-keychains` | 🟢 |
| `get_certificates` | System certificates | `security find-certificate` | 🟡 |
| `get_codesign_info` | Code signature | `codesign -dvv` | 🟢 |
| `get_quarantine_events` | Download quarantine | `xattr` / sqlite | 🟡 |
| `get_firmwarepasswd` | Firmware password status | `firmwarepasswd -check` | 🟢 |

### macOS Preferences / Defaults

| Query | Description | Domain | Impact |
|-------|-------------|--------|:------:|
| `get_defaults_global` | Global preferences | `NSGlobalDomain` | 🟢 |
| `get_defaults_finder` | Finder settings | `com.apple.finder` | 🟢 |
| `get_defaults_dock` | Dock settings | `com.apple.dock` | 🟢 |
| `get_defaults_screensaver` | Screensaver settings | `com.apple.screensaver` | 🟢 |
| `get_defaults_loginwindow` | Login window settings | `com.apple.loginwindow` | 🟢 |
| `get_defaults_sharing` | Sharing settings | `com.apple.sharing` | 🟢 |

```bash
# Example: Read all Finder defaults
defaults read com.apple.finder
```

### IOKit / IORegistry

| Query | Description | Class | Impact |
|-------|-------------|-------|:------:|
| `get_ioreg_power` | Power management | `IOPMPowerSource` | 🟢 |
| `get_ioreg_battery` | Battery details | `AppleSmartBattery` | 🟢 |
| `get_ioreg_usb` | USB tree | `IOUSBDevice` | 🟢 |
| `get_ioreg_storage` | Storage devices | `IOBlockStorageDevice` | 🟢 |
| `get_ioreg_network` | Network interfaces | `IONetworkInterface` | 🟢 |
| `get_ioreg_graphics` | Graphics/GPU | `IOAccelerator` | 🟢 |
| `get_ioreg_sensors` | Hardware sensors | `IOHWSensor` | 🟢 |
| `get_ioreg_nvram` | NVRAM variables | `IODeviceTree:/options` | 🟢 |

```bash
# Example: Battery info
ioreg -r -c AppleSmartBattery -a
```

### macOS-Specific System State

| Query | Description | Source | Impact |
|-------|-------------|--------|:------:|
| `get_sw_vers` | macOS version | `sw_vers` | 🟢 |
| `get_sysctl_hw` | Hardware sysctl | `sysctl hw` | 🟢 |
| `get_sysctl_kern` | Kernel sysctl | `sysctl kern` | 🟢 |
| `get_nvram` | NVRAM variables | `nvram -xp` | 🟢 |
| `get_kextstat` | Loaded kexts | `kextstat` | 🟢 |
| `get_profiles` | Configuration profiles | `profiles list` | 🟢 |
| `get_mdm_status` | MDM enrollment | `profiles status -type enrollment` | 🟢 |
| `get_softwareupdate` | Available updates | `softwareupdate -l` | 🟡 |
| `get_pkgutil` | Installed packages | `pkgutil --pkgs` | 🟢 |
| `get_brew_list` | Homebrew packages | `brew list --versions` | 🟢 |
| `get_mas_list` | App Store apps | `mas list` | 🟢 |
| `get_networksetup` | Network configuration | `networksetup` | 🟢 |
| `get_scutil_dns` | DNS configuration | `scutil --dns` | 🟢 |
| `get_scutil_proxy` | Proxy settings | `scutil --proxy` | 🟢 |
| `get_airport_info` | WiFi details | `airport -I` | 🟢 |
| `get_pmset` | Power management | `pmset -g` | 🟢 |
| `get_diskutil` | Disk details | `diskutil list` | 🟢 |
| `get_apfs_list` | APFS volumes | `diskutil apfs list` | 🟢 |
| `get_tmutil_status` | Time Machine status | `tmutil status` | 🟢 |

---

## Cross-Platform Summary

| Category | Windows | Linux | macOS |
|----------|---------|-------|-------|
| Hardware inventory | WMI | sysfs/DMI | system_profiler |
| Process details | WMI/tasklist | procfs | ps/launchctl |
| Service status | WMI/sc | systemd | launchd |
| Network config | WMI/netsh | sysfs/ip | networksetup |
| Storage details | WMI/diskpart | sysfs/lsblk | diskutil |
| Security status | auditpol/GPO | SELinux/AppArmor | SIP/Gatekeeper |
| Installed software | Registry | dpkg/rpm | pkgutil/brew |
| Startup items | Registry Run | systemd/cron | launchd |
| Event logs | Event Viewer | journald | Console/ASL |
| Kernel info | driverquery | procfs/sysfs | kextstat/sysctl |

---

## Security Considerations

### High-Risk Platform-Specific Queries

These queries are placed in the `sensitive` scope:

| Platform | Query | Risk |
|----------|-------|------|
| Windows | `get_security_events` | Auth patterns, PII |
| Windows | `get_rdp_events` | Remote access history |
| Windows | `get_mru_lists` | User activity tracking |
| Linux | `get_proc_environ` | Environment variables |
| Linux | `get_audit_rules` | Security configuration |
| macOS | `get_tcc_status` | Privacy permissions |
| macOS | `get_quarantine_events` | Download history |

### Queries Requiring Parameters

| Query | Required Parameter | Reason |
|-------|-------------------|--------|
| `get_proc_*` (per-process) | `pid` | Prevent bulk enumeration |
| `get_journald_logs` | `unit` or `since` | Prevent log dump |
| `get_wmi_processes` | `name` filter | Limit scope |
| `get_event_log` | `log_name`, `max_events` | Prevent bulk extraction |

---

## Implementation Notes

### Windows

```go
// Use PowerShell for WMI queries
cmd := exec.Command("powershell", "-NoProfile", "-Command",
    "Get-CimInstance -ClassName Win32_OperatingSystem | ConvertTo-Json")
```

### Linux

```go
// Direct file reads from procfs/sysfs
data, err := os.ReadFile("/proc/meminfo")

// Systemd via dbus or CLI
cmd := exec.Command("systemctl", "show", unit, "--property=ActiveState,SubState")
```

### macOS

```go
// system_profiler with JSON output
cmd := exec.Command("system_profiler", "SPHardwareDataType", "-json")

// IOKit via ioreg
cmd := exec.Command("ioreg", "-r", "-c", "AppleSmartBattery", "-a")
```

### Output Normalization

All platform-specific queries return normalized JSON with:

```json
{
  "platform": "windows|linux|darwin",
  "query": "get_wmi_os",
  "timestamp": "2024-12-12T10:30:00Z",
  "data": { ... },
  "source": "Win32_OperatingSystem"
}
```
