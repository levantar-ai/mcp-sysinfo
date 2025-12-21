# Windows Enterprise Queries

Windows-specific queries for enterprise environment diagnostics including Registry, DCOM/COM, and IIS.

!!! note "Windows Only"
    These queries are only available on Windows. On Linux and macOS, they return empty results with an appropriate message.

## Query Categories

| Category | Queries | Description |
|----------|---------|-------------|
| [Registry](#registry-queries) | 3 | Windows Registry access and security |
| [DCOM/COM](#dcomcom-security) | 4 | Distributed COM application security |
| [IIS Web Server](#iis-web-server) | 8 | Internet Information Services configuration |

---

## Registry Queries

Access Windows Registry keys, values, and security descriptors.

### get_registry_key

Read a registry key and its values.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hive` | string | Yes | Registry hive (HKLM, HKCU, HKCR, HKU, HKCC) |
| `path` | string | Yes | Path to the registry key |

**Example:**
```json
{
  "name": "get_registry_key",
  "arguments": {
    "hive": "HKLM",
    "path": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
  }
}
```

**Response includes:**
- Key name, path, and hive
- List of values with name, type, and data
- List of subkey names
- Timestamp

---

### get_registry_tree

Enumerate registry subkeys recursively with depth control.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hive` | string | Yes | Registry hive |
| `path` | string | Yes | Starting path |
| `max_depth` | int | No | Maximum recursion depth (default: 3) |

**Example:**
```json
{
  "name": "get_registry_tree",
  "arguments": {
    "hive": "HKLM",
    "path": "SOFTWARE\\Microsoft",
    "max_depth": 2
  }
}
```

---

### get_registry_security

Get security descriptor for a registry key including owner, group, and DACL.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `hive` | string | Yes | Registry hive |
| `path` | string | Yes | Path to the registry key |

**Response includes:**
- Owner SID and account name
- Group SID and account name
- DACL with access control entries (ACEs)
- Each ACE includes: type, SID, account, access mask, inheritance flags

---

## DCOM/COM Security

Query Distributed COM application registration and security settings.

### get_dcom_applications

List all registered DCOM applications from the registry.

**Response includes:**
- Application ID (GUID)
- Application name
- Local server path (executable)
- RunAs identity
- Launch and access permission flags

---

### get_dcom_permissions

Get launch and access permissions for a specific DCOM application.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `appid` | string | Yes | DCOM Application ID (GUID) |

**Response includes:**
- Launch permissions (who can start the application)
- Access permissions (who can connect to running instance)
- Each permission includes: SID, account name, access type

---

### get_dcom_identities

List RunAs identities configured for DCOM applications.

**Response includes:**
- Application ID and name
- Identity type (Interactive User, Launching User, custom account)
- Custom account name if specified

---

### get_com_security_defaults

Get machine-wide COM security defaults from HKLM\SOFTWARE\Microsoft\Ole.

**Response includes:**
- Default launch permission
- Default access permission
- Authentication level
- Impersonation level
- Legacy authentication level

---

## IIS Web Server

Query Internet Information Services (IIS) configuration.

### get_iis_sites

List all IIS websites with their configuration.

**Response includes:**
- Site ID and name
- State (Started, Stopped)
- Physical path
- Bindings (protocol, IP, port, hostname)
- Auto-start setting

---

### get_iis_app_pools

List all IIS application pools.

**Response includes:**
- Pool name and state
- .NET CLR version
- Pipeline mode (Integrated, Classic)
- 32-bit application support
- Start mode and auto-start settings
- Queue length

---

### get_iis_bindings

List all site bindings across all IIS sites.

**Response includes:**
- Site name and ID
- Protocol (http, https)
- IP address, port, hostname
- SSL certificate hash and store (for HTTPS)
- SSL flags

---

### get_iis_virtual_dirs

List virtual directories for all IIS sites.

**Response includes:**
- Site name and ID
- Virtual directory path
- Physical path mapping

---

### get_iis_handlers

List handler mappings configured in IIS.

**Response includes:**
- Handler name
- Path pattern (e.g., *.aspx)
- Allowed verbs
- Handler type or script processor
- Module and preconditions

---

### get_iis_modules

List installed IIS modules (global and managed).

**Response includes:**
- Global modules (native DLLs)
- Managed modules (.NET)
- Module name, type, and preconditions

---

### get_iis_ssl_certs

List SSL certificate bindings from HTTP.sys.

**Response includes:**
- IP:port or hostname:port binding
- Certificate hash and store
- Application ID
- Client certificate settings
- TLS/HTTP2/QUIC configuration flags

---

### get_iis_auth_config

Get authentication configuration for all IIS sites.

**Response includes per site:**
- Anonymous authentication (enabled/disabled)
- Basic authentication
- Windows authentication (NTLM/Kerberos)
- Digest authentication

---

## CLI Usage

```bash
# Registry queries
./mcp-sysinfo --query get_registry_key --hive HKLM --regpath "SOFTWARE\\Microsoft" --json
./mcp-sysinfo --query get_registry_tree --hive HKLM --regpath "SOFTWARE" --max-depth 2 --json
./mcp-sysinfo --query get_registry_security --hive HKLM --regpath "SOFTWARE" --json

# DCOM queries
./mcp-sysinfo --query get_dcom_applications --json
./mcp-sysinfo --query get_dcom_permissions --appid "{00000000-0000-0000-0000-000000000000}" --json
./mcp-sysinfo --query get_dcom_identities --json
./mcp-sysinfo --query get_com_security_defaults --json

# IIS queries
./mcp-sysinfo --query get_iis_sites --json
./mcp-sysinfo --query get_iis_app_pools --json
./mcp-sysinfo --query get_iis_bindings --json
./mcp-sysinfo --query get_iis_virtual_dirs --json
./mcp-sysinfo --query get_iis_handlers --json
./mcp-sysinfo --query get_iis_modules --json
./mcp-sysinfo --query get_iis_ssl_certs --json
./mcp-sysinfo --query get_iis_auth_config --json
```

---

## Platform Support

| Query | Linux | macOS | Windows |
|-------|:-----:|:-----:|:-------:|
| `get_registry_key` | :x: | :x: | :white_check_mark: |
| `get_registry_tree` | :x: | :x: | :white_check_mark: |
| `get_registry_security` | :x: | :x: | :white_check_mark: |
| `get_dcom_applications` | :x: | :x: | :white_check_mark: |
| `get_dcom_permissions` | :x: | :x: | :white_check_mark: |
| `get_dcom_identities` | :x: | :x: | :white_check_mark: |
| `get_com_security_defaults` | :x: | :x: | :white_check_mark: |
| `get_iis_sites` | :x: | :x: | :white_check_mark: |
| `get_iis_app_pools` | :x: | :x: | :white_check_mark: |
| `get_iis_bindings` | :x: | :x: | :white_check_mark: |
| `get_iis_virtual_dirs` | :x: | :x: | :white_check_mark: |
| `get_iis_handlers` | :x: | :x: | :white_check_mark: |
| `get_iis_modules` | :x: | :x: | :white_check_mark: |
| `get_iis_ssl_certs` | :x: | :x: | :white_check_mark: |
| `get_iis_auth_config` | :x: | :x: | :white_check_mark: |

---

*Documentation auto-generated on 2025-12-21*
