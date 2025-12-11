# Tier 4: Security & Compliance

Security monitoring, audit & compliance, and forensics support.

---

## Security Monitoring

### Open Port Scanning
Detect unexpected listening ports.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `psutil.net_connections(kind='inet')` status='LISTEN' | pip | `pip install psutil` |
| **Linux** | Map to process via `pid`, compare against whitelist | pip | `pip install psutil` |
| **macOS** | `psutil.net_connections(kind='inet')` | pip | `pip install psutil` |
| **macOS** | `lsof -i -P` for additional detail | Built-in | None |
| **Windows** | `psutil.net_connections(kind='inet')` | pip | `pip install psutil` |
| **Windows** | `Get-NetTCPConnection -State Listen` PowerShell | Built-in | None |

---

### Failed Login Tracking
Parse auth logs for brute force attempts.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (Debian)** | Parse `/var/log/auth.log` | Built-in | None |
| **Linux (RHEL)** | Parse `/var/log/secure` | Built-in | None |
| **Linux (systemd)** | `journalctl -u sshd` | Built-in | None |
| **Linux** | Regex for "Failed password", count by IP | Python stdlib | None |
| **macOS** | `log show --predicate 'eventMessage contains "failed"'` | Built-in | None |
| **macOS** | Parse `/var/log/system.log` | Built-in | None |
| **Windows** | Event Log: Security event ID 4625 | Built-in | None |
| **Windows** | `win32evtlog` module | pip | `pip install pywin32` |
| **Windows** | `wevtutil qe Security` | Built-in | None |

---

### Suspicious Process Detection
Identify crypto miners, reverse shells, known malware patterns.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Check process names against known bad patterns | pip | `pip install psutil` |
| **Linux** | High CPU + network = potential miner | pip | `pip install psutil` |
| **Linux** | Detect `/dev/tcp` in cmdline | pip | `pip install psutil` |
| **macOS** | Check process names against patterns | pip | `pip install psutil` |
| **macOS** | Unsigned binaries via `codesign -v` | Built-in | None |
| **macOS** | Check known malware paths | Built-in | None |
| **Windows** | Check process names/paths against patterns | pip | `pip install psutil` |
| **Windows** | Unsigned executables check | pip | `pip install pywin32` |
| **Windows** | Check known malware registry keys | Python stdlib | `winreg` |
| **Windows** | YARA rule scanning | pip | `pip install yara-python` |

---

### File Integrity Monitoring (FIM)
Hash critical files, detect unauthorized changes.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `hashlib` to hash `/etc`, `/usr/bin` | Python stdlib | None |
| **Linux** | Store in DB, alert on change | Python stdlib | None |
| **Linux** | `aide` integration | apt | `apt install aide` |
| **Linux** | `tripwire` integration | apt | `apt install tripwire` |
| **macOS** | `hashlib` to hash `/etc`, `/usr/local/bin`, `/Applications` | Python stdlib | None |
| **Windows** | `hashlib` to hash `C:\Windows\System32` | Python stdlib | None |

---

### Rootkit Detection
Hidden processes, suspicious kernel modules.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Compare `ps` output vs `/proc` listing | Built-in | None |
| **Linux** | Check `/proc/modules` against whitelist | Built-in | None |
| **Linux** | Detect hidden files with special names | Python stdlib | None |
| **Linux** | `rkhunter` integration | apt | `apt install rkhunter` |
| **macOS** | Compare process lists from multiple sources | Built-in | None |
| **macOS** | Check kexts in `/Library/Extensions` | Built-in | None |
| **macOS** | SIP status via `csrutil status` | Built-in | None |
| **Windows** | Compare process lists from multiple sources | Built-in | None |
| **Windows** | Check drivers in `C:\Windows\System32\drivers` | Built-in | None |
| **Windows** | Detect SSDT hooks (advanced) | pip | `pip install pywin32` (complex) |

---

## Audit & Compliance

### User Session Tracking
Who's logged in, from where, session duration.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `psutil.users()` | pip | `pip install psutil` |
| **Linux** | Parse `last` command or `/var/log/wtmp` | Built-in | None |
| **Linux** | `who` for SSH sessions | Built-in | None |
| **macOS** | `psutil.users()` | pip | `pip install psutil` |
| **macOS** | `last` command, `w` for activity | Built-in | None |
| **Windows** | `psutil.users()` | pip | `pip install psutil` |
| **Windows** | `query user` command | Built-in | None |
| **Windows** | Event log 4624 (logon), 4634 (logoff) | Built-in | None |

---

### Privilege Escalation Monitoring
Track sudo usage, setuid binary execution.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Parse `/var/log/auth.log` for sudo | Built-in | None |
| **Linux** | Find setuid: `find / -perm -4000` | Built-in | None |
| **Linux** | Linux Audit Framework | apt | `apt install auditd` |
| **macOS** | Parse `/var/log/system.log` for sudo | Built-in | None |
| **macOS** | Find setuid: `find / -perm -4000` | Built-in | None |
| **macOS** | Authorization plugin logs | Built-in | None |
| **Windows** | Event log 4672 (special privileges) | Built-in | None |
| **Windows** | Event log 4673 (privileged service) | Built-in | None |
| **Windows** | UAC prompts in Security log | Built-in | None |

---

### Security Benchmark Checks
CIS benchmark compliance scoring.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Password policy checks | Built-in | None |
| **Linux** | SSH config validation | Built-in | None |
| **Linux** | Filesystem permission checks | Built-in | None |
| **Linux** | `lynis` for automated auditing | apt | `apt install lynis` |
| **macOS** | FileVault status check | Built-in | None |
| **macOS** | Gatekeeper status | Built-in | `spctl --status` |
| **macOS** | Firewall enabled check | Built-in | None |
| **Windows** | Password policy via `secedit` | Built-in | None |
| **Windows** | Audit policy check | Built-in | None |
| **Windows** | Service hardening validation | Built-in | None |

---

### Patch/Vulnerability Status
Check for outdated packages with known CVEs.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux (Debian)** | `apt list --upgradable` | Built-in | None |
| **Linux (RHEL)** | `yum check-update` | Built-in | None |
| **Linux** | Cross-reference with NVD API | External | API access |
| **Linux** | `unattended-upgrades` status | apt | `apt install unattended-upgrades` |
| **macOS** | `softwareupdate -l` | Built-in | None |
| **macOS** | Homebrew: `brew outdated` | brew | `brew` installed |
| **Windows** | `Get-HotFix` PowerShell | Built-in | None |
| **Windows** | Windows Update Agent API | Built-in | None |
| **Windows** | MSRC CVE data comparison | External | API access |

---

### Configuration Auditing
Audit SSH config, firewall rules, permissions.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Parse `/etc/ssh/sshd_config` for weak settings | Built-in | None |
| **Linux** | Check `/etc/passwd` for UID 0 users | Built-in | None |
| **Linux** | Verify key file permissions | Built-in | None |
| **macOS** | Parse SSH config | Built-in | None |
| **macOS** | Check sharing preferences | Built-in | `systemsetup` |
| **macOS** | TCC database for app permissions | Built-in | SIP may restrict |
| **Windows** | Audit GPO settings | Built-in | `gpresult` |
| **Windows** | RDP configuration check | Built-in | Registry |
| **Windows** | Share permissions via `Get-SmbShare` | Built-in | None |

---

## Forensics Support

### Process Tree Snapshots
Full process hierarchy capture at a point in time.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | `psutil.process_iter()` with full attributes | pip | `pip install psutil` |
| **All** | Build tree via `ppid()` | pip | `pip install psutil` |
| **All** | Serialize to JSON with timestamp | Python stdlib | None |

---

### Network Connection History
Historical log of all connections.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Periodic snapshot of `psutil.net_connections()` | pip | `pip install psutil` |
| **All** | Store in time-series DB | pip | `pip install duckdb` |
| **Linux** | Netflow via `softflowd` | apt | `apt install softflowd` |
| **Windows** | ETW network events for real-time | Built-in | Complex setup |

---

### File Access Logging
What files were accessed, by whom, when.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `auditctl -w /path -p rwa` | apt | `apt install auditd` |
| **Linux** | Parse `/var/log/audit/audit.log` | apt | `apt install auditd` |
| **Linux** | `fanotify` for real-time | Kernel | CAP_SYS_ADMIN required |
| **macOS** | OpenBSM: parse `/var/audit/*` | Built-in | Audit enabled |
| **macOS** | Endpoint Security Framework | Built-in | Requires entitlement |
| **Windows** | Enable object access auditing | Built-in | GPO config |
| **Windows** | Event log 4663 | Built-in | Auditing enabled |
| **Windows** | `win32evtlog` to parse Security log | pip | `pip install pywin32` |

---

### Memory Dump Triggers
Capture process memory on suspicious activity.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | `gcore` command | apt | `apt install gdb` |
| **Linux** | `/proc/[pid]/mem` direct reading | Built-in | Requires ptrace |
| **Linux** | `procdump` for Linux | apt/GitHub | Microsoft procdump |
| **macOS** | `lldb` process save-core | Built-in | Xcode CLI tools |
| **macOS** | `vmmap` for memory layout | Built-in | None |
| **macOS** | SIP may restrict access | Built-in | SIP |
| **Windows** | `procdump` utility | Download | Sysinternals |
| **Windows** | `MiniDumpWriteDump` API via `ctypes` | Python stdlib | None |
| **Windows** | Task Manager dump (programmatic) | Built-in | None |
