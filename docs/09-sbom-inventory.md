# SBOM & Software Inventory

Software Bill of Materials and package inventory for vulnerability detection, compliance, and dependency analysis. All queries use only built-in OS tools - no third-party scanners required.

---

## Design Principles

### Lightweight Collection

| Principle | Implementation |
|-----------|----------------|
| **On-demand only** | Never poll or auto-scan; only when requested |
| **Incremental** | Support delta queries (what changed since X) |
| **Streaming** | Stream large package lists, don't buffer all in memory |
| **Caching** | Cache results with TTL (packages don't change often) |
| **Sampling** | For very large systems, sample or paginate |

### Resource Budgets

| Operation | Max Time | Max Memory | Notes |
|-----------|----------|------------|-------|
| Package list | 10s | 50MB | Most systems have <5000 packages |
| Single package info | 100ms | 1MB | Quick lookup |
| Dependency tree | 30s | 100MB | Can be large, stream results |

---

## System Package Managers

### Debian/Ubuntu (dpkg/apt)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| List all packages | Read `/var/lib/dpkg/status` | 🟢 Minimal - single file |
| Package info | Parse from status file | 🟢 Minimal |
| Package files | Read `/var/lib/dpkg/info/*.list` | 🟡 Low |
| Installed size | From status file | 🟢 Minimal |
| Dependencies | From status file | 🟢 Minimal |
| Available updates | `apt list --upgradable` | 🟠 Medium - network |

**Lightweight approach:** Parse `/var/lib/dpkg/status` directly - it's a simple text format.

```
Package: nginx
Status: install ok installed
Version: 1.18.0-0ubuntu1
Architecture: amd64
Installed-Size: 899
Depends: libc6, libpcre3, libssl1.1, zlib1g
```

---

### RHEL/CentOS/Fedora (rpm/dnf/yum)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| List all packages | `rpm -qa --queryformat` | 🟡 Low - DB query |
| Package info | `rpm -qi [package]` | 🟢 Minimal |
| Package files | `rpm -ql [package]` | 🟢 Minimal |
| Dependencies | `rpm -qR [package]` | 🟢 Minimal |
| Available updates | `dnf check-update` | 🟠 Medium - network |

**Lightweight approach:** Use `rpm -qa` with custom format to get exactly what's needed:

```bash
rpm -qa --queryformat '%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{SIZE}|%{INSTALLTIME}\n'
```

---

### Alpine (apk)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| List all packages | Read `/lib/apk/db/installed` | 🟢 Minimal - single file |
| Package info | Parse from installed DB | 🟢 Minimal |
| Available updates | `apk version -l '<'` | 🟡 Low |

---

### Arch Linux (pacman)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| List all packages | Read `/var/lib/pacman/local/*/desc` | 🟡 Low - dir scan |
| Package info | Parse desc file | 🟢 Minimal |
| Available updates | `pacman -Qu` | 🟠 Medium - network |

---

### macOS (Homebrew)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| List formulae | Read `/usr/local/Cellar/` or `/opt/homebrew/Cellar/` | 🟡 Low - dir scan |
| List casks | Read `/usr/local/Caskroom/` or `/opt/homebrew/Caskroom/` | 🟡 Low |
| Package info | Read `INSTALL_RECEIPT.json` in package dir | 🟢 Minimal |
| Available updates | `brew outdated --json` | 🟠 Medium - network |

**Lightweight approach:** Read directories and JSON receipts directly, don't shell out to `brew` for lists.

---

### macOS (System)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| Installed apps | Scan `/Applications/`, `~/Applications/` | 🟡 Low |
| App info | Read `Info.plist` from .app bundle | 🟢 Minimal |
| System packages | `pkgutil --pkgs` | 🟡 Low |
| Package info | `pkgutil --pkg-info [id]` | 🟢 Minimal |

---

### Windows (Native)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| Installed programs | Registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` | 🟢 Minimal |
| 32-bit on 64-bit | Also check `Wow6432Node` path | 🟢 Minimal |
| User installs | Registry `HKCU\...\Uninstall\*` | 🟢 Minimal |
| Windows features | `dism /online /get-features` | 🟡 Low |
| Windows updates | `Get-HotFix` PowerShell | 🟡 Low |

**Lightweight approach:** Read registry directly - much faster than WMI `Win32_Product`.

⚠️ **Warning:** Never use `Win32_Product` WMI class - it triggers MSI reconfiguration and is extremely slow.

---

### Windows (winget/Chocolatey/Scoop)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| winget list | `winget list --disable-interactivity` | 🟡 Low |
| Chocolatey | Read `C:\ProgramData\chocolatey\lib\*` | 🟡 Low |
| Scoop | Read `~\scoop\apps\*` | 🟡 Low |

---

## Language Package Managers

### Python (pip)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| System packages | Read `site-packages/*/METADATA` | 🟡 Low - dir scan |
| Virtual envs | Scan known venv locations | 🟡 Low |
| Package metadata | Parse METADATA file | 🟢 Minimal |
| Dependencies | From METADATA `Requires-Dist` | 🟢 Minimal |

**Locations to scan:**
- `/usr/lib/python*/site-packages/`
- `/usr/local/lib/python*/site-packages/`
- `~/.local/lib/python*/site-packages/`
- Virtual environments in project directories

**Lightweight approach:** Read `METADATA` or `PKG-INFO` files directly, don't spawn `pip list`.

---

### Node.js (npm/yarn/pnpm)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| Global packages | Read `{prefix}/lib/node_modules/*/package.json` | 🟡 Low |
| Project packages | Read `node_modules/*/package.json` | 🟠 Medium - can be huge |
| Lock file | Read `package-lock.json` or `yarn.lock` | 🟢 Minimal |
| Dependency tree | Parse lock file | 🟡 Low |

**Lightweight approach:**
- Read `package-lock.json` for full tree (already resolved)
- For `node_modules`, only read top-level unless asked for full tree

---

### Go Modules

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| Module cache | Read `~/go/pkg/mod/cache/download/` | 🟡 Low |
| Project deps | Read `go.sum` file | 🟢 Minimal |
| Binary deps | `go version -m [binary]` | 🟢 Minimal per binary |

**Lightweight approach:** Read `go.sum` for project dependencies - it's a simple text file.

---

### Rust (Cargo)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| Cache | Read `~/.cargo/registry/cache/` | 🟡 Low |
| Project deps | Read `Cargo.lock` | 🟢 Minimal |
| Installed binaries | Read `~/.cargo/bin/` | 🟢 Minimal |

---

### Ruby (Gem/Bundler)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| System gems | Read `/var/lib/gems/*/specifications/*.gemspec` | 🟡 Low |
| User gems | Read `~/.gem/*/specifications/` | 🟡 Low |
| Project deps | Read `Gemfile.lock` | 🟢 Minimal |

---

### Java (Maven/Gradle)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| Maven cache | Scan `~/.m2/repository/` | 🟠 Medium - large tree |
| Gradle cache | Scan `~/.gradle/caches/modules-*/` | 🟠 Medium |
| Project deps | Read `pom.xml` or `build.gradle` | 🟢 Minimal |

**Lightweight approach:** Only scan when explicitly requested; cache results.

---

### PHP (Composer)

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| Global packages | Read `~/.composer/vendor/` | 🟡 Low |
| Project deps | Read `composer.lock` | 🟢 Minimal |

---

## Container Images

### Docker Images

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| List images | Docker API `/images/json` | 🟢 Minimal |
| Image layers | Docker API `/images/[id]/history` | 🟢 Minimal |
| Image inspect | Docker API `/images/[id]/json` | 🟢 Minimal |

**Lightweight approach:** Use Docker socket API directly, don't spawn `docker` CLI.

---

### Container Package Inventory

For running containers, we can inspect their package state:

| Query | Implementation | Resource Impact |
|-------|----------------|-----------------|
| Container packages | `docker exec [id] cat /var/lib/dpkg/status` | 🟡 Low per container |
| Image packages | Analyze image layers | 🟠 Medium |

---

## SBOM Output Formats

Support standard SBOM formats for interoperability:

### CycloneDX

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "type": "library",
      "name": "nginx",
      "version": "1.18.0",
      "purl": "pkg:deb/ubuntu/nginx@1.18.0"
    }
  ]
}
```

### SPDX

```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "nginx",
      "versionInfo": "1.18.0",
      "downloadLocation": "NOASSERTION"
    }
  ]
}
```

### Package URL (purl)

Use standardized package URLs for identification:

| Type | Example |
|------|---------|
| Debian | `pkg:deb/ubuntu/nginx@1.18.0-0ubuntu1?arch=amd64` |
| RPM | `pkg:rpm/centos/nginx@1.18.0-1.el8?arch=x86_64` |
| npm | `pkg:npm/express@4.18.2` |
| PyPI | `pkg:pypi/django@4.2.0` |
| Go | `pkg:golang/github.com/gin-gonic/gin@v1.9.0` |
| Homebrew | `pkg:brew/nginx@1.25.0` |

---

## Vulnerability Correlation

Once we have the SBOM, we can correlate with vulnerability databases:

### Local Correlation (No Network)

| Database | Location | Format |
|----------|----------|--------|
| Debian Security Tracker | `/var/lib/apt/lists/*_security_*` | Text |
| RHEL OVAL | `/var/lib/yum/security/` | XML |
| Ubuntu USN | Local apt cache | Text |

### On-Demand Lookup (Network Required)

| Database | API | Rate Limit |
|----------|-----|------------|
| NVD | `nvd.nist.gov/vuln/data-feeds` | Cached JSON feeds |
| OSV | `api.osv.dev/v1/query` | No auth required |
| GitHub Advisory | `api.github.com/advisories` | Token recommended |

**Lightweight approach:**
1. Generate SBOM locally (no network)
2. User can optionally request vulnerability check (network)
3. Cache vulnerability data locally

---

## Query Summary

| Category | Queries | Implementation Complexity |
|----------|---------|---------------------------|
| System packages (apt/rpm/etc) | 6 | Low - file parsing |
| macOS packages | 4 | Low - file/dir parsing |
| Windows packages | 5 | Low - registry reading |
| Language packages | 8 | Medium - multiple formats |
| Container packages | 3 | Low - API calls |
| SBOM export | 2 | Low - JSON formatting |
| Vulnerability lookup | 3 | Medium - optional network |
| **Total** | **31** | Mostly file-based |

---

## Resource Impact Summary

| Operation | Impact | Notes |
|-----------|--------|-------|
| List system packages | 🟢-🟡 | Single file or DB read |
| List language packages | 🟡-🟠 | Directory scanning |
| Full SBOM generation | 🟠 | Combines multiple sources |
| Vulnerability lookup | 🟠 | Network + CPU for matching |

**Key optimizations:**
1. Cache package lists (TTL: 5 minutes)
2. Stream large results
3. Support filtering (only show packages matching pattern)
4. Support pagination for large inventories
5. Vulnerability lookup is optional and on-demand only
