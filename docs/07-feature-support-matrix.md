# Feature Support Matrix

A summary of feature support across Linux, macOS, and Windows.

---

## Overview

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MCP SYSTEM INFO - FEATURE SUPPORT MATRIX                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Platform        Total    Built-in    pip/stdlib    Sys Pkg    N/A          ║
║  ─────────────────────────────────────────────────────────────────────────   ║
║  Linux            145        54           52           40        0           ║
║  macOS            104        57           36            9        6           ║
║  Windows          121        66           52            2        2           ║
║  Cross-Platform   105         -           98            -        -           ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  TOTAL IMPLEMENTATIONS: 475                                                  ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Support Percentage by OS

```
Linux     ████████████████████████████████████████████████████  100%
Windows   ██████████████████████████████████████████████████    98%
macOS     █████████████████████████████████████████████████     94%
```

| Platform | Support | Notes |
|----------|---------|-------|
| **Linux** | 100% | Full support for all features |
| **Windows** | 98% | Missing ZFS, systemd |
| **macOS** | 94% | Missing GPU, some low-level features |

---

## N/A Features by Platform

### macOS (6 unsupported)

| Feature | Reason |
|---------|--------|
| NVIDIA GPU monitoring | No modern NVIDIA driver support |
| AMD GPU monitoring | No AMD support on macOS |
| Native containers | No Docker-less container runtime |
| LVM | Not supported on macOS |
| systemd | Uses launchd instead |
| ionice / I/O priority | No equivalent API |
| Cloud metadata | macOS not typically cloud-hosted |

### Windows (2 unsupported)

| Feature | Reason |
|---------|--------|
| ZFS | Not supported on Windows |
| systemd | Uses Windows Services instead |

### Linux (0 unsupported)

Full support for all documented features.

---

## Installation Breakdown

### By Platform

| Install Method | Linux | macOS | Windows |
|----------------|-------|-------|---------|
| Built-in (no install) | 54 | 57 | 66 |
| pip install | 52 | 36 | 52 |
| System package (apt/brew) | 40 | 9 | 2 |
| **Total** | **145** | **104** | **121** |

Plus **105 cross-platform features** that work identically on all platforms.

### Summary

| Category | Percentage |
|----------|------------|
| Zero-install (built-in) | ~40% |
| pip-only install | ~45% |
| System packages needed | ~15% |

---

## Availability Legend

| Symbol | Meaning |
|--------|---------|
| **Built-in** | Available by default, no installation needed |
| **Python stdlib** | Part of Python standard library |
| **pip install X** | Requires installing Python package X |
| **apt/brew** | Requires system package installation |
| **Root/Admin** | Requires elevated privileges |
| **N/A** | Not available on this platform |

---

## Key Insights

1. **Linux has the best coverage** - All features are supported, with the richest ecosystem of tools (eBPF, cgroups, systemd, /proc, /sys)

2. **Windows has excellent built-in support** - Most features work via WMI, Performance Counters, and PowerShell without extra packages

3. **macOS has good coverage but gaps** - Missing some low-level features (GPU, I/O priority, cgroups) due to platform restrictions

4. **Cross-platform features are the foundation** - 105 features work identically across all platforms using psutil and pure Python

5. **pip is the primary install method** - Most features only require `pip install` with no system dependencies

---

## Recommended Core Dependencies

These packages cover the majority of features:

```bash
pip install psutil          # Core system metrics (all platforms)
pip install watchdog        # File system events (all platforms)
pip install httpx           # HTTP client for webhooks
pip install duckdb          # Time-series storage
pip install pandas numpy    # Analytics
pip install prometheus-client  # Metrics export
```

### Platform-Specific Additions

**Linux:**
```bash
apt install smartmontools   # SMART disk health
apt install sysstat         # iostat
apt install bpfcc-tools     # eBPF tools (optional, advanced)
```

**macOS:**
```bash
brew install smartmontools  # SMART disk health
```

**Windows:**
```bash
pip install pywin32         # Windows APIs
pip install wmi             # WMI queries
```
