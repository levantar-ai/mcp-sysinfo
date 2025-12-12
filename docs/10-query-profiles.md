# Query Profiles

Query profiles bundle related queries into single calls for efficiency, while preserving AI's ability to reason about results and drill deeper with individual queries.

## Why Profiles Exist

| Without Profiles | With Profiles |
|------------------|---------------|
| AI makes 10 sequential MCP calls | AI makes 1 profile call |
| 10 round-trips of latency | 1 round-trip |
| AI must know which queries are relevant | Expert knowledge encoded in profile |
| Good for novel investigations | Good for known patterns |

**Profiles are an optimization, not a replacement for AI reasoning.**

## How Profiles Work

```
User: "Is my network secure?"
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│                      AI Agent                                │
│                                                              │
│  Recognizes: "This is a network security question"          │
│                                                              │
│  Option A: Call profile         Option B: Individual calls   │
│  ┌─────────────────────┐       ┌─────────────────────────┐  │
│  │ network_audit       │       │ get_listening_ports     │  │
│  │ (returns 6 results) │  OR   │ get_firewall_rules      │  │
│  │ 1 round-trip        │       │ get_ssh_config          │  │
│  └─────────────────────┘       │ get_dns_config          │  │
│           │                    │ get_routing_table       │  │
│           │                    │ get_network_info        │  │
│           │                    │ 6 round-trips           │  │
│           │                    └─────────────────────────┘  │
│           ▼                              │                   │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ AI analyzes results, identifies issues:             │    │
│  │ - SSH allows password auth                          │    │
│  │ - Port 3306 exposed to 0.0.0.0                     │    │
│  │ - No firewall rules for egress                     │    │
│  │                                                     │    │
│  │ AI decides: Need more detail on MySQL exposure     │    │
│  │ Calls: get_processes (filter: mysql)               │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

**Key insight**: AI still interprets results and makes follow-up decisions. Profiles just accelerate the initial data gathering.

---

## Profile Types

### 1. Investigation Profiles

For common diagnostic scenarios:

```yaml
profiles:
  network_audit:
    description: "Assess network attack surface and exposure"
    use_when: "User asks about network security, exposure, or attack surface"
    queries:
      - get_listening_ports
      - get_firewall_rules
      - get_network_info
      - get_ssh_config
      - get_dns_config
      - get_routing_table

  disk_investigation:
    description: "Diagnose disk space and I/O issues"
    use_when: "User reports disk full, slow I/O, or storage problems"
    queries:
      - get_disk_info
      - get_inode_usage
      - get_mount_options
      - get_open_files
      - get_processes        # To find disk-heavy processes

  memory_investigation:
    description: "Diagnose memory pressure and leaks"
    use_when: "User reports OOM, slow performance, or memory issues"
    queries:
      - get_memory_info
      - get_processes        # Sorted by memory
      - get_swap_info
      - get_cgroup_limits
      - get_kernel_logs      # For OOM killer events

  service_health:
    description: "Check service status and dependencies"
    use_when: "User asks why a service is down or unhealthy"
    queries:
      - get_processes
      - get_journal_logs     # Filtered to service
      - get_listening_ports
      - get_network_info     # Connection state
      - get_fd_limits
```

### 2. Incident Response Profiles

For time-sensitive triage:

```yaml
profiles:
  incident_triage:
    description: "First-pass data collection for security incidents"
    use_when: "Active incident, breach suspected, immediate triage needed"
    scope_required: sensitive
    queries:
      - get_processes
      - get_network_info
      - get_listening_ports
      - get_auth_logs
      - get_journal_logs
      - get_user_accounts
      - get_cron_jobs
      - get_startup_items
    params:
      logs_max_age_minutes: 60
      processes_include_cmdline: true

  lateral_movement_check:
    description: "Check for signs of lateral movement"
    use_when: "Investigating potential attacker movement between systems"
    scope_required: sensitive
    queries:
      - get_auth_logs        # SSH, sudo attempts
      - get_network_info     # Unusual connections
      - get_processes        # Remote shells, tunnels
      - get_ssh_config       # Forwarding enabled?
      - get_user_accounts    # New accounts?
```

### 3. Compliance Profiles

For audit and benchmarking:

```yaml
profiles:
  cis_linux_l1:
    description: "CIS Benchmark Level 1 for Linux"
    use_when: "Compliance audit, security baseline check"
    queries:
      - get_ssh_config
      - get_sudo_config
      - get_firewall_rules
      - get_mount_options
      - get_kernel_params
      - get_user_accounts
      - get_cron_jobs
      - get_selinux_status
      - get_apparmor_status

  pci_dss_check:
    description: "PCI-DSS relevant configuration checks"
    use_when: "PCI compliance audit"
    queries:
      - get_firewall_rules
      - get_listening_ports
      - get_ssl_certs
      - get_auth_logs
      - get_user_accounts
      - get_ntp_status

  hipaa_audit:
    description: "HIPAA-relevant system configuration"
    use_when: "Healthcare compliance audit"
    scope_required: sensitive
    queries:
      - get_user_accounts
      - get_auth_logs
      - get_disk_info        # Encryption status
      - get_firewall_rules
      - get_ssl_certs
```

### 4. Performance Profiles

For optimization:

```yaml
profiles:
  performance_baseline:
    description: "Capture system performance baseline"
    use_when: "User wants to understand current performance state"
    queries:
      - get_cpu_info
      - get_memory_info
      - get_disk_info
      - get_network_info
      - get_processes
      - get_temperature

  bottleneck_hunt:
    description: "Identify performance bottlenecks"
    use_when: "System is slow, need to find the cause"
    queries:
      - get_cpu_info
      - get_memory_info
      - get_disk_info
      - get_processes        # Top by CPU and memory
      - get_ipc_resources
      - get_fd_limits
      - get_cgroup_limits
```

---

## Profile Configuration

### Definition Format

```yaml
profiles:
  profile_name:
    # Required
    description: "Human-readable description"
    queries:
      - query_name_1
      - query_name_2

    # Optional
    use_when: "Hint for AI about when to use this profile"
    scope_required: sensitive  # Minimum scope needed

    # Query parameters (applied to all queries that accept them)
    params:
      limit: 100
      max_age_hours: 24

    # Per-query parameter overrides
    query_params:
      get_processes:
        sort_by: memory
        limit: 20
      get_journal_logs:
        unit: nginx
        lines: 500

    # Resource budget for entire profile
    budget:
      timeout_ms: 30000      # 30s for all queries combined
      max_output_bytes: 5242880  # 5MB total output
```

### Scope Requirements

Profiles inherit scope from their queries:

| Profile Contains | Required Scope |
|------------------|----------------|
| Only `core` queries | `core` |
| Any `logs` query | `logs` |
| Any `sensitive` query | `sensitive` |

```yaml
profiles:
  basic_health:
    # Only needs 'core' scope
    queries:
      - get_cpu_info
      - get_memory_info
      - get_disk_info

  full_triage:
    # Needs 'sensitive' scope because of get_auth_logs
    scope_required: sensitive
    queries:
      - get_cpu_info
      - get_auth_logs      # <- sensitive
      - get_processes
```

---

## Calling Profiles

### MCP Tool Interface

Profiles are exposed as a single MCP tool:

```json
{
  "name": "run_profile",
  "description": "Run a predefined query profile",
  "inputSchema": {
    "type": "object",
    "properties": {
      "profile": {
        "type": "string",
        "description": "Profile name",
        "enum": ["network_audit", "incident_triage", "cis_linux_l1", "..."]
      },
      "params": {
        "type": "object",
        "description": "Override default parameters"
      }
    },
    "required": ["profile"]
  }
}
```

### Example Call

```json
{
  "tool": "run_profile",
  "arguments": {
    "profile": "network_audit"
  }
}
```

### Response Format

```json
{
  "profile": "network_audit",
  "executed_at": "2024-12-12T10:30:00Z",
  "duration_ms": 1250,
  "results": {
    "get_listening_ports": {
      "status": "success",
      "data": { ... }
    },
    "get_firewall_rules": {
      "status": "success",
      "data": { ... }
    },
    "get_network_info": {
      "status": "success",
      "data": { ... }
    },
    "get_ssh_config": {
      "status": "error",
      "error": "Permission denied: /etc/ssh/sshd_config"
    },
    "get_dns_config": {
      "status": "success",
      "data": { ... }
    },
    "get_routing_table": {
      "status": "success",
      "data": { ... }
    }
  },
  "summary": {
    "total_queries": 6,
    "successful": 5,
    "failed": 1,
    "output_bytes": 45230
  }
}
```

---

## Listing Profiles

### Discovery Tool

```json
{
  "name": "list_profiles",
  "description": "List available query profiles"
}
```

### Response

```json
{
  "profiles": [
    {
      "name": "network_audit",
      "description": "Assess network attack surface and exposure",
      "use_when": "User asks about network security, exposure, or attack surface",
      "queries": ["get_listening_ports", "get_firewall_rules", "..."],
      "scope_required": "core"
    },
    {
      "name": "incident_triage",
      "description": "First-pass data collection for security incidents",
      "use_when": "Active incident, breach suspected, immediate triage needed",
      "queries": ["get_processes", "get_network_info", "..."],
      "scope_required": "sensitive"
    }
  ]
}
```

---

## AI Integration Guidelines

### When AI Should Use Profiles

| Situation | Recommendation |
|-----------|----------------|
| User asks broad question ("is my network secure?") | Use profile for initial data |
| User asks specific question ("what's on port 443?") | Use individual query |
| Incident response, time-sensitive | Use profile for speed |
| Follow-up investigation | Use individual queries |
| Compliance audit | Use compliance profile |
| Novel/unusual question | Use individual queries |

### System Prompt Guidance

Include in AI system prompt:

```
You have access to both individual queries and query profiles.

PROFILES: Use profiles when investigating broad topics. Profiles bundle
related queries into a single call for efficiency. After receiving profile
results, you can call individual queries for deeper investigation.

Available profiles:
- network_audit: Network security assessment
- incident_triage: Security incident first response
- cis_linux_l1: CIS compliance check
- performance_baseline: System performance snapshot

INDIVIDUAL QUERIES: Use individual queries when:
- You need specific data not covered by a profile
- Following up on profile results with targeted queries
- The user's question is narrow and specific

Example workflow:
1. User: "Check if my server is secure"
2. You: Call profile "network_audit" for broad assessment
3. Results show port 3306 open to 0.0.0.0
4. You: Call individual "get_processes" filtered to mysql for details
5. You: Provide recommendations based on combined data
```

---

## Custom Profiles

### User-Defined Profiles

Users can define custom profiles in config:

```yaml
# /etc/mcp-sysinfo/config.yaml

custom_profiles:
  my_app_health:
    description: "Check health of my specific application"
    queries:
      - get_processes
      - get_app_logs
      - get_network_info
    query_params:
      get_processes:
        filter: "myapp"
      get_app_logs:
        path: "/var/log/myapp/*.log"
        lines: 200
```

### Profile Inheritance

Extend built-in profiles:

```yaml
custom_profiles:
  extended_network_audit:
    extends: network_audit
    additional_queries:
      - get_arp_cache
      - get_ssl_certs
    query_params:
      get_ssl_certs:
        paths:
          - /etc/ssl/certs
          - /etc/nginx/ssl
```

---

## Security Considerations

### Profile Scope Enforcement

- Profiles cannot bypass scope restrictions
- If a profile includes `get_auth_logs` (sensitive), caller needs `sensitive` scope
- Missing scope = query skipped with error in results

### Audit Logging

Profile calls logged as single audit event:

```json
{
  "ts": "2024-12-12T10:30:00Z",
  "event": "profile",
  "profile": "incident_triage",
  "queries_executed": 8,
  "queries_succeeded": 7,
  "queries_denied": 1,
  "denied_queries": ["get_auth_logs"],
  "denial_reason": "scope:sensitive not granted",
  "client": {
    "jwt_sub": "user@example.com",
    "scopes": ["core", "logs"]
  }
}
```

### Resource Limits

Profile-level limits prevent abuse:

```yaml
profiles:
  expensive_audit:
    queries: [...]
    budget:
      timeout_ms: 60000        # 1 minute max
      max_output_bytes: 10485760  # 10MB max
      max_concurrent: 3        # Run max 3 queries in parallel
```

---

## Comparison: Profiles vs AI-Only

| Aspect | Profiles | AI-Only |
|--------|----------|---------|
| Latency | 1 round-trip | N round-trips |
| Flexibility | Fixed query set | Adaptive |
| Expert knowledge | Encoded in profile | AI must learn |
| Over-fetching | Possible | Minimal |
| Novel situations | Limited | Excellent |
| Compliance/audit | Reproducible | Variable |
| Debugging | Easier (known queries) | Harder |

**Recommendation**: Support both. Profiles for known patterns, individual queries for everything else. Let AI choose based on context.
