# Tier 6: LLM-Optimized Features

Natural language interface, diagnostics, documentation generation, and conversational context.

---

## Natural Language Interface

### Semantic Queries
Understand natural language like "Show me what's using the most memory".

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Map common phrases to tool calls | Python stdlib | None |
| **All** | Keyword extraction | Python stdlib | None |
| **All** | Intent classification | pip | `pip install scikit-learn` (optional) |
| **All** | Return appropriate tool with parameters | Python stdlib | None |

---

### Contextual Verbosity
Tailor response detail to the question complexity.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Detect question type (overview vs investigation) | Python stdlib | None |
| **All** | Return summary or detailed data | Python stdlib | None |

---

### Explanation Generation
Provide reasoned analysis like "Why is my system slow?"

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Collect multiple metrics | pip | `pip install psutil` |
| **All** | Apply heuristics (high CPU + high I/O = thrashing) | Python stdlib | None |
| **All** | Return structured explanation | Python stdlib | None |

---

### Recommendation Engine
Suggest optimizations based on observed patterns.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Rule-based: "High swap → add RAM" | Python stdlib | None |
| **macOS** | Platform tips: "Close Safari tabs for memory" | Python stdlib | None |
| **Windows** | Platform tips: "Disable startup programs" | Python stdlib | None |
| **All** | Store recommendations with conditions | Python stdlib | None |

---

## Diagnostic Workflows

### Guided Troubleshooting
Step-by-step diagnostic flows for common issues.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Decision tree: Slow? → CPU → Memory → Disk → Network | Python stdlib | None |
| **macOS** | Include: check Spotlight indexing, Time Machine | Python stdlib | None |
| **Windows** | Include: Windows Update, Defender scans, disk cleanup | Python stdlib | None |

---

### Root Cause Analysis
Automated RCA with evidence chain.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Correlate metrics around incident time | pip | `pip install pandas` |
| **All** | Build causal chain | Python stdlib | None |
| **All** | "High latency ← disk I/O ← backup running" | Python stdlib | None |

---

### Health Scoring
Overall system health 0-100 with category breakdown.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Weight: CPU(20), Memory(20), Disk(20), Network(15), Security(25) | Python stdlib | None |
| **macOS** | Adjust for macOS-specific indicators | Python stdlib | None |
| **Windows** | Include Windows Update status, Defender | Python stdlib | None |
| **All** | Deduct points for issues | Python stdlib | None |

---

### Issue Summarization
Concise summary of detected issues.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Aggregate active alerts | Python stdlib | None |
| **All** | Group by severity | Python stdlib | None |
| **All** | "3 issues: high memory (Chrome 4GB), disk 92%, 47 failed SSH logins" | Python stdlib | None |

---

## Documentation Generation

### System Documentation
Auto-generate system inventory and architecture docs.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Template with hardware specs, software, network config | Python stdlib | None |
| **macOS** | Include macOS version, apps, preferences | Python stdlib | None |
| **Windows** | Include Windows version, software, network | Python stdlib | None |
| **All** | Output Markdown | Python stdlib | None |

---

### Incident Reports
Generate post-mortem reports from metrics and events.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Template: Timeline, Impact, Root Cause, Resolution | Python stdlib | None |
| **All** | Auto-populate from stored metrics/alerts | pip | `pip install duckdb` or stdlib |

---

### Change Logs
Track and document system changes over time.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **Linux** | Diff snapshots over time | Python stdlib | None |
| **Linux** | "2024-01-15: nginx 1.24→1.25" | Python stdlib | None |
| **macOS** | Diff snapshots | Python stdlib | None |
| **Windows** | Include Windows Update history | Built-in | None |

---

### Runbook Generation
Create operational runbooks from observed patterns.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Observe remediation actions | Python stdlib | None |
| **All** | Generate: "When disk >90%: 1. Check large files, 2. Clear logs" | Python stdlib | None |

---

## Conversational Context

### Session Memory
Remember what was discussed earlier in the conversation.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | MCP server maintains session state | pip | MCP SDK |
| **All** | Store previous queries and results | Python stdlib | None |
| **All** | Reference in responses | Python stdlib | None |

---

### Progressive Investigation
Build up context across multiple queries.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Track investigation state | Python stdlib | None |
| **All** | "Earlier you asked about high CPU, now checking memory for same timeframe" | Python stdlib | None |

---

### Comparative References
Compare to previous queries: "Is this higher than last time I asked?"

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | Store query results with timestamps | Python stdlib | None |
| **All** | On repeat query, compare and report delta | Python stdlib | None |

---

### Proactive Insights
Surface relevant information without being asked.

| Platform | Implementation | Availability | Install |
|----------|----------------|--------------|---------|
| **All** | When returning results, check for related anomalies | pip | `pip install psutil` |
| **All** | "CPU is normal, but disk is 95% full" | Python stdlib | None |
