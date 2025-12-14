// Package main generates documentation for MCP System Info queries.
//
// Usage:
//
//	go run ./cmd/docgen -output docs/queries
//
// This tool extracts query definitions from the MCP server and generates
// markdown documentation including descriptions, parameters, response schemas,
// and example outputs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/template"
	"time"
)

// QueryDoc represents documentation for a single query.
type QueryDoc struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	Scope       string         `json:"scope"`
	Parameters  []ParameterDoc `json:"parameters,omitempty"`
	Linux       string         `json:"linux"`
	MacOS       string         `json:"macos"`
	Windows     string         `json:"windows"`
	Example     *ExampleDoc    `json:"example,omitempty"`
	Schema      map[string]any `json:"schema,omitempty"`
}

// ParameterDoc represents a query parameter.
type ParameterDoc struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	Default     string `json:"default,omitempty"`
}

// ExampleDoc represents an example request/response.
type ExampleDoc struct {
	Request  string `json:"request"`
	Response string `json:"response"`
}

// CategoryDoc represents a category of queries.
type CategoryDoc struct {
	Name        string     `json:"name"`
	Slug        string     `json:"slug"`
	Description string     `json:"description"`
	Queries     []QueryDoc `json:"queries"`
}

// queryDefinitions contains all query metadata.
// This is the source of truth for documentation.
var queryDefinitions = []QueryDoc{
	// Core Metrics
	{
		Name:        "get_cpu_info",
		Description: "Returns CPU usage, frequency, load average, and core information.",
		Category:    "core",
		Scope:       "core",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
		Parameters: []ParameterDoc{
			{Name: "per_cpu", Type: "boolean", Required: false, Description: "Include per-CPU breakdown", Default: "false"},
		},
	},
	{
		Name:        "get_memory_info",
		Description: "Returns memory usage including total, used, available, and swap.",
		Category:    "core",
		Scope:       "core",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_disk_info",
		Description: "Returns disk partition information including mount points, usage, and filesystem type.",
		Category:    "core",
		Scope:       "core",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_network_info",
		Description: "Returns network interface information including addresses, I/O statistics, and connection state.",
		Category:    "core",
		Scope:       "core",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_processes",
		Description: "Returns a list of running processes with CPU and memory usage.",
		Category:    "core",
		Scope:       "core",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
		Parameters: []ParameterDoc{
			{Name: "top", Type: "integer", Required: false, Description: "Limit to top N processes by CPU", Default: "all"},
			{Name: "sort_by", Type: "string", Required: false, Description: "Sort field: cpu, memory, pid, name", Default: "cpu"},
		},
	},
	{
		Name:        "get_uptime",
		Description: "Returns system uptime and boot time.",
		Category:    "core",
		Scope:       "core",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_temperature",
		Description: "Returns hardware temperature sensor readings.",
		Category:    "core",
		Scope:       "core",
		Linux:       "full",
		MacOS:       "partial",
		Windows:     "partial",
	},
	// Log Access
	{
		Name:        "get_journal_logs",
		Description: "Returns systemd journal logs with filtering options.",
		Category:    "logs",
		Scope:       "logs",
		Linux:       "full",
		MacOS:       "none",
		Windows:     "none",
		Parameters: []ParameterDoc{
			{Name: "unit", Type: "string", Required: false, Description: "Filter by systemd unit"},
			{Name: "priority", Type: "string", Required: false, Description: "Minimum priority (emerg, alert, crit, err, warning, notice, info, debug)"},
			{Name: "since", Type: "string", Required: false, Description: "Show entries since timestamp"},
			{Name: "lines", Type: "integer", Required: false, Description: "Number of lines to return", Default: "100"},
		},
	},
	{
		Name:        "get_syslog",
		Description: "Returns traditional syslog entries.",
		Category:    "logs",
		Scope:       "logs",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "none",
		Parameters: []ParameterDoc{
			{Name: "lines", Type: "integer", Required: false, Description: "Number of lines to return", Default: "100"},
		},
	},
	{
		Name:        "get_kernel_logs",
		Description: "Returns kernel ring buffer (dmesg) messages.",
		Category:    "logs",
		Scope:       "logs",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "none",
		Parameters: []ParameterDoc{
			{Name: "lines", Type: "integer", Required: false, Description: "Number of lines to return", Default: "100"},
		},
	},
	{
		Name:        "get_auth_logs",
		Description: "Returns authentication and security logs. Requires sensitive scope.",
		Category:    "logs",
		Scope:       "sensitive",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "none",
		Parameters: []ParameterDoc{
			{Name: "lines", Type: "integer", Required: false, Description: "Number of lines to return", Default: "100"},
		},
	},
	{
		Name:        "get_app_logs",
		Description: "Returns application-specific log files.",
		Category:    "logs",
		Scope:       "logs",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
		Parameters: []ParameterDoc{
			{Name: "app", Type: "string", Required: true, Description: "Application name (nginx, apache, mysql, etc.)"},
			{Name: "lines", Type: "integer", Required: false, Description: "Number of lines to return", Default: "100"},
		},
	},
	{
		Name:        "get_event_log",
		Description: "Returns Windows Event Log entries.",
		Category:    "logs",
		Scope:       "logs",
		Linux:       "none",
		MacOS:       "none",
		Windows:     "full",
		Parameters: []ParameterDoc{
			{Name: "log", Type: "string", Required: false, Description: "Log name: System, Application, Security", Default: "System"},
			{Name: "count", Type: "integer", Required: false, Description: "Number of entries to return", Default: "100"},
		},
	},
	// System Hooks - Scheduled Tasks
	{
		Name:        "get_cron_jobs",
		Description: "Returns cron jobs for all users and system crontabs.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "none",
	},
	{
		Name:        "get_startup_items",
		Description: "Returns startup programs and services.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_systemd_services",
		Description: "Returns systemd service unit status.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "none",
		Windows:     "none",
	},
	{
		Name:        "get_scheduled_tasks",
		Description: "Returns Windows Task Scheduler tasks.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "none",
		MacOS:       "none",
		Windows:     "full",
	},
	// System Hooks - Kernel
	{
		Name:        "get_kernel_modules",
		Description: "Returns loaded kernel modules.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "none",
		Windows:     "none",
	},
	{
		Name:        "get_loaded_drivers",
		Description: "Returns loaded kernel drivers/extensions.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	// System Hooks - Network Config
	{
		Name:        "get_dns_servers",
		Description: "Returns configured DNS servers.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_routes",
		Description: "Returns routing table.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_firewall_rules",
		Description: "Returns firewall rules.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_listening_ports",
		Description: "Returns listening network ports with process information.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_arp_table",
		Description: "Returns ARP cache entries.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_network_stats",
		Description: "Returns network interface statistics.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	// System Hooks - Filesystem
	{
		Name:        "get_mounts",
		Description: "Returns mounted filesystems with options.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_disk_io",
		Description: "Returns disk I/O statistics.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "partial",
		Windows:     "partial",
	},
	{
		Name:        "get_open_files",
		Description: "Returns open file handles for a process.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "partial",
		Parameters: []ParameterDoc{
			{Name: "pid", Type: "integer", Required: false, Description: "Process ID to check"},
		},
	},
	{
		Name:        "get_inode_usage",
		Description: "Returns inode usage per filesystem.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "none",
	},
	// System Hooks - Security
	{
		Name:        "get_env_vars",
		Description: "Returns environment variables. Sensitive values are redacted.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_user_accounts",
		Description: "Returns local user accounts.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_sudo_config",
		Description: "Returns sudoers configuration. Requires sensitive scope.",
		Category:    "hooks",
		Scope:       "sensitive",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "none",
	},
	{
		Name:        "get_ssh_config",
		Description: "Returns SSH server configuration. Requires sensitive scope.",
		Category:    "hooks",
		Scope:       "sensitive",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "partial",
	},
	{
		Name:        "get_mac_status",
		Description: "Returns Mandatory Access Control status (SELinux/AppArmor).",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "partial",
		Windows:     "none",
	},
	{
		Name:        "get_certificates",
		Description: "Returns SSL/TLS certificates from system store.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	// System Hooks - Hardware
	{
		Name:        "get_hardware_info",
		Description: "Returns hardware information (DMI/SMBIOS).",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_usb_devices",
		Description: "Returns connected USB devices.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_pci_devices",
		Description: "Returns PCI devices.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "partial",
		Windows:     "partial",
	},
	{
		Name:        "get_block_devices",
		Description: "Returns block device topology.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "partial",
		Windows:     "full",
	},
	// System Hooks - Resources
	{
		Name:        "get_ipc_resources",
		Description: "Returns System V IPC resources (semaphores, shared memory, message queues).",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "partial",
		Windows:     "none",
	},
	{
		Name:        "get_namespaces",
		Description: "Returns Linux namespaces.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "none",
		Windows:     "none",
	},
	{
		Name:        "get_cgroups",
		Description: "Returns cgroup resource limits and usage.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "none",
		Windows:     "none",
	},
	{
		Name:        "get_capabilities",
		Description: "Returns process capabilities.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "none",
		Windows:     "none",
		Parameters: []ParameterDoc{
			{Name: "pid", Type: "integer", Required: false, Description: "Process ID", Default: "self"},
		},
	},
	// System Hooks - State
	{
		Name:        "get_vm_info",
		Description: "Returns virtualization/hypervisor detection.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_timezone",
		Description: "Returns timezone and locale information.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_ntp_status",
		Description: "Returns NTP synchronization status.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_core_dumps",
		Description: "Returns core dump configuration and recent dumps.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_power_state",
		Description: "Returns power supply and battery state.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_numa_topology",
		Description: "Returns NUMA node topology.",
		Category:    "hooks",
		Scope:       "hooks",
		Linux:       "full",
		MacOS:       "none",
		Windows:     "none",
	},
	// SBOM
	{
		Name:        "get_path_executables",
		Description: "Returns executables found in PATH directories.",
		Category:    "sbom",
		Scope:       "sbom",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_system_packages",
		Description: "Returns installed system packages.",
		Category:    "sbom",
		Scope:       "sbom",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_python_packages",
		Description: "Returns installed Python packages from site-packages.",
		Category:    "sbom",
		Scope:       "sbom",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_node_packages",
		Description: "Returns globally installed Node.js packages.",
		Category:    "sbom",
		Scope:       "sbom",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_go_modules",
		Description: "Returns Go modules from the module cache.",
		Category:    "sbom",
		Scope:       "sbom",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_rust_packages",
		Description: "Returns Rust crates from the Cargo registry cache.",
		Category:    "sbom",
		Scope:       "sbom",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
	{
		Name:        "get_ruby_gems",
		Description: "Returns installed Ruby gems.",
		Category:    "sbom",
		Scope:       "sbom",
		Linux:       "full",
		MacOS:       "full",
		Windows:     "full",
	},
}

var categories = []CategoryDoc{
	{
		Name:        "Core Metrics",
		Slug:        "core",
		Description: "Fundamental system health: CPU, memory, disk, network, and processes.",
	},
	{
		Name:        "Log Access",
		Slug:        "logs",
		Description: "System logs, journals, and event logs for diagnostics.",
	},
	{
		Name:        "System Hooks",
		Slug:        "hooks",
		Description: "Deep system introspection: scheduled tasks, kernel, network config, security.",
	},
	{
		Name:        "Software Inventory",
		Slug:        "sbom",
		Description: "Package managers, executables, and language-specific dependencies.",
	},
}

const queryTemplate = `# {{ .Name }}

{{ .Description }}

## Platform Support

| Linux | macOS | Windows |
|:-----:|:-----:|:-------:|
| {{ platformIcon .Linux }} | {{ platformIcon .MacOS }} | {{ platformIcon .Windows }} |

## Scope

This query is in the ` + "`{{ .Scope }}`" + ` scope{{ if eq .Scope "sensitive" }} and is **disabled by default**{{ end }}.

{{ if .Parameters }}
## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
{{ range .Parameters -}}
| ` + "`{{ .Name }}`" + ` | {{ .Type }} | {{ if .Required }}Yes{{ else }}No{{ end }} | {{ if .Default }}` + "`{{ .Default }}`" + `{{ else }}-{{ end }} | {{ .Description }} |
{{ end }}
{{ end }}

## Example

### Request

` + "```json" + `
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "{{ .Name }}"
  }
}
` + "```" + `

### Response

` + "```json" + `
{{ .ExampleResponse }}
` + "```" + `

## Implementation

{{ if eq .Linux "full" -}}
- **Linux**: Native implementation using procfs/sysfs
{{ else if eq .Linux "partial" -}}
- **Linux**: Partial support
{{ end -}}
{{ if eq .MacOS "full" -}}
- **macOS**: Native implementation using sysctl/IOKit
{{ else if eq .MacOS "partial" -}}
- **macOS**: Partial support
{{ end -}}
{{ if eq .Windows "full" -}}
- **Windows**: Native implementation using WMI/Registry
{{ else if eq .Windows "partial" -}}
- **Windows**: Partial support
{{ end }}

---

*Documentation auto-generated on {{ .GeneratedAt }}*
`

const categoryIndexTemplate = `# {{ .Name }}

{{ .Description }}

## Queries

| Query | Description | Linux | macOS | Windows |
|-------|-------------|:-----:|:-----:|:-------:|
{{ range .Queries -}}
| [` + "`{{ .Name }}`" + `]({{ .Name }}.md) | {{ .Description | truncate 50 }} | {{ platformIcon .Linux }} | {{ platformIcon .MacOS }} | {{ platformIcon .Windows }} |
{{ end }}

## Scope

All queries in this category are in the ` + "`{{ .Slug }}`" + ` scope{{ if eq .Slug "sensitive" }} (disabled by default){{ end }}.

---

*Documentation auto-generated on {{ .GeneratedAt }}*
`

func main() {
	outputDir := flag.String("output", "docs/queries", "Output directory for generated docs")
	flag.Parse()

	funcMap := template.FuncMap{
		"platformIcon": func(support string) string {
			switch support {
			case "full":
				return ":white_check_mark:"
			case "partial":
				return ":warning:"
			default:
				return ":x:"
			}
		},
		"truncate": func(length int, s string) string {
			if len(s) <= length {
				return s
			}
			return s[:length-3] + "..."
		},
	}

	queryTmpl := template.Must(template.New("query").Funcs(funcMap).Parse(queryTemplate))
	categoryTmpl := template.Must(template.New("category").Funcs(funcMap).Parse(categoryIndexTemplate))

	// Group queries by category
	queryByCategory := make(map[string][]QueryDoc)
	for _, q := range queryDefinitions {
		queryByCategory[q.Category] = append(queryByCategory[q.Category], q)
	}

	generatedAt := time.Now().Format("2006-01-02")

	// Generate query pages
	for _, q := range queryDefinitions {
		dir := filepath.Join(*outputDir, q.Category)
		// #nosec G301 -- Documentation output directory needs to be readable
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error creating directory %s: %v\n", dir, err)
			continue
		}

		path := filepath.Join(dir, q.Name+".md")
		// #nosec G304 -- Path is constructed from trusted query definitions
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating file %s: %v\n", path, err)
			continue
		}

		data := struct {
			QueryDoc
			ExampleResponse string
			GeneratedAt     string
		}{
			QueryDoc:        q,
			ExampleResponse: generateExampleResponse(q.Name),
			GeneratedAt:     generatedAt,
		}

		if err := queryTmpl.Execute(f, data); err != nil {
			fmt.Fprintf(os.Stderr, "Error executing template for %s: %v\n", q.Name, err)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file %s: %v\n", path, err)
		}

		fmt.Printf("Generated: %s\n", path)
	}

	// Generate category index pages
	for _, cat := range categories {
		queries := queryByCategory[cat.Slug]
		sort.Slice(queries, func(i, j int) bool {
			return queries[i].Name < queries[j].Name
		})

		path := filepath.Join(*outputDir, cat.Slug, "index.md")
		// #nosec G304 -- Path is constructed from trusted category definitions
		f, err := os.Create(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating file %s: %v\n", path, err)
			continue
		}

		data := struct {
			CategoryDoc
			Queries     []QueryDoc
			GeneratedAt string
		}{
			CategoryDoc: cat,
			Queries:     queries,
			GeneratedAt: generatedAt,
		}

		if err := categoryTmpl.Execute(f, data); err != nil {
			fmt.Fprintf(os.Stderr, "Error executing template for %s: %v\n", cat.Slug, err)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing file %s: %v\n", path, err)
		}

		fmt.Printf("Generated: %s\n", path)
	}

	// Generate main index
	generateMainIndex(*outputDir, generatedAt)

	fmt.Printf("\nDocumentation generated in %s\n", *outputDir)
}

func generateMainIndex(outputDir, generatedAt string) {
	content := fmt.Sprintf(`# Query Reference

MCP System Info provides **%d queries** across multiple categories for comprehensive system diagnostics.

!!! note "Auto-Generated"
    This documentation is automatically generated from the source code on each release.

## Query Categories

| Category | Queries | Description |
|----------|---------|-------------|
`, len(queryDefinitions))

	queryByCategory := make(map[string]int)
	for _, q := range queryDefinitions {
		queryByCategory[q.Category]++
	}

	for _, cat := range categories {
		content += fmt.Sprintf("| [%s](%s/index.md) | %d | %s |\n",
			cat.Name, cat.Slug, queryByCategory[cat.Slug], cat.Description)
	}

	content += fmt.Sprintf(`
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
| `+"`core`"+` | Low | Enabled |
| `+"`logs`"+` | Medium | Enabled |
| `+"`hooks`"+` | Medium | Enabled |
| `+"`sbom`"+` | Medium | Enabled |
| `+"`sensitive`"+` | **High** | **Disabled** |

---

*Documentation auto-generated on %s*
`, generatedAt)

	path := filepath.Join(outputDir, "index.md")
	// #nosec G306 -- Documentation files need to be world-readable
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", path, err)
		return
	}
	fmt.Printf("Generated: %s\n", path)
}

// generateExampleResponse creates a sample response for a query.
func generateExampleResponse(queryName string) string {
	// In a real implementation, this would run the actual query
	// and capture the output. For now, return placeholder examples.
	examples := map[string]any{
		"get_cpu_info": map[string]any{
			"cpu_percent":  12.5,
			"cpu_count":    8,
			"cpu_freq_mhz": 2400.0,
			"load_average": []float64{1.2, 0.8, 0.5},
			"model_name":   "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz",
			"timestamp":    "2024-01-15T10:30:00Z",
		},
		"get_memory_info": map[string]any{
			"total_bytes":     17179869184,
			"used_bytes":      8589934592,
			"available_bytes": 8589934592,
			"percent_used":    50.0,
			"swap_total":      4294967296,
			"swap_used":       1073741824,
			"timestamp":       "2024-01-15T10:30:00Z",
		},
		"get_uptime": map[string]any{
			"uptime_seconds": 86400,
			"uptime_human":   "1 day, 0 hours, 0 minutes",
			"boot_time":      "2024-01-14T10:30:00Z",
			"timestamp":      "2024-01-15T10:30:00Z",
		},
	}

	if example, ok := examples[queryName]; ok {
		data, _ := json.MarshalIndent(example, "", "  ")
		return string(data)
	}

	// Default placeholder
	return `{
  "result": "...",
  "timestamp": "2024-01-15T10:30:00Z"
}`
}
