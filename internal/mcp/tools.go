package mcp

import (
	"context"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/alerts"
	"github.com/levantar-ai/mcp-sysinfo/internal/analytics"
	"github.com/levantar-ai/mcp-sysinfo/internal/compliance"
	"github.com/levantar-ai/mcp-sysinfo/internal/consumer"
	"github.com/levantar-ai/mcp-sysinfo/internal/container"
	"github.com/levantar-ai/mcp-sysinfo/internal/cpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
	"github.com/levantar-ai/mcp-sysinfo/internal/filesystem"
	"github.com/levantar-ai/mcp-sysinfo/internal/gpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/hardware"
	"github.com/levantar-ai/mcp-sysinfo/internal/kernel"
	"github.com/levantar-ai/mcp-sysinfo/internal/logs"
	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
	"github.com/levantar-ai/mcp-sysinfo/internal/netconfig"
	"github.com/levantar-ai/mcp-sysinfo/internal/network"
	"github.com/levantar-ai/mcp-sysinfo/internal/osinfo"
	"github.com/levantar-ai/mcp-sysinfo/internal/process"
	"github.com/levantar-ai/mcp-sysinfo/internal/report"
	"github.com/levantar-ai/mcp-sysinfo/internal/resources"
	"github.com/levantar-ai/mcp-sysinfo/internal/runtimes"
	"github.com/levantar-ai/mcp-sysinfo/internal/scheduled"
	"github.com/levantar-ai/mcp-sysinfo/internal/security"
	"github.com/levantar-ai/mcp-sysinfo/internal/software"
	"github.com/levantar-ai/mcp-sysinfo/internal/state"
	"github.com/levantar-ai/mcp-sysinfo/internal/storage"
	"github.com/levantar-ai/mcp-sysinfo/internal/temperature"
	"github.com/levantar-ai/mcp-sysinfo/internal/triage"
	"github.com/levantar-ai/mcp-sysinfo/internal/uptime"
	"github.com/levantar-ai/mcp-sysinfo/internal/windows"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// RegisterAllTools registers all system info tools with the MCP server.
func RegisterAllTools(s *Server) {
	// Phase 1.0: Core Metrics (scope: core)
	registerCoreTools(s)

	// Phase 1.1: Log Access (scope: logs)
	registerLogTools(s)

	// Phase 1.2: System Hooks (scope: hooks)
	registerHookTools(s)

	// Phase 1.2.5: Security Configuration (scope: sensitive)
	registerSecurityTools(s)

	// Phase 1.2.6: Hardware Information (scope: hardware)
	registerHardwareTools(s)

	// Phase 1.2.7: Process & Resources (scope: resources)
	registerResourceTools(s)

	// Phase 1.2.8: System State (scope: state)
	registerStateTools(s)

	// Phase 1.3: SBOM & Software Inventory (scope: software)
	registerSoftwareTools(s)

	// Phase 1.5: Triage & Summary Queries (scope: triage)
	registerTriageTools(s)

	// Phase 1.6: Windows Enterprise Features (scope: windows)
	registerWindowsEnterpriseTools(s)

	// Phase 2.0: Enhanced Diagnostics (scope: enhanced)
	registerEnhancedDiagnosticsTools(s)

	// Phase 2.3: System Reports (scope: report)
	registerReportTools(s)

	// Phase 3: Storage Deep Dive (scope: storage)
	registerStorageTools(s)

	// Phase 1.9: Platform Security Controls (scope: security)
	registerPlatformSecurityTools(s)

	// Phase 4: Network Intelligence (scope: network)
	registerNetworkIntelligenceTools(s)

	// Phase 5: Analytics & Trends (scope: analytics)
	registerAnalyticsTools(s)

	// Phase 6: Automation & Alerting (scope: alerts)
	registerAlertingTools(s)

	// Phase 7: Security & Compliance (scope: compliance)
	registerComplianceTools(s)

	// Phase 1.9: Consumer Diagnostics (scope: consumer)
	registerConsumerDiagnosticsTools(s)
}

func registerCoreTools(s *Server) {
	// CPU Info
	s.RegisterTool(Tool{
		Name:        "get_cpu_info",
		Description: "Get CPU usage, frequency, load average, and core count",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"per_cpu": {
					Type:        "boolean",
					Description: "Include per-CPU core statistics",
					Default:     false,
				},
			},
		},
	}, "core", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		perCPU, _ := args["per_cpu"].(bool)
		c := cpu.NewCollector()
		result, err := c.Collect(perCPU)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Memory Info
	s.RegisterTool(Tool{
		Name:        "get_memory_info",
		Description: "Get total, used, available memory and swap usage",
		InputSchema: InputSchema{Type: "object"},
	}, "core", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := memory.NewCollector()
		result, err := c.Collect()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Disk Info
	s.RegisterTool(Tool{
		Name:        "get_disk_info",
		Description: "Get disk partitions, usage, and filesystem types",
		InputSchema: InputSchema{Type: "object"},
	}, "core", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := disk.NewCollector()
		result, err := c.Collect()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Network Info
	s.RegisterTool(Tool{
		Name:        "get_network_info",
		Description: "Get network interfaces, I/O counters, and connections",
		InputSchema: InputSchema{Type: "object"},
	}, "core", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := network.NewCollector()
		result, err := c.Collect()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Processes
	s.RegisterTool(Tool{
		Name:        "get_processes",
		Description: "Get running processes, optionally sorted by CPU or memory usage",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"limit": {
					Type:        "integer",
					Description: "Maximum number of processes to return",
					Default:     10,
				},
				"sort_by": {
					Type:        "string",
					Description: "Sort by 'cpu' or 'memory'",
					Enum:        []string{"cpu", "memory"},
					Default:     "cpu",
				},
			},
		},
	}, "core", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		limit := 10
		if l, ok := args["limit"].(float64); ok {
			limit = int(l)
		}
		sortBy := "cpu"
		if s, ok := args["sort_by"].(string); ok {
			sortBy = s
		}
		c := process.NewCollector()
		result, err := c.GetTopProcesses(limit, sortBy)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Processes with accurate CPU% via time-delta sampling
	s.RegisterTool(Tool{
		Name:        "get_processes_sampled",
		Description: "Get running processes with accurate CPU% via time-delta sampling. Takes two CPU time measurements with a delay to calculate accurate CPU usage.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"sample_duration_ms": {
					Type:        "integer",
					Description: "Duration between CPU time measurements in milliseconds (default: 1000)",
					Default:     1000,
				},
			},
		},
	}, "core", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		sampleDuration := 1000
		if d, ok := args["sample_duration_ms"].(float64); ok && d > 0 {
			sampleDuration = int(d)
		}
		c := process.NewCollector()
		result, err := c.CollectSampled(sampleDuration)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Uptime
	s.RegisterTool(Tool{
		Name:        "get_uptime",
		Description: "Get system boot time and uptime duration",
		InputSchema: InputSchema{Type: "object"},
	}, "core", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := uptime.NewCollector()
		result, err := c.Collect()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Temperature
	s.RegisterTool(Tool{
		Name:        "get_temperature",
		Description: "Get hardware temperature sensor readings",
		InputSchema: InputSchema{Type: "object"},
	}, "core", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := temperature.NewCollector()
		result, err := c.Collect()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerLogTools(s *Server) {
	// Journal Logs (Linux)
	s.RegisterTool(Tool{
		Name:        "get_journal_logs",
		Description: "Get systemd journal logs (Linux only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"lines": {
					Type:        "integer",
					Description: "Number of log lines to return",
					Default:     50,
				},
				"unit": {
					Type:        "string",
					Description: "Filter by systemd unit name",
				},
				"priority": {
					Type:        "string",
					Description: "Filter by priority (emerg, alert, crit, err, warning, notice, info, debug)",
				},
			},
		},
	}, "logs", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		query := &types.LogQuery{Lines: 50}
		if l, ok := args["lines"].(float64); ok {
			query.Lines = int(l)
		}
		if u, ok := args["unit"].(string); ok {
			query.Unit = u
		}
		if p, ok := args["priority"].(float64); ok {
			query.Priority = int(p)
		}
		c := logs.NewCollector()
		result, err := c.GetJournalLogs(query)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Syslog
	s.RegisterTool(Tool{
		Name:        "get_syslog",
		Description: "Get traditional syslog entries",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"lines": {
					Type:        "integer",
					Description: "Number of log lines to return",
					Default:     50,
				},
			},
		},
	}, "logs", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		query := &types.LogQuery{Lines: 50}
		if l, ok := args["lines"].(float64); ok {
			query.Lines = int(l)
		}
		c := logs.NewCollector()
		result, err := c.GetSyslog(query)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Kernel Logs
	s.RegisterTool(Tool{
		Name:        "get_kernel_logs",
		Description: "Get kernel/dmesg logs",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"lines": {
					Type:        "integer",
					Description: "Number of log lines to return",
					Default:     50,
				},
			},
		},
	}, "logs", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		query := &types.LogQuery{Lines: 50}
		if l, ok := args["lines"].(float64); ok {
			query.Lines = int(l)
		}
		c := logs.NewCollector()
		result, err := c.GetKernelLogs(query)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Auth Logs (sensitive)
	s.RegisterTool(Tool{
		Name:        "get_auth_logs",
		Description: "Get authentication logs (requires 'sensitive' scope)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"lines": {
					Type:        "integer",
					Description: "Number of log lines to return",
					Default:     50,
				},
			},
		},
	}, "sensitive", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		query := &types.LogQuery{Lines: 50}
		if l, ok := args["lines"].(float64); ok {
			query.Lines = int(l)
		}
		c := logs.NewCollector()
		result, err := c.GetAuthLogs(query)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// App Logs
	s.RegisterTool(Tool{
		Name:        "get_app_logs",
		Description: "Get application-specific logs",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"lines": {
					Type:        "integer",
					Description: "Number of log lines to return",
					Default:     50,
				},
				"path": {
					Type:        "string",
					Description: "Path to log file or directory",
				},
			},
		},
	}, "logs", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		query := &types.AppLogQuery{LogQuery: types.LogQuery{Lines: 50}}
		if l, ok := args["lines"].(float64); ok {
			query.Lines = int(l)
		}
		if p, ok := args["path"].(string); ok {
			query.Path = p
		}
		c := logs.NewCollector()
		result, err := c.GetAppLogs(query)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Event Log (Windows)
	s.RegisterTool(Tool{
		Name:        "get_event_log",
		Description: "Get Windows Event Log entries",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"lines": {
					Type:        "integer",
					Description: "Number of entries to return",
					Default:     50,
				},
				"log_name": {
					Type:        "string",
					Description: "Event log name (Application, System, Security)",
					Default:     "System",
				},
			},
		},
	}, "logs", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		query := &types.EventLogQuery{LogQuery: types.LogQuery{Lines: 50}}
		if l, ok := args["lines"].(float64); ok {
			query.Lines = int(l)
		}
		if n, ok := args["log_name"].(string); ok {
			query.Channel = n
		}
		c := logs.NewCollector()
		result, err := c.GetEventLog(query)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerHookTools(s *Server) {
	// Scheduled Tasks
	s.RegisterTool(Tool{
		Name:        "get_scheduled_tasks",
		Description: "Get scheduled tasks (Windows Task Scheduler, at jobs, launchd)",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := scheduled.NewCollector()
		result, err := c.GetScheduledTasks()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Cron Jobs
	s.RegisterTool(Tool{
		Name:        "get_cron_jobs",
		Description: "Get cron entries (Linux/macOS)",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := scheduled.NewCollector()
		result, err := c.GetCronJobs()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Startup Items
	s.RegisterTool(Tool{
		Name:        "get_startup_items",
		Description: "Get startup programs and services",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := scheduled.NewCollector()
		result, err := c.GetStartupItems()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Systemd Services
	s.RegisterTool(Tool{
		Name:        "get_systemd_services",
		Description: "Get systemd service status (Linux)",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := scheduled.NewCollector()
		result, err := c.GetSystemdServices()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Kernel Modules
	s.RegisterTool(Tool{
		Name:        "get_kernel_modules",
		Description: "Get loaded kernel modules",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := kernel.NewCollector()
		result, err := c.GetKernelModules()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Loaded Drivers
	s.RegisterTool(Tool{
		Name:        "get_loaded_drivers",
		Description: "Get device drivers",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := kernel.NewCollector()
		result, err := c.GetLoadedDrivers()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// DNS Servers
	s.RegisterTool(Tool{
		Name:        "get_dns_servers",
		Description: "Get configured DNS servers",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetDNSServers()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Routes
	s.RegisterTool(Tool{
		Name:        "get_routes",
		Description: "Get routing table",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetRoutes()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Firewall Rules
	s.RegisterTool(Tool{
		Name:        "get_firewall_rules",
		Description: "Get firewall rules",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetFirewallRules()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Listening Ports
	s.RegisterTool(Tool{
		Name:        "get_listening_ports",
		Description: "Get listening network ports",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetListeningPorts()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// ARP Table
	s.RegisterTool(Tool{
		Name:        "get_arp_table",
		Description: "Get ARP table entries",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetARPTable()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Network Stats
	s.RegisterTool(Tool{
		Name:        "get_network_stats",
		Description: "Get network stack statistics",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetNetworkStats()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Mounts
	s.RegisterTool(Tool{
		Name:        "get_mounts",
		Description: "Get mounted filesystems",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := filesystem.NewCollector()
		result, err := c.GetMounts()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Disk I/O
	s.RegisterTool(Tool{
		Name:        "get_disk_io",
		Description: "Get disk I/O statistics",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := filesystem.NewCollector()
		result, err := c.GetDiskIO()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Open Files
	s.RegisterTool(Tool{
		Name:        "get_open_files",
		Description: "Get open file descriptors",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := filesystem.NewCollector()
		result, err := c.GetOpenFiles()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Inode Usage
	s.RegisterTool(Tool{
		Name:        "get_inode_usage",
		Description: "Get inode usage (Linux/macOS)",
		InputSchema: InputSchema{Type: "object"},
	}, "hooks", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := filesystem.NewCollector()
		result, err := c.GetInodeUsage()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerSecurityTools(s *Server) {
	// Environment Variables
	s.RegisterTool(Tool{
		Name:        "get_env_vars",
		Description: "Get system environment variables (sensitive values redacted)",
		InputSchema: InputSchema{Type: "object"},
	}, "sensitive", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetEnvVars()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// User Accounts
	s.RegisterTool(Tool{
		Name:        "get_user_accounts",
		Description: "Get local user accounts and groups",
		InputSchema: InputSchema{Type: "object"},
	}, "sensitive", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetUserAccounts()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Sudo Configuration
	s.RegisterTool(Tool{
		Name:        "get_sudo_config",
		Description: "Get sudo/privilege escalation configuration (Unix-like systems)",
		InputSchema: InputSchema{Type: "object"},
	}, "sensitive", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetSudoConfig()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// SSH Configuration
	s.RegisterTool(Tool{
		Name:        "get_ssh_config",
		Description: "Get SSH server and client configuration",
		InputSchema: InputSchema{Type: "object"},
	}, "sensitive", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetSSHConfig()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// MAC Status (SELinux/AppArmor)
	s.RegisterTool(Tool{
		Name:        "get_mac_status",
		Description: "Get Mandatory Access Control status (SELinux/AppArmor on Linux)",
		InputSchema: InputSchema{Type: "object"},
	}, "sensitive", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMACStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// SSL/TLS Certificates
	s.RegisterTool(Tool{
		Name:        "get_certificates",
		Description: "Get SSL/TLS certificates from system trust store with expiry information",
		InputSchema: InputSchema{Type: "object"},
	}, "sensitive", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetCertificates()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerHardwareTools(s *Server) {
	// Hardware Info
	s.RegisterTool(Tool{
		Name:        "get_hardware_info",
		Description: "Get system, BIOS, and motherboard information",
		InputSchema: InputSchema{Type: "object"},
	}, "hardware", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := hardware.NewCollector()
		result, err := c.GetHardwareInfo()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// USB Devices
	s.RegisterTool(Tool{
		Name:        "get_usb_devices",
		Description: "Get connected USB devices",
		InputSchema: InputSchema{Type: "object"},
	}, "hardware", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := hardware.NewCollector()
		result, err := c.GetUSBDevices()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// PCI Devices
	s.RegisterTool(Tool{
		Name:        "get_pci_devices",
		Description: "Get PCI devices",
		InputSchema: InputSchema{Type: "object"},
	}, "hardware", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := hardware.NewCollector()
		result, err := c.GetPCIDevices()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Block Devices
	s.RegisterTool(Tool{
		Name:        "get_block_devices",
		Description: "Get block device topology",
		InputSchema: InputSchema{Type: "object"},
	}, "hardware", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := hardware.NewCollector()
		result, err := c.GetBlockDevices()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerResourceTools(s *Server) {
	// Process Environment Variables
	s.RegisterTool(Tool{
		Name:        "get_process_environ",
		Description: "Get environment variables for a specific process (Linux only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"pid": {
					Type:        "integer",
					Description: "Process ID to get environment for",
				},
			},
			Required: []string{"pid"},
		},
	}, "resources", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		pid := int32(1) // Default to init
		if p, ok := args["pid"].(float64); ok {
			pid = int32(p)
		}
		c := resources.NewCollector()
		result, err := c.GetProcessEnviron(pid)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// IPC Resources
	s.RegisterTool(Tool{
		Name:        "get_ipc_resources",
		Description: "Get System V IPC resources (shared memory, semaphores, message queues)",
		InputSchema: InputSchema{Type: "object"},
	}, "resources", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := resources.NewCollector()
		result, err := c.GetIPCResources()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Namespaces
	s.RegisterTool(Tool{
		Name:        "get_namespaces",
		Description: "Get Linux namespace information",
		InputSchema: InputSchema{Type: "object"},
	}, "resources", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := resources.NewCollector()
		result, err := c.GetNamespaces()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Cgroups
	s.RegisterTool(Tool{
		Name:        "get_cgroups",
		Description: "Get cgroup limits and usage information",
		InputSchema: InputSchema{Type: "object"},
	}, "resources", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := resources.NewCollector()
		result, err := c.GetCgroups()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Process Capabilities
	s.RegisterTool(Tool{
		Name:        "get_capabilities",
		Description: "Get process capabilities (Linux only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"pid": {
					Type:        "integer",
					Description: "Process ID to get capabilities for",
				},
			},
			Required: []string{"pid"},
		},
	}, "resources", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		pid := int32(1) // Default to init
		if p, ok := args["pid"].(float64); ok {
			pid = int32(p)
		}
		c := resources.NewCollector()
		result, err := c.GetCapabilities(pid)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerStateTools(s *Server) {
	// VM Info
	s.RegisterTool(Tool{
		Name:        "get_vm_info",
		Description: "Detect if running in a virtual machine or container",
		InputSchema: InputSchema{Type: "object"},
	}, "state", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := state.NewCollector()
		result, err := c.GetVMInfo()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Timezone
	s.RegisterTool(Tool{
		Name:        "get_timezone",
		Description: "Get timezone and locale information",
		InputSchema: InputSchema{Type: "object"},
	}, "state", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := state.NewCollector()
		result, err := c.GetTimezone()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// NTP Status
	s.RegisterTool(Tool{
		Name:        "get_ntp_status",
		Description: "Get NTP synchronization status",
		InputSchema: InputSchema{Type: "object"},
	}, "state", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := state.NewCollector()
		result, err := c.GetNTPStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Core Dumps
	s.RegisterTool(Tool{
		Name:        "get_core_dumps",
		Description: "Get core dump/crash dump information",
		InputSchema: InputSchema{Type: "object"},
	}, "state", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := state.NewCollector()
		result, err := c.GetCoreDumps()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Power State
	s.RegisterTool(Tool{
		Name:        "get_power_state",
		Description: "Get power/battery state information",
		InputSchema: InputSchema{Type: "object"},
	}, "state", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := state.NewCollector()
		result, err := c.GetPowerState()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// NUMA Topology
	s.RegisterTool(Tool{
		Name:        "get_numa_topology",
		Description: "Get NUMA topology information",
		InputSchema: InputSchema{Type: "object"},
	}, "state", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := state.NewCollector()
		result, err := c.GetNUMATopology()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerSoftwareTools(s *Server) {
	// PATH Executables
	s.RegisterTool(Tool{
		Name:        "get_path_executables",
		Description: "Get executables found in PATH directories",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetPathExecutables()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// System Packages
	s.RegisterTool(Tool{
		Name:        "get_system_packages",
		Description: "Get installed system packages (dpkg, rpm, apk, pacman, brew, chocolatey)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetSystemPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Python Packages
	s.RegisterTool(Tool{
		Name:        "get_python_packages",
		Description: "Get installed Python packages from site-packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetPythonPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Node.js Packages
	s.RegisterTool(Tool{
		Name:        "get_node_packages",
		Description: "Get globally installed Node.js packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetNodePackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Go Modules
	s.RegisterTool(Tool{
		Name:        "get_go_modules",
		Description: "Get Go modules from the module cache",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetGoModules()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Rust Packages
	s.RegisterTool(Tool{
		Name:        "get_rust_packages",
		Description: "Get Rust crates from Cargo registry cache",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetRustPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Ruby Gems
	s.RegisterTool(Tool{
		Name:        "get_ruby_gems",
		Description: "Get installed Ruby gems",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetRubyGems()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Maven Packages
	s.RegisterTool(Tool{
		Name:        "get_maven_packages",
		Description: "Get Java/Maven packages from ~/.m2/repository",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetMavenPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// PHP Packages
	s.RegisterTool(Tool{
		Name:        "get_php_packages",
		Description: "Get PHP packages from Composer",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetPHPPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// .NET Packages
	s.RegisterTool(Tool{
		Name:        "get_dotnet_packages",
		Description: "Get .NET/NuGet packages from the global package cache",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetDotnetPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// macOS Applications
	s.RegisterTool(Tool{
		Name:        "get_macos_applications",
		Description: "Get installed macOS applications from /Applications (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetMacOSApplications()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Windows Hotfixes
	s.RegisterTool(Tool{
		Name:        "get_windows_hotfixes",
		Description: "Get Windows hotfixes/updates (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetWindowsHotfixes()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// SBOM CycloneDX
	s.RegisterTool(Tool{
		Name:        "get_sbom_cyclonedx",
		Description: "Generate CycloneDX 1.4 SBOM from installed packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetSBOMCycloneDX()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// SBOM SPDX
	s.RegisterTool(Tool{
		Name:        "get_sbom_spdx",
		Description: "Generate SPDX 2.3 SBOM from installed packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetSBOMSPDX()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Vulnerability Lookup (OSV)
	s.RegisterTool(Tool{
		Name:        "get_vulnerabilities_osv",
		Description: "Query OSV API for vulnerabilities in installed packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetVulnerabilitiesOSV()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Vulnerability Lookup (Debian Security Tracker)
	s.RegisterTool(Tool{
		Name:        "get_vulnerabilities_debian",
		Description: "Query Debian Security Tracker for vulnerabilities in system packages (Debian/Ubuntu only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetVulnerabilitiesDebian()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Vulnerability Lookup (NVD)
	s.RegisterTool(Tool{
		Name:        "get_vulnerabilities_nvd",
		Description: "Query NVD (National Vulnerability Database) for vulnerabilities in installed packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetVulnerabilitiesNVD()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Docker Images
	s.RegisterTool(Tool{
		Name:        "get_docker_images",
		Description: "Get Docker/Podman container images",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := container.NewCollector()
		result, err := c.GetDockerImages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Docker Containers
	s.RegisterTool(Tool{
		Name:        "get_docker_containers",
		Description: "Get Docker/Podman containers (running and stopped)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := container.NewCollector()
		result, err := c.GetDockerContainers()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Docker Image History
	s.RegisterTool(Tool{
		Name:        "get_docker_image_history",
		Description: "Get layer history for a Docker/Podman image",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"image_id": {Type: "string", Description: "Image ID or name"},
			},
			Required: []string{"image_id"},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		imageID, _ := args["image_id"].(string)
		c := container.NewCollector()
		result, err := c.GetImageHistory(imageID)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Snap Packages (Linux)
	s.RegisterTool(Tool{
		Name:        "get_snap_packages",
		Description: "Get installed Snap packages (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetSnapPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Flatpak Packages (Linux)
	s.RegisterTool(Tool{
		Name:        "get_flatpak_packages",
		Description: "Get installed Flatpak packages (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetFlatpakPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Homebrew Casks (macOS)
	s.RegisterTool(Tool{
		Name:        "get_homebrew_casks",
		Description: "Get installed Homebrew Casks (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetHomebrewCasks()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Scoop Packages (Windows)
	s.RegisterTool(Tool{
		Name:        "get_scoop_packages",
		Description: "Get installed Scoop packages (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetScoopPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Windows Programs
	s.RegisterTool(Tool{
		Name:        "get_windows_programs",
		Description: "Get installed Windows programs from registry (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetWindowsPrograms()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Windows Features
	s.RegisterTool(Tool{
		Name:        "get_windows_features",
		Description: "Get Windows optional features (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetWindowsFeatures()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// NPM Lock file
	s.RegisterTool(Tool{
		Name:        "get_npm_lock",
		Description: "Parse package-lock.json for precise npm dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to package-lock.json (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetNpmLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Pip Lock file
	s.RegisterTool(Tool{
		Name:        "get_pip_lock",
		Description: "Parse requirements.txt or Pipfile.lock for Python dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to requirements.txt or Pipfile.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetPipLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Cargo Lock file
	s.RegisterTool(Tool{
		Name:        "get_cargo_lock",
		Description: "Parse Cargo.lock for Rust dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to Cargo.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetCargoLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Go Sum file
	s.RegisterTool(Tool{
		Name:        "get_go_sum",
		Description: "Parse go.sum for Go module versions and checksums",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to go.sum (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetGoSum(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Gemfile Lock file
	s.RegisterTool(Tool{
		Name:        "get_gemfile_lock",
		Description: "Parse Gemfile.lock for Ruby gem versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to Gemfile.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetGemfileLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Phase 1.8: Application Discovery
	s.RegisterTool(Tool{
		Name:        "get_applications",
		Description: "Discover installed and running applications (web servers, databases, message queues, etc.)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetApplications()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Phase 1.8: Application Configuration
	s.RegisterTool(Tool{
		Name:        "get_app_config",
		Description: "Read application config file with sensitive data redacted (passwords, API keys, tokens, etc.)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to the configuration file"},
			},
			Required: []string{"path"},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		configPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetAppConfig(configPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// ========================================================================
	// Phase 1.10: Extended Language Ecosystems
	// ========================================================================

	// Perl Packages
	s.RegisterTool(Tool{
		Name:        "get_perl_packages",
		Description: "Get installed Perl modules from CPAN/cpanm",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetPerlPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Lua Packages
	s.RegisterTool(Tool{
		Name:        "get_lua_packages",
		Description: "Get installed LuaRocks packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetLuaPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Haskell Packages
	s.RegisterTool(Tool{
		Name:        "get_haskell_packages",
		Description: "Get installed Haskell packages from Cabal/Stack",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetHaskellPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Swift Packages
	s.RegisterTool(Tool{
		Name:        "get_swift_packages",
		Description: "Get Swift Package Manager packages (macOS/Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetSwiftPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Elixir/Hex Packages
	s.RegisterTool(Tool{
		Name:        "get_elixir_packages",
		Description: "Get installed Hex packages for Elixir",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetElixirPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// R Packages
	s.RegisterTool(Tool{
		Name:        "get_r_packages",
		Description: "Get installed R packages from CRAN",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetRPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Julia Packages
	s.RegisterTool(Tool{
		Name:        "get_julia_packages",
		Description: "Get installed Julia packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetJuliaPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Dart/Flutter Packages
	s.RegisterTool(Tool{
		Name:        "get_dart_packages",
		Description: "Get Dart/Flutter pub cache packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetDartPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// OCaml Packages
	s.RegisterTool(Tool{
		Name:        "get_ocaml_packages",
		Description: "Get installed OPAM packages (macOS/Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetOCamlPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Conda Packages
	s.RegisterTool(Tool{
		Name:        "get_conda_packages",
		Description: "Get Conda environments and packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetCondaPackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Gradle Packages
	s.RegisterTool(Tool{
		Name:        "get_gradle_packages",
		Description: "Get Java/Gradle dependency cache packages",
		InputSchema: InputSchema{Type: "object"},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := software.NewCollector()
		result, err := c.GetGradlePackages()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// ========================================================================
	// Phase 1.10: Extended Lock File Parsers
	// ========================================================================

	// Yarn Lock
	s.RegisterTool(Tool{
		Name:        "get_yarn_lock",
		Description: "Parse yarn.lock for Yarn dependency versions (supports v1 and v2+ formats)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to yarn.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetYarnLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Pnpm Lock
	s.RegisterTool(Tool{
		Name:        "get_pnpm_lock",
		Description: "Parse pnpm-lock.yaml for pnpm dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to pnpm-lock.yaml (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetPnpmLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Poetry Lock
	s.RegisterTool(Tool{
		Name:        "get_poetry_lock",
		Description: "Parse poetry.lock for Python Poetry dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to poetry.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetPoetryLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Composer Lock (Extended)
	s.RegisterTool(Tool{
		Name:        "get_composer_lock",
		Description: "Parse composer.lock for PHP Composer dependency versions with integrity hashes",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to composer.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetComposerLockExtended(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Mix Lock (Elixir)
	s.RegisterTool(Tool{
		Name:        "get_mix_lock",
		Description: "Parse mix.lock for Elixir Hex dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to mix.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetMixLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Pubspec Lock (Dart/Flutter)
	s.RegisterTool(Tool{
		Name:        "get_pubspec_lock",
		Description: "Parse pubspec.lock for Dart/Flutter dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to pubspec.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetPubspecLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Swift Package.resolved
	s.RegisterTool(Tool{
		Name:        "get_swift_resolved",
		Description: "Parse Package.resolved for Swift Package Manager dependencies (macOS/Linux only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to Package.resolved (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetSwiftResolved(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Podfile Lock (CocoaPods)
	s.RegisterTool(Tool{
		Name:        "get_podfile_lock",
		Description: "Parse Podfile.lock for CocoaPods dependencies (macOS only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to Podfile.lock (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetPodfileLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Gradle Lockfile
	s.RegisterTool(Tool{
		Name:        "get_gradle_lock",
		Description: "Parse gradle.lockfile for Gradle dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to gradle.lockfile (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetGradleLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Conda Lock
	s.RegisterTool(Tool{
		Name:        "get_conda_lock",
		Description: "Parse conda-lock.yml for Conda dependency versions",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"path": {Type: "string", Description: "Path to conda-lock.yml (defaults to current directory)"},
			},
		},
	}, "software", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		lockPath, _ := args["path"].(string)
		c := software.NewCollector()
		result, err := c.GetCondaLock(lockPath)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerTriageTools(s *Server) {
	// OS Info
	s.RegisterTool(Tool{
		Name:        "get_os_info",
		Description: "Get OS version, build, kernel, and platform information",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := osinfo.NewCollector()
		result, err := c.GetOSInfo()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// System Profile
	s.RegisterTool(Tool{
		Name:        "get_system_profile",
		Description: "Get a summary of CPU, memory, disk, and network status",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := osinfo.NewCollector()
		result, err := c.GetSystemProfile()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Service Manager Info
	s.RegisterTool(Tool{
		Name:        "get_service_manager_info",
		Description: "Get service manager status (systemd, launchd, or Windows SCM)",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := osinfo.NewCollector()
		result, err := c.GetServiceManagerInfo()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Cloud Environment
	s.RegisterTool(Tool{
		Name:        "get_cloud_environment",
		Description: "Detect cloud provider and instance metadata (AWS, GCP, Azure)",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := osinfo.NewCollector()
		result, err := c.GetCloudEnvironment()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Language Runtime Versions
	s.RegisterTool(Tool{
		Name:        "get_language_runtime_versions",
		Description: "Get installed language runtime versions (Python, Node.js, Go, Ruby, Java, PHP, Rust, .NET)",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := runtimes.NewCollector()
		result, err := c.GetLanguageRuntimes()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Phase 1.9.2: Recent Events
	// Recent Reboots
	s.RegisterTool(Tool{
		Name:        "get_recent_reboots",
		Description: "Get recent system reboot events with timestamps and reasons. Note: May be slow on macOS (uses log show)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"limit": {
					Type:        "integer",
					Description: "Maximum number of events to return",
					Default:     10,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		limit := 10
		if l, ok := args["limit"].(float64); ok {
			limit = int(l)
		}
		c := triage.NewCollector()
		result, err := c.GetRecentReboots(limit)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Recent Service Failures
	s.RegisterTool(Tool{
		Name:        "get_recent_service_failures",
		Description: "Get recent service/daemon failures with error details. Note: May be slow on macOS (uses log show)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"limit": {
					Type:        "integer",
					Description: "Maximum number of failures to return",
					Default:     20,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		limit := 20
		if l, ok := args["limit"].(float64); ok {
			limit = int(l)
		}
		c := triage.NewCollector()
		result, err := c.GetRecentServiceFailures(limit)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Recent Kernel Events
	s.RegisterTool(Tool{
		Name:        "get_recent_kernel_events",
		Description: "Get recent kernel events (errors, warnings, panics). WARNING: High latency on macOS (1+ minutes, uses log show)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"limit": {
					Type:        "integer",
					Description: "Maximum number of events to return",
					Default:     50,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		limit := 50
		if l, ok := args["limit"].(float64); ok {
			limit = int(l)
		}
		c := triage.NewCollector()
		result, err := c.GetRecentKernelEvents(limit)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Recent Resource Incidents
	s.RegisterTool(Tool{
		Name:        "get_recent_resource_incidents",
		Description: "Get recent resource incidents (OOM, disk full, high CPU). Note: May be slow on macOS (uses log show)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"limit": {
					Type:        "integer",
					Description: "Maximum number of incidents to return",
					Default:     20,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		limit := 20
		if l, ok := args["limit"].(float64); ok {
			limit = int(l)
		}
		c := triage.NewCollector()
		result, err := c.GetRecentResourceIncidents(limit)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Recent Config Changes
	s.RegisterTool(Tool{
		Name:        "get_recent_config_changes",
		Description: "Get recent configuration file changes. Note: May be slow on macOS (uses log show)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"limit": {
					Type:        "integer",
					Description: "Maximum number of changes to return",
					Default:     50,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		limit := 50
		if l, ok := args["limit"].(float64); ok {
			limit = int(l)
		}
		c := triage.NewCollector()
		result, err := c.GetRecentConfigChanges(limit)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Recent Critical Events
	s.RegisterTool(Tool{
		Name:        "get_recent_critical_events",
		Description: "Get recent critical/emergency events across all logs. WARNING: High latency on macOS (1+ minutes, uses log show)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"limit": {
					Type:        "integer",
					Description: "Maximum number of events to return",
					Default:     30,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		limit := 30
		if l, ok := args["limit"].(float64); ok {
			limit = int(l)
		}
		c := triage.NewCollector()
		result, err := c.GetRecentCriticalEvents(limit)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Phase 1.9.3: Service & Scheduling
	// Failed Units
	s.RegisterTool(Tool{
		Name:        "get_failed_units",
		Description: "Get currently failed systemd units or equivalent services",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetFailedUnits()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Timer Jobs
	s.RegisterTool(Tool{
		Name:        "get_timer_jobs",
		Description: "Get systemd timers, cron jobs, and scheduled tasks",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetTimerJobs()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Service Log View
	s.RegisterTool(Tool{
		Name:        "get_service_log_view",
		Description: "Get recent logs for a specific service. Note: May be slow on macOS (uses log show)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"service": {
					Type:        "string",
					Description: "Service name to get logs for",
				},
				"lines": {
					Type:        "integer",
					Description: "Number of log lines to return",
					Default:     100,
				},
			},
			Required: []string{"service"},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		service, _ := args["service"].(string)
		lines := 100
		if l, ok := args["lines"].(float64); ok {
			lines = int(l)
		}
		c := triage.NewCollector()
		result, err := c.GetServiceLogView(service, lines)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Deployment Events
	s.RegisterTool(Tool{
		Name:        "get_deployment_events",
		Description: "Get recent deployment/update events (packages, containers)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"limit": {
					Type:        "integer",
					Description: "Maximum number of events to return",
					Default:     20,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		limit := 20
		if l, ok := args["limit"].(float64); ok {
			limit = int(l)
		}
		c := triage.NewCollector()
		result, err := c.GetDeploymentEvents(limit)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Phase 1.9.4: Security Summary
	// Auth Failure Summary
	s.RegisterTool(Tool{
		Name:        "get_auth_failure_summary",
		Description: "Get authentication failure summary with top IPs and users. Note: May be slow on macOS (uses log show)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"hours": {
					Type:        "integer",
					Description: "Hours to look back for failures",
					Default:     24,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		hours := 24
		if h, ok := args["hours"].(float64); ok {
			hours = int(h)
		}
		c := triage.NewCollector()
		result, err := c.GetAuthFailureSummary(hours)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Security Basics
	s.RegisterTool(Tool{
		Name:        "get_security_basics",
		Description: "Get basic security status (firewall, SELinux/AppArmor, updates)",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetSecurityBasics()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// SSH Security Summary
	s.RegisterTool(Tool{
		Name:        "get_ssh_security_summary",
		Description: "Get SSH security configuration summary",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetSSHSecuritySummary()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Admin Account Summary
	s.RegisterTool(Tool{
		Name:        "get_admin_account_summary",
		Description: "Get administrative/privileged account summary",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetAdminAccountSummary()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Exposed Services Summary
	s.RegisterTool(Tool{
		Name:        "get_exposed_services_summary",
		Description: "Get summary of exposed network services",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetExposedServicesSummary()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Resource Limits
	s.RegisterTool(Tool{
		Name:        "get_resource_limits",
		Description: "Get system resource limits (ulimits, kernel params)",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetResourceLimits()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Phase 1.9.5: Software & Runtime
	// Recently Installed Software
	s.RegisterTool(Tool{
		Name:        "get_recently_installed_software",
		Description: "Get recently installed packages and software",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"days": {
					Type:        "integer",
					Description: "Number of days to look back",
					Default:     7,
				},
			},
		},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		days := 7
		if d, ok := args["days"].(float64); ok {
			days = int(d)
		}
		c := triage.NewCollector()
		result, err := c.GetRecentlyInstalledSoftware(days)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Filesystem Health Summary
	s.RegisterTool(Tool{
		Name:        "get_fs_health_summary",
		Description: "Get filesystem health summary (usage, issues, read-only mounts)",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetFSHealthSummary()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Phase 1.9.6: Meta Queries
	// Incident Triage Snapshot
	s.RegisterTool(Tool{
		Name:        "get_incident_triage_snapshot",
		Description: "Get comprehensive incident triage snapshot (system info, recent events, failures). WARNING: High latency on macOS (may take 1-5 minutes due to log queries)",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetIncidentTriageSnapshot()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Security Posture Snapshot
	s.RegisterTool(Tool{
		Name:        "get_security_posture_snapshot",
		Description: "Get security posture snapshot with risk score and recommendations. WARNING: High latency on macOS (may take 1-5 minutes due to log queries)",
		InputSchema: InputSchema{Type: "object"},
	}, "triage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := triage.NewCollector()
		result, err := c.GetSecurityPostureSnapshot()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

// registerWindowsEnterpriseTools registers Phase 1.10 Windows Enterprise tools.
func registerWindowsEnterpriseTools(s *Server) {
	// ==========================================================================
	// Phase 1.10.1: Registry Queries
	// ==========================================================================

	// Get Registry Key
	s.RegisterTool(Tool{
		Name:        "get_registry_key",
		Description: "Read a Windows registry key and its values (Windows only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"hive": {
					Type:        "string",
					Description: "Registry hive (HKLM, HKCU, HKCR, HKU, HKCC)",
					Default:     "HKLM",
				},
				"path": {
					Type:        "string",
					Description: "Registry key path (e.g., SOFTWARE\\Microsoft\\Windows\\CurrentVersion)",
				},
			},
			Required: []string{"path"},
		},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		hive := "HKLM"
		if h, ok := args["hive"].(string); ok && h != "" {
			hive = h
		}
		path, _ := args["path"].(string)

		c := windows.NewCollector()
		result, err := c.GetRegistryKey(hive, path)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get Registry Tree
	s.RegisterTool(Tool{
		Name:        "get_registry_tree",
		Description: "Recursively enumerate a Windows registry key and its subkeys (Windows only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"hive": {
					Type:        "string",
					Description: "Registry hive (HKLM, HKCU, HKCR, HKU, HKCC)",
					Default:     "HKLM",
				},
				"path": {
					Type:        "string",
					Description: "Registry key path",
				},
				"max_depth": {
					Type:        "integer",
					Description: "Maximum depth to recurse (default 3)",
					Default:     3,
				},
			},
			Required: []string{"path"},
		},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		hive := "HKLM"
		if h, ok := args["hive"].(string); ok && h != "" {
			hive = h
		}
		path, _ := args["path"].(string)
		maxDepth := 3
		if d, ok := args["max_depth"].(float64); ok {
			maxDepth = int(d)
		}

		c := windows.NewCollector()
		result, err := c.GetRegistryTree(hive, path, maxDepth)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get Registry Security
	s.RegisterTool(Tool{
		Name:        "get_registry_security",
		Description: "Get security descriptor (owner, group, DACL) for a Windows registry key (Windows only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"hive": {
					Type:        "string",
					Description: "Registry hive (HKLM, HKCU, HKCR, HKU, HKCC)",
					Default:     "HKLM",
				},
				"path": {
					Type:        "string",
					Description: "Registry key path",
				},
			},
			Required: []string{"path"},
		},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		hive := "HKLM"
		if h, ok := args["hive"].(string); ok && h != "" {
			hive = h
		}
		path, _ := args["path"].(string)

		c := windows.NewCollector()
		result, err := c.GetRegistrySecurity(hive, path)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// ==========================================================================
	// Phase 1.10.2: DCOM/COM Security Queries
	// ==========================================================================

	// Get DCOM Applications
	s.RegisterTool(Tool{
		Name:        "get_dcom_applications",
		Description: "List all registered DCOM applications (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetDCOMApplications()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get DCOM Permissions
	s.RegisterTool(Tool{
		Name:        "get_dcom_permissions",
		Description: "Get launch and access permissions for a DCOM application (Windows only)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"appid": {
					Type:        "string",
					Description: "DCOM AppID GUID (e.g., {00000000-0000-0000-0000-000000000000})",
				},
			},
			Required: []string{"appid"},
		},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		appID, _ := args["appid"].(string)

		c := windows.NewCollector()
		result, err := c.GetDCOMPermissions(appID)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get DCOM Identities
	s.RegisterTool(Tool{
		Name:        "get_dcom_identities",
		Description: "List RunAs identities for all DCOM applications (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetDCOMIdentities()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get COM Security Defaults
	s.RegisterTool(Tool{
		Name:        "get_com_security_defaults",
		Description: "Get machine-wide COM/DCOM security settings (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetCOMSecurityDefaults()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// ==========================================================================
	// Phase 1.10.3: IIS Web Server Queries
	// ==========================================================================

	// Get IIS Sites
	s.RegisterTool(Tool{
		Name:        "get_iis_sites",
		Description: "List all IIS websites with bindings and configuration (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetIISSites()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get IIS App Pools
	s.RegisterTool(Tool{
		Name:        "get_iis_app_pools",
		Description: "List all IIS application pools with configuration (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetIISAppPools()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get IIS Bindings
	s.RegisterTool(Tool{
		Name:        "get_iis_bindings",
		Description: "List all site bindings across all IIS sites (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetIISBindings()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get IIS Virtual Directories
	s.RegisterTool(Tool{
		Name:        "get_iis_virtual_dirs",
		Description: "List all virtual directories across all IIS sites (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetIISVirtualDirs()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get IIS Handlers
	s.RegisterTool(Tool{
		Name:        "get_iis_handlers",
		Description: "List all handler mappings configured in IIS (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetIISHandlers()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get IIS Modules
	s.RegisterTool(Tool{
		Name:        "get_iis_modules",
		Description: "List all modules (native and managed) installed in IIS (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetIISModules()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get IIS SSL Certs
	s.RegisterTool(Tool{
		Name:        "get_iis_ssl_certs",
		Description: "List all SSL certificate bindings in IIS (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetIISSSLCerts()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get IIS Auth Config
	s.RegisterTool(Tool{
		Name:        "get_iis_auth_config",
		Description: "Get authentication configuration for all IIS sites (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "windows", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := windows.NewCollector()
		result, err := c.GetIISAuthConfig()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

// registerEnhancedDiagnosticsTools registers Phase 2 Enhanced Diagnostics tools.
func registerEnhancedDiagnosticsTools(s *Server) {
	// ==========================================================================
	// Phase 2.1: GPU Diagnostics
	// ==========================================================================

	// Get GPU Info
	s.RegisterTool(Tool{
		Name:        "get_gpu_info",
		Description: "Get GPU information including memory, utilization, temperature, and processes",
		InputSchema: InputSchema{Type: "object"},
	}, "enhanced", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := gpu.NewCollector()
		result, err := c.GetGPUInfo()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// ==========================================================================
	// Phase 2.2: Container Metrics
	// ==========================================================================

	// Get Container Stats
	s.RegisterTool(Tool{
		Name:        "get_container_stats",
		Description: "Get real-time CPU, memory, network, and I/O stats for Docker/Podman containers",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"container_id": {
					Type:        "string",
					Description: "Container ID or name (optional, returns all running containers if not specified)",
				},
			},
		},
	}, "enhanced", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		containerID, _ := args["container_id"].(string)
		c := container.NewCollector()
		result, err := c.GetContainerStats(containerID)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get Container Logs
	s.RegisterTool(Tool{
		Name:        "get_container_logs",
		Description: "Get logs from a Docker/Podman container",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"container_id": {
					Type:        "string",
					Description: "Container ID or name",
				},
				"lines": {
					Type:        "integer",
					Description: "Number of lines to return (default 100)",
					Default:     100,
				},
				"since": {
					Type:        "string",
					Description: "Return logs since this timestamp (RFC3339 or Unix timestamp)",
				},
			},
			Required: []string{"container_id"},
		},
	}, "enhanced", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		containerID, _ := args["container_id"].(string)
		lines := 100
		if l, ok := args["lines"].(float64); ok {
			lines = int(l)
		}
		since, _ := args["since"].(string)

		c := container.NewCollector()
		result, err := c.GetContainerLogs(containerID, lines, since)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

// registerReportTools registers Phase 2.3 System Report tools.
func registerReportTools(s *Server) {
	// ==========================================================================
	// Phase 2.3: System Reports with Parallel Collection
	// ==========================================================================

	// Generate System Report
	s.RegisterTool(Tool{
		Name:        "generate_system_report",
		Description: "Generate a comprehensive system report with all data collected in parallel. Returns JSON suitable for binding to HTML templates.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"sections": {
					Type:        "array",
					Description: "Specific sections to include (default: all). Options: os, hardware, uptime, cpu, memory, gpu, processes, disks, network, listening_ports, dns, routes, arp, startup_items, programs, runtimes",
				},
				"timeout_seconds": {
					Type:        "integer",
					Description: "Maximum time to wait for all collectors (default: 30)",
					Default:     30,
				},
			},
		},
	}, "report", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		timeout := 30 * time.Second
		if t, ok := args["timeout_seconds"].(float64); ok && t > 0 {
			timeout = time.Duration(t) * time.Second
		}

		var sections []string
		if s, ok := args["sections"].([]interface{}); ok {
			for _, v := range s {
				if str, ok := v.(string); ok {
					sections = append(sections, str)
				}
			}
		}

		rg := report.NewReportGenerator(timeout)
		result, err := rg.GenerateSystemReport(ctx, sections)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Generate IIS Report (Windows only)
	s.RegisterTool(Tool{
		Name:        "generate_iis_report",
		Description: "Generate a comprehensive IIS web server report with all data collected in parallel. Returns JSON suitable for binding to HTML templates. Windows only.",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"sections": {
					Type:        "array",
					Description: "Specific sections to include (default: all). Options: sites, app_pools, bindings, virtual_dirs, handlers, modules, ssl_certs, auth_config",
				},
				"timeout_seconds": {
					Type:        "integer",
					Description: "Maximum time to wait for all collectors (default: 30)",
					Default:     30,
				},
			},
		},
	}, "report", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		timeout := 30 * time.Second
		if t, ok := args["timeout_seconds"].(float64); ok && t > 0 {
			timeout = time.Duration(t) * time.Second
		}

		var sections []string
		if s, ok := args["sections"].([]interface{}); ok {
			for _, v := range s {
				if str, ok := v.(string); ok {
					sections = append(sections, str)
				}
			}
		}

		rg := report.NewIISReportGenerator(timeout)
		result, err := rg.GenerateIISReport(ctx, sections)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

// registerStorageTools registers Phase 3 Storage Deep Dive tools.
func registerStorageTools(s *Server) {
	// ==========================================================================
	// Phase 3: Storage Deep Dive
	// ==========================================================================

	// Get SMART Health
	s.RegisterTool(Tool{
		Name:        "get_smart_health",
		Description: "Get SMART disk health information including temperature, power-on hours, and health status. Requires smartctl or platform-specific APIs",
		InputSchema: InputSchema{Type: "object"},
	}, "storage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := storage.NewCollector()
		result, err := c.GetSMARTHealth()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get I/O Latency
	s.RegisterTool(Tool{
		Name:        "get_io_latency",
		Description: "Get disk I/O latency statistics including read/write latency, IOPS, and queue depth",
		InputSchema: InputSchema{Type: "object"},
	}, "storage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := storage.NewCollector()
		result, err := c.GetIOLatency()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get Volume Status
	s.RegisterTool(Tool{
		Name:        "get_volume_status",
		Description: "Get volume manager status including ZFS pools, LVM groups, MD RAID arrays, and Windows Storage Spaces",
		InputSchema: InputSchema{Type: "object"},
	}, "storage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := storage.NewCollector()
		result, err := c.GetVolumeStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get Mount Changes
	s.RegisterTool(Tool{
		Name:        "get_mount_changes",
		Description: "Get current mount points and filesystem information",
		InputSchema: InputSchema{Type: "object"},
	}, "storage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := storage.NewCollector()
		result, err := c.GetMountChanges()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Get FS Events
	s.RegisterTool(Tool{
		Name:        "get_fs_events",
		Description: "Get filesystem event monitoring capabilities and information for the platform",
		InputSchema: InputSchema{Type: "object"},
	}, "storage", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := storage.NewCollector()
		result, err := c.GetFSEvents()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

// registerPlatformSecurityTools registers Phase 1.9 Platform Security Controls tools.
func registerPlatformSecurityTools(s *Server) {
	// ==========================================================================
	// Phase 1.9: Platform Security Controls
	// ==========================================================================

	// Windows Security Controls (12 queries)

	s.RegisterTool(Tool{
		Name:        "get_windows_defender_status",
		Description: "Get Windows Defender status including real-time protection, signatures, tamper protection, and scan ages (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsDefenderStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_firewall_profiles",
		Description: "Get Windows Firewall profile states for Domain, Private, and Public profiles (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsFirewallProfiles()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_bitlocker_status",
		Description: "Get BitLocker encryption status per volume including protection status, encryption method, and key protectors (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetBitLockerStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_smb_shares",
		Description: "Get SMB shares and permissions summary (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsSMBShares()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_rdp_config",
		Description: "Get RDP configuration including enabled status, NLA, port, and security settings (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsRDPConfig()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_winrm_config",
		Description: "Get WinRM listener and authentication configuration (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsWinRMConfig()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_applocker_policy",
		Description: "Get AppLocker enforcement mode and rule collections (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsAppLockerPolicy()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_wdac_status",
		Description: "Get WDAC/Code Integrity policy state including UMCI, KMCI, and HVCI status (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsWDACStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_local_security_policy",
		Description: "Get local security policy summary including password policy, lockout policy, and audit settings (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsLocalSecurityPolicy()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_gpo_applied",
		Description: "Get applied Group Policy Objects for computer scope (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsGPOApplied()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_credential_guard",
		Description: "Get Credential Guard and LSA protection status (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsCredentialGuard()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_windows_update_health",
		Description: "Get Windows Update health including pending updates, reboot required, and update source (Windows only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetWindowsUpdateHealth()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// macOS Security Controls (8 queries)

	s.RegisterTool(Tool{
		Name:        "get_macos_filevault_status",
		Description: "Get FileVault disk encryption status (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMacOSFileVaultStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_macos_gatekeeper_status",
		Description: "Get Gatekeeper and notarization status (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMacOSGatekeeperStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_macos_sip_status",
		Description: "Get System Integrity Protection (SIP) status (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMacOSSIPStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_macos_xprotect_status",
		Description: "Get XProtect/MRT version and status (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMacOSXProtectStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_macos_pf_rules",
		Description: "Get Packet Filter (pf) status and rules summary (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMacOSPFRules()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_macos_mdm_profiles",
		Description: "Get installed MDM configuration profiles (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMacOSMDMProfiles()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_macos_tcc_permissions",
		Description: "Get TCC (Transparency, Consent, and Control) permissions summary (macOS only, sensitive)",
		InputSchema: InputSchema{Type: "object"},
	}, "sensitive", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMacOSTCCPermissions()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_macos_security_log_events",
		Description: "Get unified log security events (macOS only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetMacOSSecurityLogEvents()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Linux Security Controls (7 queries)

	s.RegisterTool(Tool{
		Name:        "get_linux_auditd_status",
		Description: "Get auditd status and rule summary (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetLinuxAuditdStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_linux_kernel_lockdown",
		Description: "Get kernel lockdown mode and Secure Boot status (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetLinuxKernelLockdown()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_linux_sysctl_security",
		Description: "Get key sysctl hardening values with security score (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetLinuxSysctlSecurity()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_linux_firewall_backend",
		Description: "Get active firewall backend (nftables/iptables/firewalld/ufw) (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetLinuxFirewallBackend()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_linux_mac_detailed",
		Description: "Get detailed SELinux or AppArmor status including profiles and enforcement mode (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetLinuxMACDetailed()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_linux_package_repos",
		Description: "Get package repository summary (apt/dnf/yum/zypper/pacman) (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetLinuxPackageRepos()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_linux_auto_updates",
		Description: "Get unattended upgrades/automatic update status (Linux only)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetLinuxAutoUpdates()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Cross-Platform (1 query)

	s.RegisterTool(Tool{
		Name:        "get_vendor_services",
		Description: "Get OS vendor services inventory (Microsoft/Apple/Linux distro services)",
		InputSchema: InputSchema{Type: "object"},
	}, "security", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := security.NewCollector()
		result, err := c.GetVendorServices()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerNetworkIntelligenceTools(s *Server) {
	// ==========================================================================
	// Phase 4: Network Intelligence (5 queries)
	// ==========================================================================

	s.RegisterTool(Tool{
		Name:        "get_connection_tracking",
		Description: "Get network connection tracking information including established, listening, and time-wait connections",
		InputSchema: InputSchema{Type: "object"},
	}, "network", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetConnectionTracking()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_dns_stats",
		Description: "Get DNS resolver statistics including configured servers, cache status, and resolution status",
		InputSchema: InputSchema{Type: "object"},
	}, "network", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetDNSStats()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_firewall_deep",
		Description: "Get detailed firewall configuration including rules, chains, and policy information",
		InputSchema: InputSchema{Type: "object"},
	}, "network", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetFirewallDeep()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_wifi_metrics",
		Description: "Get WiFi interface metrics including signal strength, noise, link quality, and connection details",
		InputSchema: InputSchema{Type: "object"},
	}, "network", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := netconfig.NewCollector()
		result, err := c.GetWiFiMetrics()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_network_latency",
		Description: "Measure network latency to specified targets using ICMP ping",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"targets": {
					Type:        "array",
					Description: "List of target hosts/IPs to ping (default: 8.8.8.8, 1.1.1.1)",
				},
			},
		},
	}, "network", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		var targets []string
		if t, ok := args["targets"].([]interface{}); ok {
			for _, v := range t {
				if s, ok := v.(string); ok {
					targets = append(targets, s)
				}
			}
		}
		c := netconfig.NewCollector()
		result, err := c.GetNetworkLatency(targets)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerAnalyticsTools(s *Server) {
	// ==========================================================================
	// Phase 5: Analytics & Trends (4 queries)
	// ==========================================================================

	s.RegisterTool(Tool{
		Name:        "get_historical_metrics",
		Description: "Get historical system metrics for CPU, memory, and disk usage over a specified period",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"period": {
					Type:        "string",
					Description: "Time period for historical data: 1h, 24h, or 7d (default: 1h)",
					Default:     "1h",
				},
			},
		},
	}, "analytics", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		period, _ := args["period"].(string)
		if period == "" {
			period = "1h"
		}
		c := analytics.NewCollector()
		result, err := c.GetHistoricalMetrics(period)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_anomaly_detection",
		Description: "Detect anomalies in current system metrics by comparing against thresholds",
		InputSchema: InputSchema{Type: "object"},
	}, "analytics", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := analytics.NewCollector()
		result, err := c.GetAnomalyDetection()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_capacity_forecast",
		Description: "Get capacity forecasts for disk and memory resources with estimated time to exhaustion",
		InputSchema: InputSchema{Type: "object"},
	}, "analytics", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := analytics.NewCollector()
		result, err := c.GetCapacityForecast()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_trend_analysis",
		Description: "Analyze performance trends for CPU, memory, and disk I/O",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"period": {
					Type:        "string",
					Description: "Time period for trend analysis: 1h, 24h, or 7d (default: 1h)",
					Default:     "1h",
				},
			},
		},
	}, "analytics", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		period, _ := args["period"].(string)
		if period == "" {
			period = "1h"
		}
		c := analytics.NewCollector()
		result, err := c.GetTrendAnalysis(period)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerAlertingTools(s *Server) {
	// ==========================================================================
	// Phase 6: Automation & Alerting (3 read-only queries)
	// ==========================================================================

	s.RegisterTool(Tool{
		Name:        "get_alert_status",
		Description: "Get current system alert status including CPU, memory, disk, and network alerts",
		InputSchema: InputSchema{Type: "object"},
	}, "alerts", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := alerts.NewCollector()
		result, err := c.GetAlertStatus()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_remediation_suggestions",
		Description: "Get remediation suggestions based on current system issues and alerts",
		InputSchema: InputSchema{Type: "object"},
	}, "alerts", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := alerts.NewCollector()
		result, err := c.GetRemediationSuggestions()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_runbook_recommendations",
		Description: "Get runbook recommendations based on current system state and active issues",
		InputSchema: InputSchema{Type: "object"},
	}, "alerts", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := alerts.NewCollector()
		result, err := c.GetRunbookRecommendations()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

func registerComplianceTools(s *Server) {
	// ==========================================================================
	// Phase 7: Security & Compliance (5 queries)
	// ==========================================================================

	s.RegisterTool(Tool{
		Name:        "get_security_scan",
		Description: "Perform a security vulnerability scan checking for common misconfigurations and vulnerabilities",
		InputSchema: InputSchema{Type: "object"},
	}, "compliance", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := compliance.NewCollector()
		result, err := c.GetSecurityScan()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_compliance_check",
		Description: "Perform compliance checks against security frameworks (CIS, PCI-DSS, HIPAA, STIG)",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"framework": {
					Type:        "string",
					Description: "Compliance framework to check against: cis, pci, hipaa, stig (default: basic)",
					Default:     "basic",
				},
			},
		},
	}, "compliance", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		framework, _ := args["framework"].(string)
		if framework == "" {
			framework = "basic"
		}
		c := compliance.NewCollector()
		result, err := c.GetComplianceCheck(framework)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_forensic_snapshot",
		Description: "Collect a forensic snapshot including running processes, network connections, loaded modules, and user sessions",
		InputSchema: InputSchema{Type: "object"},
	}, "compliance", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := compliance.NewCollector()
		result, err := c.GetForensicSnapshot()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_audit_trail",
		Description: "Retrieve security audit events including authentication, privilege escalation, and service events",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]Property{
				"hours": {
					Type:        "integer",
					Description: "Number of hours of audit history to retrieve (default: 24)",
					Default:     24,
				},
			},
		},
	}, "compliance", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		hours := 24
		if h, ok := args["hours"].(float64); ok {
			hours = int(h)
		}
		c := compliance.NewCollector()
		result, err := c.GetAuditTrail(hours)
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	s.RegisterTool(Tool{
		Name:        "get_hardening_recommendations",
		Description: "Get security hardening recommendations based on current system configuration",
		InputSchema: InputSchema{Type: "object"},
	}, "compliance", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := compliance.NewCollector()
		result, err := c.GetHardeningRecommendations()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}

// Phase 1.9: Consumer Diagnostics - Common end-user hardware issues
func registerConsumerDiagnosticsTools(s *Server) {
	// Bluetooth Devices
	s.RegisterTool(Tool{
		Name:        "get_bluetooth_devices",
		Description: "Get Bluetooth devices and adapter status (Windows only, stubs on other platforms)",
		InputSchema: InputSchema{Type: "object"},
	}, "consumer", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := consumer.NewCollector()
		result, err := c.GetBluetoothDevices()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Audio Devices
	s.RegisterTool(Tool{
		Name:        "get_audio_devices",
		Description: "Get audio playback and recording devices (Windows only, stubs on other platforms)",
		InputSchema: InputSchema{Type: "object"},
	}, "consumer", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := consumer.NewCollector()
		result, err := c.GetAudioDevices()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Printers
	s.RegisterTool(Tool{
		Name:        "get_printers",
		Description: "Get printer information and spooler status (Windows only, stubs on other platforms)",
		InputSchema: InputSchema{Type: "object"},
	}, "consumer", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := consumer.NewCollector()
		result, err := c.GetPrinters()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})

	// Display Configuration
	s.RegisterTool(Tool{
		Name:        "get_display_config",
		Description: "Get display/monitor configuration and video adapters (Windows only, stubs on other platforms)",
		InputSchema: InputSchema{Type: "object"},
	}, "consumer", func(ctx context.Context, args map[string]interface{}) (*CallToolResult, error) {
		c := consumer.NewCollector()
		result, err := c.GetDisplayConfig()
		if err != nil {
			return nil, err
		}
		return &CallToolResult{Content: []Content{NewJSONContent(result)}}, nil
	})
}
