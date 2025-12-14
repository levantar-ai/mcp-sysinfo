package mcp

import (
	"context"

	"github.com/levantar-ai/mcp-sysinfo/internal/cpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
	"github.com/levantar-ai/mcp-sysinfo/internal/filesystem"
	"github.com/levantar-ai/mcp-sysinfo/internal/hardware"
	"github.com/levantar-ai/mcp-sysinfo/internal/kernel"
	"github.com/levantar-ai/mcp-sysinfo/internal/resources"
	"github.com/levantar-ai/mcp-sysinfo/internal/state"
	"github.com/levantar-ai/mcp-sysinfo/internal/logs"
	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
	"github.com/levantar-ai/mcp-sysinfo/internal/netconfig"
	"github.com/levantar-ai/mcp-sysinfo/internal/network"
	"github.com/levantar-ai/mcp-sysinfo/internal/process"
	"github.com/levantar-ai/mcp-sysinfo/internal/scheduled"
	"github.com/levantar-ai/mcp-sysinfo/internal/temperature"
	"github.com/levantar-ai/mcp-sysinfo/internal/uptime"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// RegisterAllTools registers all system info tools with the MCP server.
func RegisterAllTools(s *Server) {
	// Phase 1: Core Metrics (scope: core)
	registerCoreTools(s)

	// Phase 1.5: Log Access (scope: logs)
	registerLogTools(s)

	// Phase 1.6: System Hooks (scope: hooks)
	registerHookTools(s)

	// Phase 1.6.6: Hardware Information (scope: hardware)
	registerHardwareTools(s)

	// Phase 1.6.7: Process & Resources (scope: resources)
	registerResourceTools(s)

	// Phase 1.6.8: System State (scope: state)
	registerStateTools(s)
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
