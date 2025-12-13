package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/levantar-ai/mcp-sysinfo/internal/cpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
	"github.com/levantar-ai/mcp-sysinfo/internal/filesystem"
	"github.com/levantar-ai/mcp-sysinfo/internal/kernel"
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

// Version info - set via ldflags
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// CLI flags
	showVersion := flag.Bool("version", false, "Show version information")
	showHelp := flag.Bool("help", false, "Show help information")
	query := flag.String("query", "", "Run a specific query (e.g., get_cpu_info)")
	jsonOutput := flag.Bool("json", false, "Output in JSON format")

	flag.Usage = printHelp
	flag.Parse()

	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	if *showVersion {
		printVersion()
		os.Exit(0)
	}

	if *query != "" {
		runQuery(*query, *jsonOutput)
		os.Exit(0)
	}

	// Default: show info and available queries
	printBanner()
	fmt.Println("\nUse --help for available commands and queries.")
	fmt.Println("Use --query <name> to run a specific query.")
}

func printBanner() {
	fmt.Println("MCP System Info Server")
	fmt.Println("======================")
	fmt.Printf("Version:  %s\n", version)
	fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Go:       %s\n", runtime.Version())
}

func printVersion() {
	fmt.Printf("mcp-sysinfo %s\n", version)
	fmt.Printf("  commit: %s\n", commit)
	fmt.Printf("  built:  %s\n", date)
	fmt.Printf("  go:     %s\n", runtime.Version())
	fmt.Printf("  os:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func printHelp() {
	fmt.Print(`MCP System Info Server - Read-only AI diagnostics plane

USAGE:
    mcp-sysinfo [OPTIONS]
    mcp-sysinfo --query <QUERY_NAME> [--json]

OPTIONS:
    --help              Show this help message
    --version           Show version information
    --query <name>      Run a specific query
    --json              Output results in JSON format

AVAILABLE QUERIES:

  Phase 1 - Core Metrics (7 queries):
    get_cpu_info        CPU usage, frequency, load average, core count
    get_memory_info     Total, used, available memory and swap
    get_disk_info       Partitions, usage, filesystem types
    get_network_info    Interfaces, I/O counters, connections
    get_processes       Process list, top by CPU/memory
    get_uptime          Boot time, uptime duration
    get_temperature     Hardware temperature sensors

  Phase 1.5 - Log Access (6 queries):
    get_journal_logs    Systemd journal (Linux)
    get_syslog          Traditional syslog (Linux/macOS)
    get_kernel_logs     Kernel/dmesg logs
    get_auth_logs       Authentication logs (sensitive)
    get_app_logs        Application-specific logs
    get_event_log       Windows Event Log

  Phase 1.6 - System Hooks (16 queries - partial):
    get_scheduled_tasks  Windows Task Scheduler / at jobs / launchd
    get_cron_jobs        Cron entries (Linux/macOS)
    get_startup_items    Startup programs and services
    get_systemd_services Systemd service status (Linux)
    get_kernel_modules   Loaded kernel modules
    get_loaded_drivers   Device drivers
    get_dns_servers      Configured DNS servers
    get_routes           Routing table
    get_firewall_rules   Firewall rules
    get_listening_ports  Listening network ports
    get_arp_table        ARP table entries
    get_network_stats    Network stack statistics
    get_mounts           Mounted filesystems
    get_disk_io          Disk I/O statistics
    get_open_files       Open file descriptors
    get_inode_usage      Inode usage (Linux/macOS)

EXAMPLES:
    # Show CPU information
    mcp-sysinfo --query get_cpu_info

    # Get memory info as JSON
    mcp-sysinfo --query get_memory_info --json

    # List running processes
    mcp-sysinfo --query get_processes

    # View recent system logs
    mcp-sysinfo --query get_syslog

SECURITY:
    This tool provides READ-ONLY access to system information.
    No shell execution, no arbitrary commands.
    See SECURITY.md for the complete security model.

For more information: https://github.com/levantar-ai/mcp-sysinfo
`)
}

func runQuery(queryName string, jsonOut bool) {
	var result interface{}
	var err error

	switch queryName {
	case "get_cpu_info":
		c := cpu.NewCollector()
		result, err = c.Collect(false)

	case "get_memory_info":
		c := memory.NewCollector()
		result, err = c.Collect()

	case "get_disk_info":
		c := disk.NewCollector()
		result, err = c.Collect()

	case "get_network_info":
		c := network.NewCollector()
		result, err = c.Collect()

	case "get_processes":
		c := process.NewCollector()
		result, err = c.GetTopProcesses(10, "cpu") // Top 10 by CPU

	case "get_uptime":
		c := uptime.NewCollector()
		result, err = c.Collect()

	case "get_temperature":
		c := temperature.NewCollector()
		result, err = c.Collect()

	case "get_journal_logs":
		c := logs.NewCollector()
		result, err = c.GetJournalLogs(&types.LogQuery{Lines: 50})

	case "get_syslog":
		c := logs.NewCollector()
		result, err = c.GetSyslog(&types.LogQuery{Lines: 50})

	case "get_kernel_logs":
		c := logs.NewCollector()
		result, err = c.GetKernelLogs(&types.LogQuery{Lines: 50})

	case "get_auth_logs":
		c := logs.NewCollector()
		result, err = c.GetAuthLogs(&types.LogQuery{Lines: 50})

	case "get_app_logs":
		c := logs.NewCollector()
		result, err = c.GetAppLogs(&types.AppLogQuery{LogQuery: types.LogQuery{Lines: 50}})

	case "get_event_log":
		c := logs.NewCollector()
		result, err = c.GetEventLog(&types.EventLogQuery{LogQuery: types.LogQuery{Lines: 50}})

	case "get_scheduled_tasks":
		c := scheduled.NewCollector()
		result, err = c.GetScheduledTasks()

	case "get_cron_jobs":
		c := scheduled.NewCollector()
		result, err = c.GetCronJobs()

	case "get_startup_items":
		c := scheduled.NewCollector()
		result, err = c.GetStartupItems()

	case "get_systemd_services":
		c := scheduled.NewCollector()
		result, err = c.GetSystemdServices()

	case "get_kernel_modules":
		c := kernel.NewCollector()
		result, err = c.GetKernelModules()

	case "get_loaded_drivers":
		c := kernel.NewCollector()
		result, err = c.GetLoadedDrivers()

	case "get_dns_servers":
		c := netconfig.NewCollector()
		result, err = c.GetDNSServers()

	case "get_routes":
		c := netconfig.NewCollector()
		result, err = c.GetRoutes()

	case "get_firewall_rules":
		c := netconfig.NewCollector()
		result, err = c.GetFirewallRules()

	case "get_listening_ports":
		c := netconfig.NewCollector()
		result, err = c.GetListeningPorts()

	case "get_arp_table":
		c := netconfig.NewCollector()
		result, err = c.GetARPTable()

	case "get_network_stats":
		c := netconfig.NewCollector()
		result, err = c.GetNetworkStats()

	case "get_mounts":
		c := filesystem.NewCollector()
		result, err = c.GetMounts()

	case "get_disk_io":
		c := filesystem.NewCollector()
		result, err = c.GetDiskIO()

	case "get_open_files":
		c := filesystem.NewCollector()
		result, err = c.GetOpenFiles()

	case "get_inode_usage":
		c := filesystem.NewCollector()
		result, err = c.GetInodeUsage()

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown query '%s'\n", queryName)
		fmt.Fprintln(os.Stderr, "Use --help to see available queries.")
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		printResult(queryName, result)
	}
}

func printResult(queryName string, result interface{}) {
	fmt.Printf("=== %s ===\n\n", queryName)

	// Pretty print based on type
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}
