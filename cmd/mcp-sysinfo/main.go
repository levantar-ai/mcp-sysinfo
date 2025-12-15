package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/audit"
	"github.com/levantar-ai/mcp-sysinfo/internal/cpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
	"github.com/levantar-ai/mcp-sysinfo/internal/filesystem"
	"github.com/levantar-ai/mcp-sysinfo/internal/hardware"
	"github.com/levantar-ai/mcp-sysinfo/internal/kernel"
	"github.com/levantar-ai/mcp-sysinfo/internal/logs"
	"github.com/levantar-ai/mcp-sysinfo/internal/mcp"
	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
	"github.com/levantar-ai/mcp-sysinfo/internal/netconfig"
	"github.com/levantar-ai/mcp-sysinfo/internal/network"
	"github.com/levantar-ai/mcp-sysinfo/internal/process"
	"github.com/levantar-ai/mcp-sysinfo/internal/redact"
	"github.com/levantar-ai/mcp-sysinfo/internal/resources"
	"github.com/levantar-ai/mcp-sysinfo/internal/scheduled"
	"github.com/levantar-ai/mcp-sysinfo/internal/security"
	"github.com/levantar-ai/mcp-sysinfo/internal/software"
	"github.com/levantar-ai/mcp-sysinfo/internal/state"
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
	query := flag.String("query", "", "Run a specific query directly (bypasses MCP)")
	jsonOutput := flag.Bool("json", false, "Output in JSON format (for --query)")
	pid := flag.Int("pid", 0, "Process ID for queries that need it (e.g., get_capabilities)")

	// Transport flags
	transport := flag.String("transport", "stdio", "Transport: stdio (default), http")
	listenAddr := flag.String("listen", "127.0.0.1:8080", "Listen address for HTTP transport")
	serverURL := flag.String("server-url", "", "Public server URL (for OAuth metadata)")

	// OAuth flags (for HTTP transport with token introspection)
	authServer := flag.String("auth-server", "", "OAuth authorization server URL (for token introspection)")
	clientID := flag.String("client-id", "", "OAuth client ID for token introspection")
	clientSecret := flag.String("client-secret", "", "OAuth client secret")

	// OIDC flags (for HTTP transport with local JWT validation)
	oidcIssuer := flag.String("oidc-issuer", "", "OIDC issuer URL (e.g., https://enterprise.okta.com)")
	oidcAudience := flag.String("oidc-audience", "", "Expected audience claim (typically this server's client ID)")

	// TLS flags
	tlsCert := flag.String("tls-cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS key file")

	// Redaction flags
	enableRedaction := flag.Bool("redact", false, "Enable output redaction of sensitive data")
	redactProvider := flag.String("redact-provider", "default", "Redaction provider: default, gitguardian")

	// Audit flags
	enableAudit := flag.Bool("audit", false, "Enable audit logging")
	auditOutput := flag.String("audit-output", "/var/log/mcp-sysinfo/audit.jsonl", "Audit log file path")
	auditBufferSize := flag.Int("audit-buffer-size", 100, "Audit buffer size (0 for synchronous writes)")
	auditFlushInterval := flag.Duration("audit-flush-interval", 5*time.Second, "Audit flush interval")
	auditMaxFileSize := flag.Int64("audit-max-file-size", 100*1024*1024, "Max audit file size before rotation (bytes)")
	auditMaxFiles := flag.Int("audit-max-files", 10, "Max number of rotated audit files to keep")
	auditSyncWrite := flag.Bool("audit-sync-write", false, "Force synchronous writes (fsync after each write)")
	auditVerify := flag.Bool("audit-verify", false, "Verify audit log integrity and exit")

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

	// Configure redaction if enabled
	if *enableRedaction {
		redact.Enable(*redactProvider)
	}

	// Configure audit if enabled or verifying
	if *enableAudit || *auditVerify {
		cfg := audit.Config{
			Enabled:       true,
			ProviderName:  "default",
			Output:        *auditOutput,
			BufferSize:    *auditBufferSize,
			FlushInterval: *auditFlushInterval,
			MaxFileSize:   *auditMaxFileSize,
			MaxFiles:      *auditMaxFiles,
			IncludeHash:   true, // Always enable hash chain for tamper evidence
			SyncWrite:     *auditSyncWrite,
		}

		if err := audit.Configure(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Error configuring audit: %v\n", err)
			os.Exit(1)
		}

		// Handle audit verify mode
		if *auditVerify {
			count, err := audit.Verify()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Audit verification FAILED: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Audit verification OK: %d events verified\n", count)
			os.Exit(0)
		}

		// Ensure audit is flushed on exit
		defer func() {
			if err := audit.Close(); err != nil {
				log.Printf("Warning: error closing audit: %v", err)
			}
		}()

		log.Printf("Audit logging enabled: %s", *auditOutput)
	}

	// Direct query mode (for testing/debugging)
	if *query != "" {
		pidVal := int32(0)
		if *pid > 0 {
			pidVal = int32(*pid) // #nosec G115 -- checked for positive
		}
		runQuery(*query, *jsonOutput, pidVal)
		os.Exit(0)
	}

	// Create MCP server
	mcpServer := mcp.NewServer("mcp-sysinfo", version)
	mcp.RegisterAllTools(mcpServer)

	// Set up context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	// Run server based on transport
	switch *transport {
	case "stdio":
		// Standard MCP transport - JSON-RPC over stdin/stdout
		if err := mcpServer.ServeStdio(ctx); err != nil && err != context.Canceled {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "http":
		// HTTP transport with optional OAuth
		httpConfig := &mcp.HTTPConfig{
			ListenAddr: *listenAddr,
			ServerURL:  *serverURL,
			TLSCert:    *tlsCert,
			TLSKey:     *tlsKey,
		}

		if httpConfig.ServerURL == "" {
			// Default server URL based on listen address
			scheme := "http"
			if *tlsCert != "" {
				scheme = "https"
			}
			httpConfig.ServerURL = fmt.Sprintf("%s://%s", scheme, *listenAddr)
		}

		// Configure authentication - OIDC takes precedence over OAuth introspection
		if *oidcIssuer != "" {
			if *oidcAudience == "" {
				fmt.Fprintln(os.Stderr, "Error: --oidc-audience required with --oidc-issuer")
				os.Exit(1)
			}

			httpConfig.OIDC = &mcp.OIDCConfig{
				Issuer:         *oidcIssuer,
				Audience:       *oidcAudience,
				RequiredScopes: []string{}, // Allow any scope, tool-level checks
			}
		} else if *authServer != "" {
			// Fall back to OAuth introspection
			if *clientID == "" || *clientSecret == "" {
				fmt.Fprintln(os.Stderr, "Error: --client-id and --client-secret required with --auth-server")
				os.Exit(1)
			}

			httpConfig.Auth = &mcp.OAuthConfig{
				AuthServerURL:     *authServer,
				ClientID:          *clientID,
				ClientSecret:      *clientSecret,
				ResourceServerURL: httpConfig.ServerURL,
				RequiredScopes:    []string{}, // Allow any scope, tool-level checks
			}
		}

		httpServer := mcp.NewHTTPServer(mcpServer, httpConfig)

		errChan := make(chan error, 1)
		go func() {
			errChan <- httpServer.Start()
		}()

		select {
		case err := <-errChan:
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		case <-ctx.Done():
			if err := httpServer.Shutdown(context.Background()); err != nil {
				fmt.Fprintf(os.Stderr, "Error during shutdown: %v\n", err)
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown transport: %s\n", *transport)
		os.Exit(1)
	}
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
    mcp-sysinfo [OPTIONS]                    Run as MCP server (stdio)
    mcp-sysinfo --transport http [OPTIONS]   Run as HTTP server with OAuth
    mcp-sysinfo --query <NAME> [--json]      Run query directly (testing)

TRANSPORT OPTIONS:
    --transport <type>   Transport: stdio (default), http
    --listen <addr>      HTTP listen address (default: 127.0.0.1:8080)
    --server-url <url>   Public server URL (for OAuth metadata)
    --tls-cert <file>    TLS certificate file (enables HTTPS)
    --tls-key <file>     TLS key file

OIDC OPTIONS (for HTTP transport - local JWT validation):
    --oidc-issuer <url>  OIDC issuer URL (e.g., https://enterprise.okta.com)
    --oidc-audience <s>  Expected audience claim

OAUTH OPTIONS (for HTTP transport - token introspection):
    --auth-server <url>  OAuth authorization server URL
    --client-id <id>     OAuth client ID for token introspection
    --client-secret <s>  OAuth client secret

REDACTION OPTIONS:
    --redact             Enable output redaction of sensitive data
    --redact-provider    Redaction provider: default, gitguardian

AUDIT OPTIONS:
    --audit              Enable audit logging
    --audit-output       Audit log file path (default: /var/log/mcp-sysinfo/audit.jsonl)
    --audit-buffer-size  Buffer size for async writes (default: 100, 0 for sync)
    --audit-flush-interval  Flush interval (default: 5s)
    --audit-max-file-size   Max file size before rotation (default: 100MB)
    --audit-max-files    Max rotated files to keep (default: 10)
    --audit-sync-write   Force synchronous writes (fsync each write)
    --audit-verify       Verify audit log integrity and exit

OTHER OPTIONS:
    --help               Show this help message
    --version            Show version information
    --query <name>       Run a specific query directly
    --json               Output results in JSON format

EXAMPLES:
    # Run as MCP server (for Claude Desktop, etc.)
    mcp-sysinfo

    # Run as HTTP server without auth (development)
    mcp-sysinfo --transport http --listen 127.0.0.1:8080

    # Run as HTTP server with OIDC (enterprise IdP)
    mcp-sysinfo --transport http \
        --listen 0.0.0.0:8443 \
        --server-url https://mcp.example.com \
        --tls-cert /etc/mcp/cert.pem \
        --tls-key /etc/mcp/key.pem \
        --oidc-issuer https://enterprise.okta.com \
        --oidc-audience mcp-sysinfo

    # Run as HTTP server with OAuth introspection
    mcp-sysinfo --transport http \
        --listen 0.0.0.0:8443 \
        --server-url https://mcp.example.com \
        --tls-cert /etc/mcp/cert.pem \
        --tls-key /etc/mcp/key.pem \
        --auth-server http://localhost:8444 \
        --client-id mcp-sysinfo \
        --client-secret SECRET

    # Test a query directly
    mcp-sysinfo --query get_cpu_info --json

    # Run with audit logging enabled
    mcp-sysinfo --audit --audit-output /var/log/mcp-sysinfo/audit.jsonl

    # Verify audit log integrity
    mcp-sysinfo --audit-verify --audit-output /var/log/mcp-sysinfo/audit.jsonl

AVAILABLE TOOLS (37):

  Core Metrics (scope: core):
    get_cpu_info, get_memory_info, get_disk_info, get_network_info,
    get_processes, get_uptime, get_temperature

  Log Access (scope: logs):
    get_journal_logs, get_syslog, get_kernel_logs, get_app_logs,
    get_event_log

  System Hooks (scope: hooks):
    get_scheduled_tasks, get_cron_jobs, get_startup_items,
    get_systemd_services, get_kernel_modules, get_loaded_drivers,
    get_dns_servers, get_routes, get_firewall_rules, get_listening_ports,
    get_arp_table, get_network_stats, get_mounts, get_disk_io,
    get_open_files, get_inode_usage, get_env_vars, get_user_accounts,
    get_sudo_config, get_ssh_config, get_mac_status, get_certificates

  Software Inventory (scope: software):
    get_path_executables, get_system_packages

  Sensitive (scope: sensitive):
    get_auth_logs

SECURITY:
    stdio transport: No auth required (OS-level controls apply)
    http transport:  OAuth 2.1 with token introspection recommended

    See SECURITY.md for complete security architecture.

For more information: https://github.com/levantar-ai/mcp-sysinfo
`)
}

func runQuery(queryName string, jsonOut bool, pid int32) {
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
		result, err = c.GetTopProcesses(10, "cpu")

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

	case "get_env_vars":
		c := security.NewCollector()
		result, err = c.GetEnvVars()

	case "get_user_accounts":
		c := security.NewCollector()
		result, err = c.GetUserAccounts()

	case "get_sudo_config":
		c := security.NewCollector()
		result, err = c.GetSudoConfig()

	case "get_ssh_config":
		c := security.NewCollector()
		result, err = c.GetSSHConfig()

	case "get_mac_status":
		c := security.NewCollector()
		result, err = c.GetMACStatus()

	case "get_certificates":
		c := security.NewCollector()
		result, err = c.GetCertificates()

	// Hardware queries (Phase 1.6.6)
	case "get_hardware_info":
		c := hardware.NewCollector()
		result, err = c.GetHardwareInfo()

	case "get_usb_devices":
		c := hardware.NewCollector()
		result, err = c.GetUSBDevices()

	case "get_pci_devices":
		c := hardware.NewCollector()
		result, err = c.GetPCIDevices()

	case "get_block_devices":
		c := hardware.NewCollector()
		result, err = c.GetBlockDevices()

	// Resources queries (Phase 1.6.7)
	case "get_process_environ":
		c := resources.NewCollector()
		result, err = c.GetProcessEnviron(pid)

	case "get_ipc_resources":
		c := resources.NewCollector()
		result, err = c.GetIPCResources()

	case "get_namespaces":
		c := resources.NewCollector()
		result, err = c.GetNamespaces()

	case "get_cgroups":
		c := resources.NewCollector()
		result, err = c.GetCgroups()

	case "get_capabilities":
		c := resources.NewCollector()
		result, err = c.GetCapabilities(pid)

	// State queries (Phase 1.6.8)
	case "get_vm_info":
		c := state.NewCollector()
		result, err = c.GetVMInfo()

	case "get_timezone":
		c := state.NewCollector()
		result, err = c.GetTimezone()

	case "get_ntp_status":
		c := state.NewCollector()
		result, err = c.GetNTPStatus()

	case "get_core_dumps":
		c := state.NewCollector()
		result, err = c.GetCoreDumps()

	case "get_power_state":
		c := state.NewCollector()
		result, err = c.GetPowerState()

	case "get_numa_topology":
		c := state.NewCollector()
		result, err = c.GetNUMATopology()

	// Software queries (Phase 1.7)
	case "get_path_executables":
		c := software.NewCollector()
		result, err = c.GetPathExecutables()

	case "get_system_packages":
		c := software.NewCollector()
		result, err = c.GetSystemPackages()

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
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
}
