//go:build integration && darwin

// Package integration contains smoke tests that verify all queries work on macOS.
package integration

import (
	"context"
	"encoding/json"
	"os"
	"testing"
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
	"github.com/levantar-ai/mcp-sysinfo/internal/runtimes"
	"github.com/levantar-ai/mcp-sysinfo/internal/scheduled"
	"github.com/levantar-ai/mcp-sysinfo/internal/security"
	"github.com/levantar-ai/mcp-sysinfo/internal/software"
	"github.com/levantar-ai/mcp-sysinfo/internal/state"
	"github.com/levantar-ai/mcp-sysinfo/internal/storage"
	"github.com/levantar-ai/mcp-sysinfo/internal/temperature"
	"github.com/levantar-ai/mcp-sysinfo/internal/triage"
	"github.com/levantar-ai/mcp-sysinfo/internal/uptime"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// mustJSON marshals value to JSON and fails the test if it errors
func mustJSON(t *testing.T, name string, v interface{}) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Errorf("%s: failed to marshal to JSON: %v", name, err)
		return
	}
	if len(data) == 0 {
		t.Errorf("%s: JSON output is empty", name)
	}
	t.Logf("%s: OK (%d bytes)", name, len(data))
}

// =============================================================================
// Phase 1: Core Metrics (7 queries)
// =============================================================================

func TestSmoke_Darwin_GetCPUInfo(t *testing.T) {
	c := cpu.NewCollector()
	result, err := c.Collect(false)
	if err != nil {
		t.Fatalf("get_cpu_info failed: %v", err)
	}
	if result == nil {
		t.Fatal("get_cpu_info returned nil")
	}
	mustJSON(t, "get_cpu_info", result)
}

func TestSmoke_Darwin_GetMemoryInfo(t *testing.T) {
	c := memory.NewCollector()
	result, err := c.Collect()
	if err != nil {
		t.Fatalf("get_memory_info failed: %v", err)
	}
	if result == nil {
		t.Fatal("get_memory_info returned nil")
	}
	mustJSON(t, "get_memory_info", result)
}

func TestSmoke_Darwin_GetDiskInfo(t *testing.T) {
	c := disk.NewCollector()
	result, err := c.Collect()
	if err != nil {
		t.Fatalf("get_disk_info failed: %v", err)
	}
	if result == nil {
		t.Fatal("get_disk_info returned nil")
	}
	mustJSON(t, "get_disk_info", result)
}

func TestSmoke_Darwin_GetNetworkInfo(t *testing.T) {
	c := network.NewCollector()
	result, err := c.Collect()
	if err != nil {
		t.Fatalf("get_network_info failed: %v", err)
	}
	if result == nil {
		t.Fatal("get_network_info returned nil")
	}
	mustJSON(t, "get_network_info", result)
}

func TestSmoke_Darwin_GetProcesses(t *testing.T) {
	c := process.NewCollector()
	result, err := c.Collect()
	if err != nil {
		t.Fatalf("get_processes failed: %v", err)
	}
	if result == nil {
		t.Fatal("get_processes returned nil")
	}
	mustJSON(t, "get_processes", result)
}

func TestSmoke_Darwin_GetUptime(t *testing.T) {
	c := uptime.NewCollector()
	result, err := c.Collect()
	if err != nil {
		t.Fatalf("get_uptime failed: %v", err)
	}
	if result == nil {
		t.Fatal("get_uptime returned nil")
	}
	mustJSON(t, "get_uptime", result)
}

func TestSmoke_Darwin_GetTemperature(t *testing.T) {
	c := temperature.NewCollector()
	result, err := c.Collect()
	if err != nil {
		t.Logf("get_temperature returned error (may require SMC access): %v", err)
		return
	}
	if result != nil {
		mustJSON(t, "get_temperature", result)
	} else {
		t.Log("get_temperature: OK (no sensors available)")
	}
}

// =============================================================================
// Phase 1.5: Log Access (6 queries - macOS specific)
// =============================================================================

func TestSmoke_Darwin_GetSyslog(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetSyslog(&types.LogQuery{Lines: 10})
	if err != nil {
		t.Logf("get_syslog returned error: %v", err)
		return
	}
	mustJSON(t, "get_syslog", result)
}

func TestSmoke_Darwin_GetKernelLogs(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetKernelLogs(&types.LogQuery{Lines: 10})
	if err != nil {
		t.Logf("get_kernel_logs returned error: %v", err)
		return
	}
	mustJSON(t, "get_kernel_logs", result)
}

func TestSmoke_Darwin_GetAuthLogs(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetAuthLogs(&types.LogQuery{Lines: 10})
	if err != nil {
		t.Logf("get_auth_logs returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_auth_logs", result)
}

func TestSmoke_Darwin_GetAppLogs(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetAppLogs(&types.AppLogQuery{
		LogQuery: types.LogQuery{Lines: 10},
		Path:     "/var/log/system.log",
	})
	if err != nil {
		t.Logf("get_app_logs returned error: %v", err)
		return
	}
	mustJSON(t, "get_app_logs", result)
}

// =============================================================================
// Phase 1.6: System Hooks (31 queries - macOS variants)
// =============================================================================

func TestSmoke_Darwin_GetScheduledTasks(t *testing.T) {
	c := scheduled.NewCollector()
	result, err := c.GetScheduledTasks()
	if err != nil {
		t.Fatalf("get_scheduled_tasks failed: %v", err)
	}
	mustJSON(t, "get_scheduled_tasks", result)
}

func TestSmoke_Darwin_GetCronJobs(t *testing.T) {
	c := scheduled.NewCollector()
	result, err := c.GetCronJobs()
	if err != nil {
		t.Fatalf("get_cron_jobs failed: %v", err)
	}
	mustJSON(t, "get_cron_jobs", result)
}

func TestSmoke_Darwin_GetStartupItems(t *testing.T) {
	c := scheduled.NewCollector()
	result, err := c.GetStartupItems()
	if err != nil {
		t.Fatalf("get_startup_items failed: %v", err)
	}
	mustJSON(t, "get_startup_items", result)
}

func TestSmoke_Darwin_GetKernelModules(t *testing.T) {
	c := kernel.NewCollector()
	result, err := c.GetKernelModules()
	if err != nil {
		t.Fatalf("get_kernel_modules failed: %v", err)
	}
	mustJSON(t, "get_kernel_modules", result)
}

func TestSmoke_Darwin_GetLoadedDrivers(t *testing.T) {
	c := kernel.NewCollector()
	result, err := c.GetLoadedDrivers()
	if err != nil {
		t.Fatalf("get_loaded_drivers failed: %v", err)
	}
	mustJSON(t, "get_loaded_drivers", result)
}

func TestSmoke_Darwin_GetDNSServers(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetDNSServers()
	if err != nil {
		t.Fatalf("get_dns_servers failed: %v", err)
	}
	mustJSON(t, "get_dns_servers", result)
}

func TestSmoke_Darwin_GetRoutes(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetRoutes()
	if err != nil {
		t.Fatalf("get_routes failed: %v", err)
	}
	mustJSON(t, "get_routes", result)
}

func TestSmoke_Darwin_GetFirewallRules(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetFirewallRules()
	if err != nil {
		t.Logf("get_firewall_rules returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_firewall_rules", result)
}

func TestSmoke_Darwin_GetListeningPorts(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetListeningPorts()
	if err != nil {
		t.Fatalf("get_listening_ports failed: %v", err)
	}
	mustJSON(t, "get_listening_ports", result)
}

func TestSmoke_Darwin_GetARPTable(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetARPTable()
	if err != nil {
		t.Fatalf("get_arp_table failed: %v", err)
	}
	mustJSON(t, "get_arp_table", result)
}

func TestSmoke_Darwin_GetNetworkStats(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetNetworkStats()
	if err != nil {
		t.Fatalf("get_network_stats failed: %v", err)
	}
	mustJSON(t, "get_network_stats", result)
}

func TestSmoke_Darwin_GetMounts(t *testing.T) {
	c := filesystem.NewCollector()
	result, err := c.GetMounts()
	if err != nil {
		t.Fatalf("get_mounts failed: %v", err)
	}
	mustJSON(t, "get_mounts", result)
}

func TestSmoke_Darwin_GetDiskIO(t *testing.T) {
	c := filesystem.NewCollector()
	result, err := c.GetDiskIO()
	if err != nil {
		t.Fatalf("get_disk_io failed: %v", err)
	}
	mustJSON(t, "get_disk_io", result)
}

func TestSmoke_Darwin_GetOpenFiles(t *testing.T) {
	c := filesystem.NewCollector()
	result, err := c.GetOpenFiles()
	if err != nil {
		t.Logf("get_open_files returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_open_files", result)
}

func TestSmoke_Darwin_GetInodeUsage(t *testing.T) {
	c := filesystem.NewCollector()
	result, err := c.GetInodeUsage()
	if err != nil {
		t.Fatalf("get_inode_usage failed: %v", err)
	}
	mustJSON(t, "get_inode_usage", result)
}

func TestSmoke_Darwin_GetHardwareInfo(t *testing.T) {
	c := hardware.NewCollector()
	result, err := c.GetHardwareInfo()
	if err != nil {
		t.Fatalf("get_hardware_info failed: %v", err)
	}
	mustJSON(t, "get_hardware_info", result)
}

func TestSmoke_Darwin_GetUSBDevices(t *testing.T) {
	c := hardware.NewCollector()
	result, err := c.GetUSBDevices()
	if err != nil {
		t.Fatalf("get_usb_devices failed: %v", err)
	}
	mustJSON(t, "get_usb_devices", result)
}

func TestSmoke_Darwin_GetPCIDevices(t *testing.T) {
	c := hardware.NewCollector()
	result, err := c.GetPCIDevices()
	if err != nil {
		t.Fatalf("get_pci_devices failed: %v", err)
	}
	mustJSON(t, "get_pci_devices", result)
}

func TestSmoke_Darwin_GetBlockDevices(t *testing.T) {
	c := hardware.NewCollector()
	result, err := c.GetBlockDevices()
	if err != nil {
		t.Fatalf("get_block_devices failed: %v", err)
	}
	mustJSON(t, "get_block_devices", result)
}

func TestSmoke_Darwin_GetVMInfo(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetVMInfo()
	if err != nil {
		t.Fatalf("get_vm_info failed: %v", err)
	}
	mustJSON(t, "get_vm_info", result)
}

func TestSmoke_Darwin_GetTimezone(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetTimezone()
	if err != nil {
		t.Fatalf("get_timezone failed: %v", err)
	}
	mustJSON(t, "get_timezone", result)
}

func TestSmoke_Darwin_GetNTPStatus(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetNTPStatus()
	if err != nil {
		t.Logf("get_ntp_status returned error (NTP may not be configured): %v", err)
		return
	}
	mustJSON(t, "get_ntp_status", result)
}

func TestSmoke_Darwin_GetCoreDumps(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetCoreDumps()
	if err != nil {
		t.Fatalf("get_core_dumps failed: %v", err)
	}
	mustJSON(t, "get_core_dumps", result)
}

func TestSmoke_Darwin_GetPowerState(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetPowerState()
	if err != nil {
		t.Fatalf("get_power_state failed: %v", err)
	}
	mustJSON(t, "get_power_state", result)
}

// =============================================================================
// Phase 1.2.5: Security Configuration (6 queries)
// =============================================================================

func TestSmoke_Darwin_GetEnvVars(t *testing.T) {
	c := security.NewCollector()
	result, err := c.GetEnvVars()
	if err != nil {
		t.Fatalf("get_env_vars failed: %v", err)
	}
	mustJSON(t, "get_env_vars", result)
}

func TestSmoke_Darwin_GetUserAccounts(t *testing.T) {
	c := security.NewCollector()
	result, err := c.GetUserAccounts()
	if err != nil {
		t.Fatalf("get_user_accounts failed: %v", err)
	}
	mustJSON(t, "get_user_accounts", result)
}

func TestSmoke_Darwin_GetSudoConfig(t *testing.T) {
	c := security.NewCollector()
	result, err := c.GetSudoConfig()
	if err != nil {
		t.Logf("get_sudo_config returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_sudo_config", result)
}

func TestSmoke_Darwin_GetSSHConfig(t *testing.T) {
	c := security.NewCollector()
	result, err := c.GetSSHConfig()
	if err != nil {
		t.Logf("get_ssh_config returned error (SSH may not be configured): %v", err)
		return
	}
	mustJSON(t, "get_ssh_config", result)
}

func TestSmoke_Darwin_GetMACStatus(t *testing.T) {
	c := security.NewCollector()
	result, err := c.GetMACStatus()
	if err != nil {
		t.Fatalf("get_mac_status failed: %v", err)
	}
	mustJSON(t, "get_mac_status", result)
}

func TestSmoke_Darwin_GetCertificates(t *testing.T) {
	c := security.NewCollector()
	result, err := c.GetCertificates()
	if err != nil {
		t.Fatalf("get_certificates failed: %v", err)
	}
	mustJSON(t, "get_certificates", result)
}

// =============================================================================
// Phase 1.3: Software Inventory (31 queries)
// =============================================================================

func TestSmoke_Darwin_GetPathExecutables(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("get_path_executables failed: %v", err)
	}
	mustJSON(t, "get_path_executables", result)
}

func TestSmoke_Darwin_GetSystemPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("get_system_packages failed: %v", err)
	}
	mustJSON(t, "get_system_packages", result)
}

func TestSmoke_Darwin_GetPythonPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetPythonPackages()
	if err != nil {
		t.Logf("get_python_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_python_packages", result)
}

func TestSmoke_Darwin_GetNodePackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetNodePackages()
	if err != nil {
		t.Logf("get_node_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_node_packages", result)
}

func TestSmoke_Darwin_GetGoModules(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetGoModules()
	if err != nil {
		t.Logf("get_go_modules returned error: %v", err)
		return
	}
	mustJSON(t, "get_go_modules", result)
}

func TestSmoke_Darwin_GetRustPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetRustPackages()
	if err != nil {
		t.Logf("get_rust_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_rust_packages", result)
}

func TestSmoke_Darwin_GetRubyGems(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetRubyGems()
	if err != nil {
		t.Logf("get_ruby_gems returned error: %v", err)
		return
	}
	mustJSON(t, "get_ruby_gems", result)
}

func TestSmoke_Darwin_GetMavenPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetMavenPackages()
	if err != nil {
		t.Logf("get_maven_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_maven_packages", result)
}

func TestSmoke_Darwin_GetPHPPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetPHPPackages()
	if err != nil {
		t.Logf("get_php_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_php_packages", result)
}

func TestSmoke_Darwin_GetDotnetPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetDotnetPackages()
	if err != nil {
		t.Logf("get_dotnet_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_dotnet_packages", result)
}

func TestSmoke_Darwin_GetMacOSApplications(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetMacOSApplications()
	if err != nil {
		t.Fatalf("get_macos_applications failed: %v", err)
	}
	mustJSON(t, "get_macos_applications", result)
}

func TestSmoke_Darwin_GetHomebrewCasks(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetHomebrewCasks()
	if err != nil {
		t.Logf("get_homebrew_casks returned error (Homebrew may not be installed): %v", err)
		return
	}
	mustJSON(t, "get_homebrew_casks", result)
}

func TestSmoke_Darwin_GetSBOMCycloneDX(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetSBOMCycloneDX()
	if err != nil {
		t.Fatalf("get_sbom_cyclonedx failed: %v", err)
	}
	mustJSON(t, "get_sbom_cyclonedx", result)
}

func TestSmoke_Darwin_GetSBOMSPDX(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetSBOMSPDX()
	if err != nil {
		t.Fatalf("get_sbom_spdx failed: %v", err)
	}
	mustJSON(t, "get_sbom_spdx", result)
}

func TestSmoke_Darwin_GetDockerImages(t *testing.T) {
	c := container.NewCollector()
	result, err := c.GetDockerImages()
	if err != nil {
		t.Logf("get_docker_images returned error (Docker may not be available): %v", err)
		return
	}
	mustJSON(t, "get_docker_images", result)
}

func TestSmoke_Darwin_GetDockerContainers(t *testing.T) {
	c := container.NewCollector()
	result, err := c.GetDockerContainers()
	if err != nil {
		t.Logf("get_docker_containers returned error (Docker may not be available): %v", err)
		return
	}
	mustJSON(t, "get_docker_containers", result)
}

func TestSmoke_Darwin_GetImageHistory(t *testing.T) {
	c := container.NewCollector()
	result, err := c.GetImageHistory("alpine:latest")
	if err != nil {
		t.Logf("get_docker_image_history returned error (Docker/image may not be available): %v", err)
		return
	}
	mustJSON(t, "get_docker_image_history", result)
}

func TestSmoke_Darwin_GetNpmLock(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetNpmLock("/nonexistent/package-lock.json")
	if err != nil {
		t.Logf("get_npm_lock returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_npm_lock", result)
}

func TestSmoke_Darwin_GetPipLock(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetPipLock("/nonexistent/requirements.txt")
	if err != nil {
		t.Logf("get_pip_lock returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_pip_lock", result)
}

func TestSmoke_Darwin_GetCargoLock(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetCargoLock("/nonexistent/Cargo.lock")
	if err != nil {
		t.Logf("get_cargo_lock returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_cargo_lock", result)
}

func TestSmoke_Darwin_GetGoSum(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetGoSum("/nonexistent/go.sum")
	if err != nil {
		t.Logf("get_go_sum returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_go_sum", result)
}

func TestSmoke_Darwin_GetGemfileLock(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetGemfileLock("/nonexistent/Gemfile.lock")
	if err != nil {
		t.Logf("get_gemfile_lock returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_gemfile_lock", result)
}

func TestSmoke_Darwin_GetVulnerabilitiesOSV(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping external API call in short mode")
	}
	c := software.NewCollector()
	result, err := c.GetVulnerabilitiesOSV()
	if err != nil {
		t.Logf("get_vulnerabilities_osv returned error: %v", err)
		return
	}
	mustJSON(t, "get_vulnerabilities_osv", result)
}

func TestSmoke_Darwin_GetVulnerabilitiesNVD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping external API call in short mode")
	}
	c := software.NewCollector()
	result, err := c.GetVulnerabilitiesNVD()
	if err != nil {
		t.Logf("get_vulnerabilities_nvd returned error: %v", err)
		return
	}
	mustJSON(t, "get_vulnerabilities_nvd", result)
}

// =============================================================================
// Phase 1.8: Application Discovery (2 queries)
// =============================================================================

func TestSmoke_Darwin_GetApplications(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetApplications()
	if err != nil {
		t.Fatalf("get_applications failed: %v", err)
	}
	mustJSON(t, "get_applications", result)
}

func TestSmoke_Darwin_GetAppConfig(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetAppConfig("/etc/hosts")
	if err != nil {
		t.Logf("get_app_config returned error: %v", err)
		return
	}
	mustJSON(t, "get_app_config", result)
}

// =============================================================================
// Phase 1.9: Triage & Summary (25 queries)
// =============================================================================

func TestSmoke_Darwin_GetOSInfo(t *testing.T) {
	c := osinfo.NewCollector()
	result, err := c.GetOSInfo()
	if err != nil {
		t.Fatalf("get_os_info failed: %v", err)
	}
	mustJSON(t, "get_os_info", result)
}

func TestSmoke_Darwin_GetSystemProfile(t *testing.T) {
	c := osinfo.NewCollector()
	result, err := c.GetSystemProfile()
	if err != nil {
		t.Fatalf("get_system_profile failed: %v", err)
	}
	mustJSON(t, "get_system_profile", result)
}

func TestSmoke_Darwin_GetServiceManagerInfo(t *testing.T) {
	c := osinfo.NewCollector()
	result, err := c.GetServiceManagerInfo()
	if err != nil {
		t.Fatalf("get_service_manager_info failed: %v", err)
	}
	mustJSON(t, "get_service_manager_info", result)
}

func TestSmoke_Darwin_GetCloudEnvironment(t *testing.T) {
	c := osinfo.NewCollector()
	result, err := c.GetCloudEnvironment()
	if err != nil {
		t.Fatalf("get_cloud_environment failed: %v", err)
	}
	mustJSON(t, "get_cloud_environment", result)
}

func TestSmoke_Darwin_GetLanguageRuntimes(t *testing.T) {
	c := runtimes.NewCollector()
	result, err := c.GetLanguageRuntimes()
	if err != nil {
		t.Fatalf("get_language_runtime_versions failed: %v", err)
	}
	mustJSON(t, "get_language_runtime_versions", result)
}

func TestSmoke_Darwin_GetRecentReboots(t *testing.T) {
	// Skip in CI - uses 'log show' which is slow on macOS runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' on macOS")
	}
	c := triage.NewCollector()
	result, err := c.GetRecentReboots(10)
	if err != nil {
		t.Fatalf("get_recent_reboots failed: %v", err)
	}
	mustJSON(t, "get_recent_reboots", result)
}

func TestSmoke_Darwin_GetRecentServiceFailures(t *testing.T) {
	// Skip in CI - uses 'log show' which is slow on macOS runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' on macOS")
	}
	c := triage.NewCollector()
	result, err := c.GetRecentServiceFailures(24)
	if err != nil {
		t.Fatalf("get_recent_service_failures failed: %v", err)
	}
	mustJSON(t, "get_recent_service_failures", result)
}

func TestSmoke_Darwin_GetRecentKernelEvents(t *testing.T) {
	// Skip in CI - uses 'log show' which takes 1+ minutes on macOS runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' on macOS")
	}
	c := triage.NewCollector()
	result, err := c.GetRecentKernelEvents(24)
	if err != nil {
		t.Fatalf("get_recent_kernel_events failed: %v", err)
	}
	mustJSON(t, "get_recent_kernel_events", result)
}

func TestSmoke_Darwin_GetRecentCriticalEvents(t *testing.T) {
	// Skip in CI - uses 'log show' which takes 1+ minutes on macOS runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' on macOS")
	}
	c := triage.NewCollector()
	result, err := c.GetRecentCriticalEvents(24)
	if err != nil {
		t.Fatalf("get_recent_critical_events failed: %v", err)
	}
	mustJSON(t, "get_recent_critical_events", result)
}

func TestSmoke_Darwin_GetRecentResourceIncidents(t *testing.T) {
	// Skip in CI - uses 'log show' which is slow on macOS runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' on macOS")
	}
	c := triage.NewCollector()
	result, err := c.GetRecentResourceIncidents(24)
	if err != nil {
		t.Fatalf("get_recent_resource_incidents failed: %v", err)
	}
	mustJSON(t, "get_recent_resource_incidents", result)
}

func TestSmoke_Darwin_GetRecentConfigChanges(t *testing.T) {
	// Skip in CI - uses 'log show' which is slow on macOS runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' on macOS")
	}
	c := triage.NewCollector()
	result, err := c.GetRecentConfigChanges(24)
	if err != nil {
		t.Fatalf("get_recent_config_changes failed: %v", err)
	}
	mustJSON(t, "get_recent_config_changes", result)
}

func TestSmoke_Darwin_GetFailedUnits(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetFailedUnits()
	if err != nil {
		t.Fatalf("get_failed_units failed: %v", err)
	}
	mustJSON(t, "get_failed_units", result)
}

func TestSmoke_Darwin_GetTimerJobs(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetTimerJobs()
	if err != nil {
		t.Fatalf("get_timer_jobs failed: %v", err)
	}
	mustJSON(t, "get_timer_jobs", result)
}

func TestSmoke_Darwin_GetServiceLogView(t *testing.T) {
	// Skip in CI - uses 'log show' which is slow on macOS runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' on macOS")
	}
	c := triage.NewCollector()
	result, err := c.GetServiceLogView("sshd", 10)
	if err != nil {
		t.Logf("get_service_log_view returned error: %v", err)
		return
	}
	mustJSON(t, "get_service_log_view", result)
}

func TestSmoke_Darwin_GetSecurityBasics(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetSecurityBasics()
	if err != nil {
		t.Fatalf("get_security_basics failed: %v", err)
	}
	mustJSON(t, "get_security_basics", result)
}

func TestSmoke_Darwin_GetAuthFailureSummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetAuthFailureSummary(24)
	if err != nil {
		t.Logf("get_auth_failure_summary returned error: %v", err)
		return
	}
	mustJSON(t, "get_auth_failure_summary", result)
}

func TestSmoke_Darwin_GetAdminAccountSummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetAdminAccountSummary()
	if err != nil {
		t.Fatalf("get_admin_account_summary failed: %v", err)
	}
	mustJSON(t, "get_admin_account_summary", result)
}

func TestSmoke_Darwin_GetExposedServicesSummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetExposedServicesSummary()
	if err != nil {
		t.Fatalf("get_exposed_services_summary failed: %v", err)
	}
	mustJSON(t, "get_exposed_services_summary", result)
}

func TestSmoke_Darwin_GetSSHSecuritySummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetSSHSecuritySummary()
	if err != nil {
		t.Fatalf("get_ssh_security_summary failed: %v", err)
	}
	mustJSON(t, "get_ssh_security_summary", result)
}

func TestSmoke_Darwin_GetResourceLimits(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetResourceLimits()
	if err != nil {
		t.Fatalf("get_resource_limits failed: %v", err)
	}
	mustJSON(t, "get_resource_limits", result)
}

func TestSmoke_Darwin_GetRecentlyInstalledSoftware(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetRecentlyInstalledSoftware(50)
	if err != nil {
		t.Fatalf("get_recently_installed_software failed: %v", err)
	}
	mustJSON(t, "get_recently_installed_software", result)
}

func TestSmoke_Darwin_GetFSHealthSummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetFSHealthSummary()
	if err != nil {
		t.Fatalf("get_fs_health_summary failed: %v", err)
	}
	mustJSON(t, "get_fs_health_summary", result)
}

func TestSmoke_Darwin_GetDeploymentEvents(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetDeploymentEvents(24)
	if err != nil {
		t.Fatalf("get_deployment_events failed: %v", err)
	}
	mustJSON(t, "get_deployment_events", result)
}

func TestSmoke_Darwin_GetIncidentTriageSnapshot(t *testing.T) {
	// Skip in CI - this test calls multiple 'log show' commands which can take 10+ minutes on macOS CI runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' commands on macOS runners")
	}
	c := triage.NewCollector()
	result, err := c.GetIncidentTriageSnapshot()
	if err != nil {
		t.Fatalf("get_incident_triage_snapshot failed: %v", err)
	}
	mustJSON(t, "get_incident_triage_snapshot", result)
}

func TestSmoke_Darwin_GetSecurityPostureSnapshot(t *testing.T) {
	// Skip in CI - this test calls multiple 'log show' commands which can take 10+ minutes on macOS CI runners
	if os.Getenv("CI") != "" {
		t.Skip("Skipping in CI due to slow 'log show' commands on macOS runners")
	}
	c := triage.NewCollector()
	result, err := c.GetSecurityPostureSnapshot()
	if err != nil {
		t.Fatalf("get_security_posture_snapshot failed: %v", err)
	}
	mustJSON(t, "get_security_posture_snapshot", result)
}

// =============================================================================
// Phase 2.0: Enhanced Diagnostics (5 queries)
// =============================================================================

func TestSmoke_Darwin_GetGPUInfo(t *testing.T) {
	c := gpu.NewCollector()
	result, err := c.GetGPUInfo()
	if err != nil {
		t.Logf("get_gpu_info returned error (GPU info may be limited on macOS): %v", err)
		return
	}
	mustJSON(t, "get_gpu_info", result)
}

func TestSmoke_Darwin_GetContainerStats(t *testing.T) {
	c := container.NewCollector()
	result, err := c.GetContainerStats("")
	if err != nil {
		t.Logf("get_container_stats returned error (Docker may not be available): %v", err)
		return
	}
	mustJSON(t, "get_container_stats", result)
}

func TestSmoke_Darwin_GetContainerLogs(t *testing.T) {
	// First get a container ID if any exist
	c := container.NewCollector()
	containers, err := c.GetDockerContainers()
	if err != nil || containers.Count == 0 {
		t.Log("get_container_logs: skipped (no containers available)")
		return
	}

	// Get logs from the first container
	result, err := c.GetContainerLogs(containers.Containers[0].ID, 10, "")
	if err != nil {
		t.Logf("get_container_logs returned error: %v", err)
		return
	}
	mustJSON(t, "get_container_logs", result)
}

func TestSmoke_Darwin_GenerateSystemReport(t *testing.T) {
	rg := report.NewReportGenerator(30 * time.Second)
	ctx := context.Background()
	result, err := rg.GenerateSystemReport(ctx, []string{"os", "cpu", "memory", "uptime"})
	if err != nil {
		t.Fatalf("generate_system_report failed: %v", err)
	}
	mustJSON(t, "generate_system_report", result)
}

func TestSmoke_Darwin_GetProcessesSampled(t *testing.T) {
	c := process.NewCollector()
	// Use a short sample duration for tests
	result, err := c.CollectSampled(200)
	if err != nil {
		t.Fatalf("get_processes_sampled failed: %v", err)
	}
	mustJSON(t, "get_processes_sampled", result)
}

// =============================================================================
// Phase 3: Storage Deep Dive (5 queries)
// =============================================================================

func TestSmoke_Darwin_GetSMARTHealth(t *testing.T) {
	c := storage.NewCollector()
	result, err := c.GetSMARTHealth()
	if err != nil {
		t.Fatalf("get_smart_health failed: %v", err)
	}
	mustJSON(t, "get_smart_health", result)
}

func TestSmoke_Darwin_GetIOLatency(t *testing.T) {
	c := storage.NewCollector()
	result, err := c.GetIOLatency()
	if err != nil {
		t.Fatalf("get_io_latency failed: %v", err)
	}
	mustJSON(t, "get_io_latency", result)
}

func TestSmoke_Darwin_GetVolumeStatus(t *testing.T) {
	c := storage.NewCollector()
	result, err := c.GetVolumeStatus()
	if err != nil {
		t.Fatalf("get_volume_status failed: %v", err)
	}
	mustJSON(t, "get_volume_status", result)
}

func TestSmoke_Darwin_GetMountChanges(t *testing.T) {
	c := storage.NewCollector()
	result, err := c.GetMountChanges()
	if err != nil {
		t.Fatalf("get_mount_changes failed: %v", err)
	}
	mustJSON(t, "get_mount_changes", result)
}

func TestSmoke_Darwin_GetFSEvents(t *testing.T) {
	c := storage.NewCollector()
	result, err := c.GetFSEvents()
	if err != nil {
		t.Fatalf("get_fs_events failed: %v", err)
	}
	mustJSON(t, "get_fs_events", result)
}

// =============================================================================
// Phase 4: Network Intelligence (5 queries)
// =============================================================================

func TestSmoke_Darwin_GetConnectionTracking(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetConnectionTracking()
	if err != nil {
		t.Fatalf("get_connection_tracking failed: %v", err)
	}
	mustJSON(t, "get_connection_tracking", result)
}

func TestSmoke_Darwin_GetDNSStats(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetDNSStats()
	if err != nil {
		t.Fatalf("get_dns_stats failed: %v", err)
	}
	mustJSON(t, "get_dns_stats", result)
}

func TestSmoke_Darwin_GetFirewallDeep(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetFirewallDeep()
	if err != nil {
		t.Logf("get_firewall_deep returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_firewall_deep", result)
}

func TestSmoke_Darwin_GetWiFiMetrics(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetWiFiMetrics()
	if err != nil {
		t.Logf("get_wifi_metrics returned error (WiFi may not be available): %v", err)
		return
	}
	mustJSON(t, "get_wifi_metrics", result)
}

func TestSmoke_Darwin_GetNetworkLatency(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetNetworkLatency([]string{"8.8.8.8", "1.1.1.1"})
	if err != nil {
		t.Logf("get_network_latency returned error: %v", err)
		return
	}
	mustJSON(t, "get_network_latency", result)
}

// =============================================================================
// Phase 5: Analytics & Trends (4 queries)
// =============================================================================

func TestSmoke_Darwin_GetHistoricalMetrics(t *testing.T) {
	c := analytics.NewCollector()
	result, err := c.GetHistoricalMetrics("1h")
	if err != nil {
		t.Fatalf("get_historical_metrics failed: %v", err)
	}
	mustJSON(t, "get_historical_metrics", result)
}

func TestSmoke_Darwin_GetAnomalyDetection(t *testing.T) {
	c := analytics.NewCollector()
	result, err := c.GetAnomalyDetection()
	if err != nil {
		t.Fatalf("get_anomaly_detection failed: %v", err)
	}
	mustJSON(t, "get_anomaly_detection", result)
}

func TestSmoke_Darwin_GetCapacityForecast(t *testing.T) {
	c := analytics.NewCollector()
	result, err := c.GetCapacityForecast()
	if err != nil {
		t.Fatalf("get_capacity_forecast failed: %v", err)
	}
	mustJSON(t, "get_capacity_forecast", result)
}

func TestSmoke_Darwin_GetTrendAnalysis(t *testing.T) {
	c := analytics.NewCollector()
	result, err := c.GetTrendAnalysis("1h")
	if err != nil {
		t.Fatalf("get_trend_analysis failed: %v", err)
	}
	mustJSON(t, "get_trend_analysis", result)
}

// =============================================================================
// Phase 6: Automation & Alerting (3 queries)
// =============================================================================

func TestSmoke_Darwin_GetAlertStatus(t *testing.T) {
	c := alerts.NewCollector()
	result, err := c.GetAlertStatus()
	if err != nil {
		t.Fatalf("get_alert_status failed: %v", err)
	}
	mustJSON(t, "get_alert_status", result)
}

func TestSmoke_Darwin_GetRemediationSuggestions(t *testing.T) {
	c := alerts.NewCollector()
	result, err := c.GetRemediationSuggestions()
	if err != nil {
		t.Fatalf("get_remediation_suggestions failed: %v", err)
	}
	mustJSON(t, "get_remediation_suggestions", result)
}

func TestSmoke_Darwin_GetRunbookRecommendations(t *testing.T) {
	c := alerts.NewCollector()
	result, err := c.GetRunbookRecommendations()
	if err != nil {
		t.Fatalf("get_runbook_recommendations failed: %v", err)
	}
	mustJSON(t, "get_runbook_recommendations", result)
}

// =============================================================================
// Phase 7: Security & Compliance (5 queries)
// =============================================================================

func TestSmoke_Darwin_GetSecurityScan(t *testing.T) {
	c := compliance.NewCollector()
	result, err := c.GetSecurityScan()
	if err != nil {
		t.Fatalf("get_security_scan failed: %v", err)
	}
	mustJSON(t, "get_security_scan", result)
}

func TestSmoke_Darwin_GetComplianceCheck(t *testing.T) {
	c := compliance.NewCollector()
	result, err := c.GetComplianceCheck("cis")
	if err != nil {
		t.Fatalf("get_compliance_check failed: %v", err)
	}
	mustJSON(t, "get_compliance_check", result)
}

func TestSmoke_Darwin_GetForensicSnapshot(t *testing.T) {
	c := compliance.NewCollector()
	result, err := c.GetForensicSnapshot()
	if err != nil {
		t.Fatalf("get_forensic_snapshot failed: %v", err)
	}
	mustJSON(t, "get_forensic_snapshot", result)
}

func TestSmoke_Darwin_GetAuditTrail(t *testing.T) {
	c := compliance.NewCollector()
	result, err := c.GetAuditTrail(24)
	if err != nil {
		t.Fatalf("get_audit_trail failed: %v", err)
	}
	mustJSON(t, "get_audit_trail", result)
}

func TestSmoke_Darwin_GetHardeningRecommendations(t *testing.T) {
	c := compliance.NewCollector()
	result, err := c.GetHardeningRecommendations()
	if err != nil {
		t.Fatalf("get_hardening_recommendations failed: %v", err)
	}
	mustJSON(t, "get_hardening_recommendations", result)
}

// =============================================================================
// Phase 1.9: Consumer Diagnostics (4 queries - stubs on macOS)
// =============================================================================

func TestSmoke_Darwin_GetBluetoothDevices(t *testing.T) {
	c := consumer.NewCollector()
	result, err := c.GetBluetoothDevices()
	if err != nil {
		t.Fatalf("get_bluetooth_devices failed: %v", err)
	}
	// On macOS, this returns a stub with "not implemented" error
	if result.Error == "" {
		t.Log("get_bluetooth_devices: macOS implementation available")
	} else {
		t.Logf("get_bluetooth_devices: stub returned (expected): %s", result.Error)
	}
	mustJSON(t, "get_bluetooth_devices", result)
}

func TestSmoke_Darwin_GetAudioDevices(t *testing.T) {
	c := consumer.NewCollector()
	result, err := c.GetAudioDevices()
	if err != nil {
		t.Fatalf("get_audio_devices failed: %v", err)
	}
	// On macOS, this returns a stub with "not implemented" error
	if result.Error == "" {
		t.Log("get_audio_devices: macOS implementation available")
	} else {
		t.Logf("get_audio_devices: stub returned (expected): %s", result.Error)
	}
	mustJSON(t, "get_audio_devices", result)
}

func TestSmoke_Darwin_GetPrinters(t *testing.T) {
	c := consumer.NewCollector()
	result, err := c.GetPrinters()
	if err != nil {
		t.Fatalf("get_printers failed: %v", err)
	}
	// On macOS, this returns a stub with "not implemented" error
	if result.Error == "" {
		t.Log("get_printers: macOS implementation available")
	} else {
		t.Logf("get_printers: stub returned (expected): %s", result.Error)
	}
	mustJSON(t, "get_printers", result)
}

func TestSmoke_Darwin_GetDisplayConfig(t *testing.T) {
	c := consumer.NewCollector()
	result, err := c.GetDisplayConfig()
	if err != nil {
		t.Fatalf("get_display_config failed: %v", err)
	}
	// On macOS, this returns a stub with "not implemented" error
	if result.Error == "" {
		t.Log("get_display_config: macOS implementation available")
	} else {
		t.Logf("get_display_config: stub returned (expected): %s", result.Error)
	}
	mustJSON(t, "get_display_config", result)
}
