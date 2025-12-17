//go:build integration && linux

// Package integration contains smoke tests that verify all queries work on Linux.
package integration

import (
	"encoding/json"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/container"
	"github.com/levantar-ai/mcp-sysinfo/internal/cpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
	"github.com/levantar-ai/mcp-sysinfo/internal/filesystem"
	"github.com/levantar-ai/mcp-sysinfo/internal/hardware"
	"github.com/levantar-ai/mcp-sysinfo/internal/kernel"
	"github.com/levantar-ai/mcp-sysinfo/internal/logs"
	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
	"github.com/levantar-ai/mcp-sysinfo/internal/netconfig"
	"github.com/levantar-ai/mcp-sysinfo/internal/network"
	"github.com/levantar-ai/mcp-sysinfo/internal/osinfo"
	"github.com/levantar-ai/mcp-sysinfo/internal/process"
	"github.com/levantar-ai/mcp-sysinfo/internal/resources"
	"github.com/levantar-ai/mcp-sysinfo/internal/runtimes"
	"github.com/levantar-ai/mcp-sysinfo/internal/scheduled"
	"github.com/levantar-ai/mcp-sysinfo/internal/software"
	"github.com/levantar-ai/mcp-sysinfo/internal/state"
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

func TestSmoke_Linux_GetCPUInfo(t *testing.T) {
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

func TestSmoke_Linux_GetMemoryInfo(t *testing.T) {
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

func TestSmoke_Linux_GetDiskInfo(t *testing.T) {
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

func TestSmoke_Linux_GetNetworkInfo(t *testing.T) {
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

func TestSmoke_Linux_GetProcesses(t *testing.T) {
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

func TestSmoke_Linux_GetUptime(t *testing.T) {
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

func TestSmoke_Linux_GetTemperature(t *testing.T) {
	c := temperature.NewCollector()
	result, err := c.Collect()
	if err != nil {
		t.Logf("get_temperature returned error (may be expected in VM): %v", err)
		return
	}
	// Temperature may return nil on VMs/containers - that's OK
	if result != nil {
		mustJSON(t, "get_temperature", result)
	} else {
		t.Log("get_temperature: OK (no sensors available)")
	}
}

// =============================================================================
// Phase 1.5: Log Access (6 queries)
// =============================================================================

func TestSmoke_Linux_GetJournalLogs(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetJournalLogs(&types.LogQuery{Lines: 10})
	if err != nil {
		t.Logf("get_journal_logs returned error (journald may not be available): %v", err)
		return
	}
	mustJSON(t, "get_journal_logs", result)
}

func TestSmoke_Linux_GetSyslog(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetSyslog(&types.LogQuery{Lines: 10})
	if err != nil {
		t.Logf("get_syslog returned error (syslog may not be available): %v", err)
		return
	}
	mustJSON(t, "get_syslog", result)
}

func TestSmoke_Linux_GetKernelLogs(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetKernelLogs(&types.LogQuery{Lines: 10})
	if err != nil {
		t.Logf("get_kernel_logs returned error: %v", err)
		return
	}
	mustJSON(t, "get_kernel_logs", result)
}

func TestSmoke_Linux_GetAuthLogs(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetAuthLogs(&types.LogQuery{Lines: 10})
	if err != nil {
		t.Logf("get_auth_logs returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_auth_logs", result)
}

func TestSmoke_Linux_GetAppLogs(t *testing.T) {
	c := logs.NewCollector()
	result, err := c.GetAppLogs(&types.AppLogQuery{
		LogQuery: types.LogQuery{Lines: 10},
		Path:     "/var/log/syslog",
	})
	if err != nil {
		t.Logf("get_app_logs returned error: %v", err)
		return
	}
	mustJSON(t, "get_app_logs", result)
}

// =============================================================================
// Phase 1.6: System Hooks (31 queries)
// =============================================================================

func TestSmoke_Linux_GetScheduledTasks(t *testing.T) {
	c := scheduled.NewCollector()
	result, err := c.GetScheduledTasks()
	if err != nil {
		t.Fatalf("get_scheduled_tasks failed: %v", err)
	}
	mustJSON(t, "get_scheduled_tasks", result)
}

func TestSmoke_Linux_GetCronJobs(t *testing.T) {
	c := scheduled.NewCollector()
	result, err := c.GetCronJobs()
	if err != nil {
		t.Fatalf("get_cron_jobs failed: %v", err)
	}
	mustJSON(t, "get_cron_jobs", result)
}

func TestSmoke_Linux_GetStartupItems(t *testing.T) {
	c := scheduled.NewCollector()
	result, err := c.GetStartupItems()
	if err != nil {
		t.Fatalf("get_startup_items failed: %v", err)
	}
	mustJSON(t, "get_startup_items", result)
}

func TestSmoke_Linux_GetSystemdServices(t *testing.T) {
	c := scheduled.NewCollector()
	result, err := c.GetSystemdServices()
	if err != nil {
		t.Logf("get_systemd_services returned error (systemd may not be available): %v", err)
		return
	}
	mustJSON(t, "get_systemd_services", result)
}

func TestSmoke_Linux_GetKernelModules(t *testing.T) {
	c := kernel.NewCollector()
	result, err := c.GetKernelModules()
	if err != nil {
		t.Fatalf("get_kernel_modules failed: %v", err)
	}
	mustJSON(t, "get_kernel_modules", result)
}

func TestSmoke_Linux_GetLoadedDrivers(t *testing.T) {
	c := kernel.NewCollector()
	result, err := c.GetLoadedDrivers()
	if err != nil {
		t.Fatalf("get_loaded_drivers failed: %v", err)
	}
	mustJSON(t, "get_loaded_drivers", result)
}

func TestSmoke_Linux_GetDNSServers(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetDNSServers()
	if err != nil {
		t.Fatalf("get_dns_servers failed: %v", err)
	}
	mustJSON(t, "get_dns_servers", result)
}

func TestSmoke_Linux_GetRoutes(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetRoutes()
	if err != nil {
		t.Fatalf("get_routes failed: %v", err)
	}
	mustJSON(t, "get_routes", result)
}

func TestSmoke_Linux_GetFirewallRules(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetFirewallRules()
	if err != nil {
		t.Logf("get_firewall_rules returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_firewall_rules", result)
}

func TestSmoke_Linux_GetListeningPorts(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetListeningPorts()
	if err != nil {
		t.Fatalf("get_listening_ports failed: %v", err)
	}
	mustJSON(t, "get_listening_ports", result)
}

func TestSmoke_Linux_GetARPTable(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetARPTable()
	if err != nil {
		t.Fatalf("get_arp_table failed: %v", err)
	}
	mustJSON(t, "get_arp_table", result)
}

func TestSmoke_Linux_GetNetworkStats(t *testing.T) {
	c := netconfig.NewCollector()
	result, err := c.GetNetworkStats()
	if err != nil {
		t.Fatalf("get_network_stats failed: %v", err)
	}
	mustJSON(t, "get_network_stats", result)
}

func TestSmoke_Linux_GetMounts(t *testing.T) {
	c := filesystem.NewCollector()
	result, err := c.GetMounts()
	if err != nil {
		t.Fatalf("get_mounts failed: %v", err)
	}
	mustJSON(t, "get_mounts", result)
}

func TestSmoke_Linux_GetDiskIO(t *testing.T) {
	c := filesystem.NewCollector()
	result, err := c.GetDiskIO()
	if err != nil {
		t.Fatalf("get_disk_io failed: %v", err)
	}
	mustJSON(t, "get_disk_io", result)
}

func TestSmoke_Linux_GetOpenFiles(t *testing.T) {
	c := filesystem.NewCollector()
	result, err := c.GetOpenFiles()
	if err != nil {
		t.Logf("get_open_files returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_open_files", result)
}

func TestSmoke_Linux_GetInodeUsage(t *testing.T) {
	c := filesystem.NewCollector()
	result, err := c.GetInodeUsage()
	if err != nil {
		t.Fatalf("get_inode_usage failed: %v", err)
	}
	mustJSON(t, "get_inode_usage", result)
}

func TestSmoke_Linux_GetHardwareInfo(t *testing.T) {
	c := hardware.NewCollector()
	result, err := c.GetHardwareInfo()
	if err != nil {
		t.Fatalf("get_hardware_info failed: %v", err)
	}
	mustJSON(t, "get_hardware_info", result)
}

func TestSmoke_Linux_GetUSBDevices(t *testing.T) {
	c := hardware.NewCollector()
	result, err := c.GetUSBDevices()
	if err != nil {
		t.Fatalf("get_usb_devices failed: %v", err)
	}
	mustJSON(t, "get_usb_devices", result)
}

func TestSmoke_Linux_GetPCIDevices(t *testing.T) {
	c := hardware.NewCollector()
	result, err := c.GetPCIDevices()
	if err != nil {
		t.Fatalf("get_pci_devices failed: %v", err)
	}
	mustJSON(t, "get_pci_devices", result)
}

func TestSmoke_Linux_GetBlockDevices(t *testing.T) {
	c := hardware.NewCollector()
	result, err := c.GetBlockDevices()
	if err != nil {
		t.Fatalf("get_block_devices failed: %v", err)
	}
	mustJSON(t, "get_block_devices", result)
}

func TestSmoke_Linux_GetProcessEnviron(t *testing.T) {
	c := resources.NewCollector()
	result, err := c.GetProcessEnviron(1) // init/systemd
	if err != nil {
		t.Logf("get_process_environ returned error (may require elevated permissions): %v", err)
		return
	}
	mustJSON(t, "get_process_environ", result)
}

func TestSmoke_Linux_GetIPCResources(t *testing.T) {
	c := resources.NewCollector()
	result, err := c.GetIPCResources()
	if err != nil {
		t.Fatalf("get_ipc_resources failed: %v", err)
	}
	mustJSON(t, "get_ipc_resources", result)
}

func TestSmoke_Linux_GetNamespaces(t *testing.T) {
	c := resources.NewCollector()
	result, err := c.GetNamespaces()
	if err != nil {
		t.Fatalf("get_namespaces failed: %v", err)
	}
	mustJSON(t, "get_namespaces", result)
}

func TestSmoke_Linux_GetCgroups(t *testing.T) {
	c := resources.NewCollector()
	result, err := c.GetCgroups()
	if err != nil {
		t.Fatalf("get_cgroups failed: %v", err)
	}
	mustJSON(t, "get_cgroups", result)
}

func TestSmoke_Linux_GetCapabilities(t *testing.T) {
	c := resources.NewCollector()
	result, err := c.GetCapabilities(0)
	if err != nil {
		t.Fatalf("get_capabilities failed: %v", err)
	}
	mustJSON(t, "get_capabilities", result)
}

func TestSmoke_Linux_GetVMInfo(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetVMInfo()
	if err != nil {
		t.Fatalf("get_vm_info failed: %v", err)
	}
	mustJSON(t, "get_vm_info", result)
}

func TestSmoke_Linux_GetTimezone(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetTimezone()
	if err != nil {
		t.Fatalf("get_timezone failed: %v", err)
	}
	mustJSON(t, "get_timezone", result)
}

func TestSmoke_Linux_GetNTPStatus(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetNTPStatus()
	if err != nil {
		t.Logf("get_ntp_status returned error (NTP may not be configured): %v", err)
		return
	}
	mustJSON(t, "get_ntp_status", result)
}

func TestSmoke_Linux_GetCoreDumps(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetCoreDumps()
	if err != nil {
		t.Fatalf("get_core_dumps failed: %v", err)
	}
	mustJSON(t, "get_core_dumps", result)
}

func TestSmoke_Linux_GetPowerState(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetPowerState()
	if err != nil {
		t.Fatalf("get_power_state failed: %v", err)
	}
	mustJSON(t, "get_power_state", result)
}

func TestSmoke_Linux_GetNUMATopology(t *testing.T) {
	c := state.NewCollector()
	result, err := c.GetNUMATopology()
	if err != nil {
		t.Logf("get_numa_topology returned error (NUMA may not be available): %v", err)
		return
	}
	mustJSON(t, "get_numa_topology", result)
}

// =============================================================================
// Phase 1.7: Software Inventory (31 queries)
// =============================================================================

func TestSmoke_Linux_GetPathExecutables(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("get_path_executables failed: %v", err)
	}
	mustJSON(t, "get_path_executables", result)
}

func TestSmoke_Linux_GetSystemPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("get_system_packages failed: %v", err)
	}
	mustJSON(t, "get_system_packages", result)
}

func TestSmoke_Linux_GetPythonPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetPythonPackages()
	if err != nil {
		t.Logf("get_python_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_python_packages", result)
}

func TestSmoke_Linux_GetNodePackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetNodePackages()
	if err != nil {
		t.Logf("get_node_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_node_packages", result)
}

func TestSmoke_Linux_GetGoModules(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetGoModules()
	if err != nil {
		t.Logf("get_go_modules returned error: %v", err)
		return
	}
	mustJSON(t, "get_go_modules", result)
}

func TestSmoke_Linux_GetRustPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetRustPackages()
	if err != nil {
		t.Logf("get_rust_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_rust_packages", result)
}

func TestSmoke_Linux_GetRubyGems(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetRubyGems()
	if err != nil {
		t.Logf("get_ruby_gems returned error: %v", err)
		return
	}
	mustJSON(t, "get_ruby_gems", result)
}

func TestSmoke_Linux_GetMavenPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetMavenPackages()
	if err != nil {
		t.Logf("get_maven_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_maven_packages", result)
}

func TestSmoke_Linux_GetPHPPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetPHPPackages()
	if err != nil {
		t.Logf("get_php_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_php_packages", result)
}

func TestSmoke_Linux_GetDotnetPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetDotnetPackages()
	if err != nil {
		t.Logf("get_dotnet_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_dotnet_packages", result)
}

func TestSmoke_Linux_GetSnapPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetSnapPackages()
	if err != nil {
		t.Logf("get_snap_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_snap_packages", result)
}

func TestSmoke_Linux_GetFlatpakPackages(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetFlatpakPackages()
	if err != nil {
		t.Logf("get_flatpak_packages returned error: %v", err)
		return
	}
	mustJSON(t, "get_flatpak_packages", result)
}

func TestSmoke_Linux_GetSBOMCycloneDX(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetSBOMCycloneDX()
	if err != nil {
		t.Fatalf("get_sbom_cyclonedx failed: %v", err)
	}
	mustJSON(t, "get_sbom_cyclonedx", result)
}

func TestSmoke_Linux_GetSBOMSPDX(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetSBOMSPDX()
	if err != nil {
		t.Fatalf("get_sbom_spdx failed: %v", err)
	}
	mustJSON(t, "get_sbom_spdx", result)
}

func TestSmoke_Linux_GetDockerImages(t *testing.T) {
	c := container.NewCollector()
	result, err := c.GetDockerImages()
	if err != nil {
		t.Logf("get_docker_images returned error (Docker may not be available): %v", err)
		return
	}
	mustJSON(t, "get_docker_images", result)
}

func TestSmoke_Linux_GetDockerContainers(t *testing.T) {
	c := container.NewCollector()
	result, err := c.GetDockerContainers()
	if err != nil {
		t.Logf("get_docker_containers returned error (Docker may not be available): %v", err)
		return
	}
	mustJSON(t, "get_docker_containers", result)
}

func TestSmoke_Linux_GetImageHistory(t *testing.T) {
	c := container.NewCollector()
	result, err := c.GetImageHistory("alpine:latest")
	if err != nil {
		t.Logf("get_docker_image_history returned error (Docker/image may not be available): %v", err)
		return
	}
	mustJSON(t, "get_docker_image_history", result)
}

func TestSmoke_Linux_GetNpmLock(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetNpmLock("/nonexistent/package-lock.json")
	if err != nil {
		t.Logf("get_npm_lock returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_npm_lock", result)
}

func TestSmoke_Linux_GetPipLock(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetPipLock("/nonexistent/requirements.txt")
	if err != nil {
		t.Logf("get_pip_lock returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_pip_lock", result)
}

func TestSmoke_Linux_GetCargoLock(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetCargoLock("/nonexistent/Cargo.lock")
	if err != nil {
		t.Logf("get_cargo_lock returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_cargo_lock", result)
}

func TestSmoke_Linux_GetGoSum(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetGoSum("/nonexistent/go.sum")
	if err != nil {
		t.Logf("get_go_sum returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_go_sum", result)
}

func TestSmoke_Linux_GetGemfileLock(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetGemfileLock("/nonexistent/Gemfile.lock")
	if err != nil {
		t.Logf("get_gemfile_lock returned error (expected for nonexistent file): %v", err)
		return
	}
	mustJSON(t, "get_gemfile_lock", result)
}

// Vulnerability queries - these hit external APIs so we just verify they don't panic
func TestSmoke_Linux_GetVulnerabilitiesOSV(t *testing.T) {
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

func TestSmoke_Linux_GetVulnerabilitiesDebian(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping external API call in short mode")
	}
	c := software.NewCollector()
	result, err := c.GetVulnerabilitiesDebian()
	if err != nil {
		t.Logf("get_vulnerabilities_debian returned error: %v", err)
		return
	}
	mustJSON(t, "get_vulnerabilities_debian", result)
}

func TestSmoke_Linux_GetVulnerabilitiesNVD(t *testing.T) {
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

func TestSmoke_Linux_GetApplications(t *testing.T) {
	c := software.NewCollector()
	result, err := c.GetApplications()
	if err != nil {
		t.Fatalf("get_applications failed: %v", err)
	}
	mustJSON(t, "get_applications", result)
}

func TestSmoke_Linux_GetAppConfig(t *testing.T) {
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

func TestSmoke_Linux_GetOSInfo(t *testing.T) {
	c := osinfo.NewCollector()
	result, err := c.GetOSInfo()
	if err != nil {
		t.Fatalf("get_os_info failed: %v", err)
	}
	mustJSON(t, "get_os_info", result)
}

func TestSmoke_Linux_GetSystemProfile(t *testing.T) {
	c := osinfo.NewCollector()
	result, err := c.GetSystemProfile()
	if err != nil {
		t.Fatalf("get_system_profile failed: %v", err)
	}
	mustJSON(t, "get_system_profile", result)
}

func TestSmoke_Linux_GetServiceManagerInfo(t *testing.T) {
	c := osinfo.NewCollector()
	result, err := c.GetServiceManagerInfo()
	if err != nil {
		t.Fatalf("get_service_manager_info failed: %v", err)
	}
	mustJSON(t, "get_service_manager_info", result)
}

func TestSmoke_Linux_GetCloudEnvironment(t *testing.T) {
	c := osinfo.NewCollector()
	result, err := c.GetCloudEnvironment()
	if err != nil {
		t.Fatalf("get_cloud_environment failed: %v", err)
	}
	mustJSON(t, "get_cloud_environment", result)
}

func TestSmoke_Linux_GetLanguageRuntimes(t *testing.T) {
	c := runtimes.NewCollector()
	result, err := c.GetLanguageRuntimes()
	if err != nil {
		t.Fatalf("get_language_runtime_versions failed: %v", err)
	}
	mustJSON(t, "get_language_runtime_versions", result)
}

func TestSmoke_Linux_GetRecentReboots(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetRecentReboots(10)
	if err != nil {
		t.Fatalf("get_recent_reboots failed: %v", err)
	}
	mustJSON(t, "get_recent_reboots", result)
}

func TestSmoke_Linux_GetRecentServiceFailures(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetRecentServiceFailures(24)
	if err != nil {
		t.Fatalf("get_recent_service_failures failed: %v", err)
	}
	mustJSON(t, "get_recent_service_failures", result)
}

func TestSmoke_Linux_GetRecentKernelEvents(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetRecentKernelEvents(24)
	if err != nil {
		t.Fatalf("get_recent_kernel_events failed: %v", err)
	}
	mustJSON(t, "get_recent_kernel_events", result)
}

func TestSmoke_Linux_GetRecentCriticalEvents(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetRecentCriticalEvents(24)
	if err != nil {
		t.Fatalf("get_recent_critical_events failed: %v", err)
	}
	mustJSON(t, "get_recent_critical_events", result)
}

func TestSmoke_Linux_GetRecentResourceIncidents(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetRecentResourceIncidents(24)
	if err != nil {
		t.Fatalf("get_recent_resource_incidents failed: %v", err)
	}
	mustJSON(t, "get_recent_resource_incidents", result)
}

func TestSmoke_Linux_GetRecentConfigChanges(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetRecentConfigChanges(24)
	if err != nil {
		t.Fatalf("get_recent_config_changes failed: %v", err)
	}
	mustJSON(t, "get_recent_config_changes", result)
}

func TestSmoke_Linux_GetFailedUnits(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetFailedUnits()
	if err != nil {
		t.Fatalf("get_failed_units failed: %v", err)
	}
	mustJSON(t, "get_failed_units", result)
}

func TestSmoke_Linux_GetTimerJobs(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetTimerJobs()
	if err != nil {
		t.Fatalf("get_timer_jobs failed: %v", err)
	}
	mustJSON(t, "get_timer_jobs", result)
}

func TestSmoke_Linux_GetServiceLogView(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetServiceLogView("sshd", 10)
	if err != nil {
		t.Logf("get_service_log_view returned error: %v", err)
		return
	}
	mustJSON(t, "get_service_log_view", result)
}

func TestSmoke_Linux_GetSecurityBasics(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetSecurityBasics()
	if err != nil {
		t.Fatalf("get_security_basics failed: %v", err)
	}
	mustJSON(t, "get_security_basics", result)
}

func TestSmoke_Linux_GetAuthFailureSummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetAuthFailureSummary(24)
	if err != nil {
		t.Logf("get_auth_failure_summary returned error: %v", err)
		return
	}
	mustJSON(t, "get_auth_failure_summary", result)
}

func TestSmoke_Linux_GetAdminAccountSummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetAdminAccountSummary()
	if err != nil {
		t.Fatalf("get_admin_account_summary failed: %v", err)
	}
	mustJSON(t, "get_admin_account_summary", result)
}

func TestSmoke_Linux_GetExposedServicesSummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetExposedServicesSummary()
	if err != nil {
		t.Fatalf("get_exposed_services_summary failed: %v", err)
	}
	mustJSON(t, "get_exposed_services_summary", result)
}

func TestSmoke_Linux_GetSSHSecuritySummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetSSHSecuritySummary()
	if err != nil {
		t.Fatalf("get_ssh_security_summary failed: %v", err)
	}
	mustJSON(t, "get_ssh_security_summary", result)
}

func TestSmoke_Linux_GetResourceLimits(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetResourceLimits()
	if err != nil {
		t.Fatalf("get_resource_limits failed: %v", err)
	}
	mustJSON(t, "get_resource_limits", result)
}

func TestSmoke_Linux_GetRecentlyInstalledSoftware(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetRecentlyInstalledSoftware(50)
	if err != nil {
		t.Fatalf("get_recently_installed_software failed: %v", err)
	}
	mustJSON(t, "get_recently_installed_software", result)
}

func TestSmoke_Linux_GetFSHealthSummary(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetFSHealthSummary()
	if err != nil {
		t.Fatalf("get_fs_health_summary failed: %v", err)
	}
	mustJSON(t, "get_fs_health_summary", result)
}

func TestSmoke_Linux_GetDeploymentEvents(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetDeploymentEvents(24)
	if err != nil {
		t.Fatalf("get_deployment_events failed: %v", err)
	}
	mustJSON(t, "get_deployment_events", result)
}

func TestSmoke_Linux_GetIncidentTriageSnapshot(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetIncidentTriageSnapshot()
	if err != nil {
		t.Fatalf("get_incident_triage_snapshot failed: %v", err)
	}
	mustJSON(t, "get_incident_triage_snapshot", result)
}

func TestSmoke_Linux_GetSecurityPostureSnapshot(t *testing.T) {
	c := triage.NewCollector()
	result, err := c.GetSecurityPostureSnapshot()
	if err != nil {
		t.Fatalf("get_security_posture_snapshot failed: %v", err)
	}
	mustJSON(t, "get_security_posture_snapshot", result)
}
