//go:build windows

package osinfo

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getOSInfo retrieves OS information on Windows.
func (c *Collector) getOSInfo() (*types.OSInfoResult, error) {
	result := &types.OSInfoResult{
		Platform:       "windows",
		PlatformFamily: "windows",
		Timestamp:      time.Now(),
	}

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		result.Hostname = hostname
	}

	// Use PowerShell to get OS info
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Csv -NoTypeInformation")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			// Parse CSV (header on line 0, data on line 1)
			values := parseCSVLine(lines[1])
			if len(values) >= 4 {
				result.Name = strings.Trim(values[0], `"`)
				result.PlatformVersion = strings.Trim(values[1], `"`)
				result.Build = strings.Trim(values[2], `"`)
				arch := strings.Trim(values[3], `"`)
				if strings.Contains(arch, "64") {
					result.KernelArch = "x86_64"
				} else {
					result.KernelArch = "x86"
				}
			}
		}
	}

	// Parse version from PlatformVersion (e.g., "10.0.19045")
	if result.PlatformVersion != "" {
		parts := strings.Split(result.PlatformVersion, ".")
		if len(parts) >= 2 {
			result.Version = parts[0] + "." + parts[1]
		}
		result.KernelVersion = result.PlatformVersion
	}

	// Detect boot mode
	// #nosec G204 -- no user input
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command",
		"if (Test-Path 'HKLM:\\System\\CurrentControlSet\\Control\\SecureBoot\\State') { 'UEFI' } else { 'BIOS' }")
	if output, err := cmd.Output(); err == nil {
		bootMode := strings.TrimSpace(string(output))
		if bootMode == "UEFI" {
			result.BootMode = "UEFI"
		} else {
			result.BootMode = "BIOS"
		}
	}

	return result, nil
}

// parseCSVLine parses a simple CSV line.
func parseCSVLine(line string) []string {
	var result []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ',' && !inQuotes:
			result = append(result, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		result = append(result, current.String())
	}

	return result
}

// getSystemProfile retrieves system profile on Windows.
func (c *Collector) getSystemProfile() (*types.SystemProfileResult, error) {
	result := &types.SystemProfileResult{
		Timestamp: time.Now(),
	}

	// Get OS info
	osInfo, err := c.getOSInfo()
	if err == nil {
		result.OS = *osInfo
	}

	// Get CPU summary
	result.CPU = getCPUSummary()

	// Get memory summary
	result.Memory = getMemorySummary()

	// Get disk summary
	result.Disk = getDiskSummary()

	// Get network summary
	result.Network = getNetworkSummary()

	return result, nil
}

func getCPUSummary() types.CPUSummary {
	summary := types.CPUSummary{}

	// Get CPU info via PowerShell
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, LoadPercentage | ConvertTo-Csv -NoTypeInformation")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			values := parseCSVLine(lines[1])
			if len(values) >= 5 {
				summary.Model = strings.Trim(values[0], `"`)
				summary.Cores, _ = strconv.Atoi(strings.Trim(values[1], `"`))
				summary.LogicalCores, _ = strconv.Atoi(strings.Trim(values[2], `"`))
				freq, _ := strconv.ParseFloat(strings.Trim(values[3], `"`), 64)
				summary.FrequencyMHz = freq
				load, _ := strconv.ParseFloat(strings.Trim(values[4], `"`), 64)
				summary.UsagePercent = load
			}
		}
	}

	return summary
}

func getMemorySummary() types.MemorySummary {
	summary := types.MemorySummary{}

	bytesToGB := func(b uint64) float64 {
		return float64(b) / (1024 * 1024 * 1024)
	}

	// Get memory info via PowerShell
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory | ConvertTo-Csv -NoTypeInformation")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			values := parseCSVLine(lines[1])
			if len(values) >= 4 {
				totalKB, _ := strconv.ParseUint(strings.Trim(values[0], `"`), 10, 64)
				freeKB, _ := strconv.ParseUint(strings.Trim(values[1], `"`), 10, 64)
				swapTotalKB, _ := strconv.ParseUint(strings.Trim(values[2], `"`), 10, 64)
				swapFreeKB, _ := strconv.ParseUint(strings.Trim(values[3], `"`), 10, 64)

				totalBytes := totalKB * 1024
				freeBytes := freeKB * 1024
				usedBytes := totalBytes - freeBytes

				summary.TotalGB = bytesToGB(totalBytes)
				summary.AvailableGB = bytesToGB(freeBytes)
				summary.UsedGB = bytesToGB(usedBytes)
				if totalBytes > 0 {
					summary.UsagePercent = (float64(usedBytes) / float64(totalBytes)) * 100
				}

				// Swap (Virtual Memory includes physical + pagefile)
				swapOnlyTotalKB := swapTotalKB - totalKB
				swapOnlyFreeKB := swapFreeKB - freeKB
				summary.SwapTotalGB = bytesToGB(swapOnlyTotalKB * 1024)
				summary.SwapUsedGB = bytesToGB((swapOnlyTotalKB - swapOnlyFreeKB) * 1024)
			}
		}
	}

	return summary
}

func getDiskSummary() types.DiskSummary {
	summary := types.DiskSummary{}

	// Get disk info via PowerShell
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object Size, FreeSpace | ConvertTo-Csv -NoTypeInformation")
	if output, err := cmd.Output(); err == nil {
		var totalBytes, freeBytes uint64

		for _, line := range strings.Split(string(output), "\n")[1:] { // Skip header
			values := parseCSVLine(line)
			if len(values) >= 2 {
				size, _ := strconv.ParseUint(strings.Trim(values[0], `"`), 10, 64)
				free, _ := strconv.ParseUint(strings.Trim(values[1], `"`), 10, 64)

				if size > 0 {
					totalBytes += size
					freeBytes += free
					summary.Partitions++
				}
			}
		}

		usedBytes := totalBytes - freeBytes

		bytesToGB := func(b uint64) float64 {
			return float64(b) / (1024 * 1024 * 1024)
		}

		summary.TotalGB = bytesToGB(totalBytes)
		summary.UsedGB = bytesToGB(usedBytes)
		summary.FreeGB = bytesToGB(freeBytes)
		if totalBytes > 0 {
			summary.UsagePercent = (float64(usedBytes) / float64(totalBytes)) * 100
		}
	}

	return summary
}

func getNetworkSummary() types.NetworkSummary {
	summary := types.NetworkSummary{}
	summary.Hostname, _ = os.Hostname()

	interfaces, err := net.Interfaces()
	if err != nil {
		return summary
	}

	var activeIPs []string
	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		summary.Interfaces++

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}

			if ip4 := ip.To4(); ip4 != nil {
				activeIPs = append(activeIPs, ip4.String())
				if summary.PrimaryIP == "" {
					summary.PrimaryIP = ip4.String()
				}
			}
		}
	}

	summary.ActiveIPs = activeIPs
	return summary
}

// getServiceManagerInfo retrieves service manager info on Windows.
func (c *Collector) getServiceManagerInfo() (*types.ServiceManagerInfoResult, error) {
	result := &types.ServiceManagerInfoResult{
		Type:      "scm",
		Running:   true,
		Timestamp: time.Now(),
	}

	// Get service counts via PowerShell
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command",
		"$all = Get-Service; @{Total=$all.Count; Running=($all | Where-Object Status -eq 'Running').Count; Stopped=($all | Where-Object Status -eq 'Stopped').Count} | ConvertTo-Json")
	if output, err := cmd.Output(); err == nil {
		// Parse simple JSON manually
		text := string(output)
		if strings.Contains(text, "Total") {
			// Extract numbers
			for _, line := range strings.Split(text, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, `"Total"`) {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						val := strings.TrimSpace(strings.Trim(parts[1], ","))
						result.TotalUnits, _ = strconv.Atoi(val)
						result.LoadedUnits = result.TotalUnits
					}
				}
				if strings.HasPrefix(line, `"Running"`) {
					parts := strings.Split(line, ":")
					if len(parts) >= 2 {
						val := strings.TrimSpace(strings.Trim(parts[1], ","))
						result.ActiveUnits, _ = strconv.Atoi(val)
					}
				}
			}
		}
	}

	// Get Windows version for SCM version
	// #nosec G204 -- no user input
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_OperatingSystem).Version")
	if output, err := cmd.Output(); err == nil {
		result.Version = strings.TrimSpace(string(output))
	}

	return result, nil
}

// getCloudEnvironment detects cloud provider on Windows.
func (c *Collector) getCloudEnvironment() (*types.CloudEnvironmentResult, error) {
	result := &types.CloudEnvironmentResult{
		Timestamp: time.Now(),
	}

	// Check for cloud providers via DMI/SMBIOS
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).Manufacturer")
	if output, err := cmd.Output(); err == nil {
		mfg := strings.ToLower(strings.TrimSpace(string(output)))

		if strings.Contains(mfg, "amazon") || strings.Contains(mfg, "xen") {
			result.IsCloud = true
			result.Provider = "aws"
			result.DetectionMethod = "wmi"
			c.fetchAWSMetadata(result)
			return result, nil
		}
		if strings.Contains(mfg, "google") {
			result.IsCloud = true
			result.Provider = "gcp"
			result.DetectionMethod = "wmi"
			c.fetchGCPMetadata(result)
			return result, nil
		}
		if strings.Contains(mfg, "microsoft") {
			// Check product name for Azure
			// #nosec G204 -- no user input
			cmd = cmdexec.Command("powershell", "-NoProfile", "-Command",
				"(Get-CimInstance Win32_ComputerSystem).Model")
			if output, err := cmd.Output(); err == nil {
				model := strings.ToLower(strings.TrimSpace(string(output)))
				if strings.Contains(model, "virtual machine") {
					result.IsCloud = true
					result.Provider = "azure"
					result.DetectionMethod = "wmi"
					c.fetchAzureMetadata(result)
					return result, nil
				}
			}
		}
	}

	// Try metadata endpoints
	if c.probeAWSMetadata(result) {
		return result, nil
	}
	if c.probeGCPMetadata(result) {
		return result, nil
	}
	if c.probeAzureMetadata(result) {
		return result, nil
	}

	return result, nil
}

// probeAWSMetadata probes AWS metadata endpoint.
func (c *Collector) probeAWSMetadata(result *types.CloudEnvironmentResult) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	tokenReq, _ := http.NewRequestWithContext(ctx, "PUT", "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return false
	}
	defer tokenResp.Body.Close()

	token, _ := io.ReadAll(tokenResp.Body)

	idReq, _ := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/latest/dynamic/instance-identity/document", nil)
	if len(token) > 0 {
		idReq.Header.Set("X-aws-ec2-metadata-token", string(token))
	}
	idResp, err := client.Do(idReq)
	if err != nil {
		return false
	}
	defer idResp.Body.Close()

	if idResp.StatusCode == 200 {
		result.IsCloud = true
		result.Provider = "aws"
		result.DetectionMethod = "metadata"
		c.fetchAWSMetadata(result)
		return true
	}

	return false
}

// fetchAWSMetadata fetches AWS instance metadata.
func (c *Collector) fetchAWSMetadata(result *types.CloudEnvironmentResult) {
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	tokenReq, _ := http.NewRequestWithContext(ctx, "PUT", "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	var token string
	if tokenResp, err := client.Do(tokenReq); err == nil {
		defer tokenResp.Body.Close()
		tokenBytes, _ := io.ReadAll(tokenResp.Body)
		token = string(tokenBytes)
	}

	fetchMeta := func(path string) string {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/latest/meta-data/"+path, nil)
		if token != "" {
			req.Header.Set("X-aws-ec2-metadata-token", token)
		}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	result.InstanceID = fetchMeta("instance-id")
	result.InstanceType = fetchMeta("instance-type")
	result.Region = fetchMeta("placement/region")
	result.Zone = fetchMeta("placement/availability-zone")
	result.PrivateIP = fetchMeta("local-ipv4")
	result.PublicIP = fetchMeta("public-ipv4")
}

// probeGCPMetadata probes GCP metadata endpoint.
func (c *Collector) probeGCPMetadata(result *types.CloudEnvironmentResult) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://metadata.google.internal/computeMetadata/v1/instance/zone", nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.IsCloud = true
		result.Provider = "gcp"
		result.DetectionMethod = "metadata"
		c.fetchGCPMetadata(result)
		return true
	}

	return false
}

// fetchGCPMetadata fetches GCP instance metadata.
func (c *Collector) fetchGCPMetadata(result *types.CloudEnvironmentResult) {
	// Simplified - full implementation would fetch all metadata
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	fetchMeta := func(path string) string {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://metadata.google.internal/computeMetadata/v1/"+path, nil)
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	result.Zone = fetchMeta("instance/zone")
	result.InstanceID = fetchMeta("instance/id")
}

// probeAzureMetadata probes Azure metadata endpoint.
func (c *Collector) probeAzureMetadata(result *types.CloudEnvironmentResult) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	req, _ := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", nil)
	req.Header.Set("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		result.IsCloud = true
		result.Provider = "azure"
		result.DetectionMethod = "metadata"
		c.fetchAzureMetadata(result)
		return true
	}

	return false
}

// fetchAzureMetadata fetches Azure instance metadata.
func (c *Collector) fetchAzureMetadata(result *types.CloudEnvironmentResult) {
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	fetchMeta := func(path string) string {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://169.254.169.254/metadata/instance/"+path+"?api-version=2021-02-01&format=text", nil)
		req.Header.Set("Metadata", "true")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	result.InstanceID = fetchMeta("compute/vmId")
	result.InstanceType = fetchMeta("compute/vmSize")
	result.Region = fetchMeta("compute/location")
}
