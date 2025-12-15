//go:build darwin

package osinfo

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getOSInfo retrieves OS information on macOS.
func (c *Collector) getOSInfo() (*types.OSInfoResult, error) {
	result := &types.OSInfoResult{
		Platform:       "darwin",
		PlatformFamily: "darwin",
		Timestamp:      time.Now(),
	}

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		result.Hostname = hostname
	}

	// Use sw_vers to get macOS version info
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("sw_vers")
	if output, err := cmd.Output(); err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "ProductName":
				result.Name = value
			case "ProductVersion":
				result.Version = value
				result.PlatformVersion = value
			case "BuildVersion":
				result.Build = value
			}
		}
	}

	// Map version to codename
	if result.Version != "" {
		parts := strings.Split(result.Version, ".")
		if len(parts) >= 1 {
			major, _ := strconv.Atoi(parts[0])
			codenames := map[int]string{
				15: "Sequoia",
				14: "Sonoma",
				13: "Ventura",
				12: "Monterey",
				11: "Big Sur",
			}
			if name, ok := codenames[major]; ok {
				result.Codename = name
			}
		}
	}

	// Get kernel info via uname command
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command("uname", "-r").Output(); err == nil {
		result.KernelVersion = strings.TrimSpace(string(output))
	}
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command("uname", "-m").Output(); err == nil {
		result.KernelArch = strings.TrimSpace(string(output))
	}

	// macOS always uses UEFI on modern Macs
	result.BootMode = "UEFI"

	return result, nil
}

// getSystemProfile retrieves system profile on macOS.
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

	// Use sysctl to get CPU info
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("sysctl", "-n", "machdep.cpu.brand_string")
	if output, err := cmd.Output(); err == nil {
		summary.Model = strings.TrimSpace(string(output))
	}

	// #nosec G204 -- no user input
	cmd = cmdexec.Command("sysctl", "-n", "hw.physicalcpu")
	if output, err := cmd.Output(); err == nil {
		summary.Cores, _ = strconv.Atoi(strings.TrimSpace(string(output)))
	}

	// #nosec G204 -- no user input
	cmd = cmdexec.Command("sysctl", "-n", "hw.logicalcpu")
	if output, err := cmd.Output(); err == nil {
		summary.LogicalCores, _ = strconv.Atoi(strings.TrimSpace(string(output)))
	}

	// Get CPU frequency
	// #nosec G204 -- no user input
	cmd = cmdexec.Command("sysctl", "-n", "hw.cpufrequency")
	if output, err := cmd.Output(); err == nil {
		freq, _ := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
		summary.FrequencyMHz = freq / 1000000
	}

	// Get CPU usage from top
	// #nosec G204 -- no user input
	cmd = cmdexec.Command("top", "-l", "1", "-n", "0", "-s", "0")
	if output, err := cmd.Output(); err == nil {
		re := regexp.MustCompile(`CPU usage: ([\d.]+)% user, ([\d.]+)% sys`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 3 {
			user, _ := strconv.ParseFloat(matches[1], 64)
			sys, _ := strconv.ParseFloat(matches[2], 64)
			summary.UsagePercent = user + sys
		}
	}

	return summary
}

func getMemorySummary() types.MemorySummary {
	summary := types.MemorySummary{}

	bytesToGB := func(b uint64) float64 {
		return float64(b) / (1024 * 1024 * 1024)
	}

	// Get total memory
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("sysctl", "-n", "hw.memsize")
	if output, err := cmd.Output(); err == nil {
		total, _ := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
		summary.TotalGB = bytesToGB(total)
	}

	// Get memory usage from vm_stat
	// #nosec G204 -- no user input
	cmd = cmdexec.Command("vm_stat")
	if output, err := cmd.Output(); err == nil {
		pageSize := uint64(4096)
		var active, inactive, wired, free uint64

		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "page size of") {
				re := regexp.MustCompile(`(\d+) bytes`)
				if matches := re.FindStringSubmatch(line); len(matches) >= 2 {
					pageSize, _ = strconv.ParseUint(matches[1], 10, 64)
				}
				continue
			}

			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}

			value := strings.TrimSpace(strings.TrimSuffix(parts[1], "."))
			pages, _ := strconv.ParseUint(value, 10, 64)
			bytes := pages * pageSize

			switch {
			case strings.Contains(parts[0], "Pages active"):
				active = bytes
			case strings.Contains(parts[0], "Pages inactive"):
				inactive = bytes
			case strings.Contains(parts[0], "Pages wired"):
				wired = bytes
			case strings.Contains(parts[0], "Pages free"):
				free = bytes
			}
		}

		used := active + inactive + wired
		available := free + inactive
		totalBytes := used + free

		summary.UsedGB = bytesToGB(used)
		summary.AvailableGB = bytesToGB(available)
		if totalBytes > 0 {
			summary.UsagePercent = (float64(used) / float64(totalBytes)) * 100
		}
	}

	// Get swap info
	// #nosec G204 -- no user input
	cmd = cmdexec.Command("sysctl", "-n", "vm.swapusage")
	if output, err := cmd.Output(); err == nil {
		// Format: "total = 2048.00M  used = 512.00M  free = 1536.00M"
		re := regexp.MustCompile(`total = ([\d.]+)M.*used = ([\d.]+)M`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 3 {
			total, _ := strconv.ParseFloat(matches[1], 64)
			used, _ := strconv.ParseFloat(matches[2], 64)
			summary.SwapTotalGB = total / 1024
			summary.SwapUsedGB = used / 1024
		}
	}

	return summary
}

func getDiskSummary() types.DiskSummary {
	summary := types.DiskSummary{}

	// Use df to get disk usage
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("df", "-k")
	if output, err := cmd.Output(); err == nil {
		var totalKB, usedKB, freeKB uint64
		seenDevices := make(map[string]bool)

		for _, line := range strings.Split(string(output), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}

			device := fields[0]
			mountpoint := fields[8] // On macOS, mountpoint is the 9th field

			// Skip virtual filesystems
			if !strings.HasPrefix(device, "/dev/") {
				continue
			}

			// Skip duplicates
			if seenDevices[device] {
				continue
			}
			seenDevices[device] = true

			total, _ := strconv.ParseUint(fields[1], 10, 64)
			used, _ := strconv.ParseUint(fields[2], 10, 64)
			free, _ := strconv.ParseUint(fields[3], 10, 64)

			totalKB += total
			usedKB += used
			freeKB += free

			_ = mountpoint
			summary.Partitions++
		}

		kbToGB := func(kb uint64) float64 {
			return float64(kb) / (1024 * 1024)
		}

		summary.TotalGB = kbToGB(totalKB)
		summary.UsedGB = kbToGB(usedKB)
		summary.FreeGB = kbToGB(freeKB)
		if totalKB > 0 {
			summary.UsagePercent = (float64(usedKB) / float64(totalKB)) * 100
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

// getServiceManagerInfo retrieves service manager info on macOS.
func (c *Collector) getServiceManagerInfo() (*types.ServiceManagerInfoResult, error) {
	result := &types.ServiceManagerInfoResult{
		Type:      "launchd",
		Running:   true,
		PID:       1, // launchd is always PID 1
		Timestamp: time.Now(),
	}

	// Get launchd version
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("launchctl", "version")
	if output, err := cmd.Output(); err == nil {
		result.Version = strings.TrimSpace(string(output))
	}

	// Count services
	// #nosec G204 -- no user input
	cmd = cmdexec.Command("launchctl", "list")
	if output, err := cmd.Output(); err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines[1:] { // Skip header
			if line == "" {
				continue
			}
			result.TotalUnits++

			fields := strings.Fields(line)
			if len(fields) >= 2 {
				// First field is PID (or -), second is status code
				if fields[0] != "-" {
					result.ActiveUnits++
				}
				// Non-zero status indicates failure
				if status, err := strconv.Atoi(fields[1]); err == nil && status != 0 {
					result.FailedUnits++
				}
			}
		}
		result.LoadedUnits = result.TotalUnits
	}

	return result, nil
}

// getCloudEnvironment detects cloud provider on macOS.
func (c *Collector) getCloudEnvironment() (*types.CloudEnvironmentResult, error) {
	result := &types.CloudEnvironmentResult{
		Timestamp: time.Now(),
	}

	// macOS is typically not run in cloud environments directly
	// but can be in EC2 Mac instances
	if c.probeAWSMetadata(result) {
		return result, nil
	}

	// Check for virtualization (Parallels, VMware, etc. on non-cloud)
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("sysctl", "-n", "machdep.cpu.brand_string")
	if output, err := cmd.Output(); err == nil {
		brand := strings.ToLower(string(output))
		if strings.Contains(brand, "virtual") {
			result.IsCloud = false // VM but not cloud
		}
	}

	return result, nil
}

// probeAWSMetadata probes AWS metadata endpoint.
func (c *Collector) probeAWSMetadata(result *types.CloudEnvironmentResult) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	// Try IMDSv2
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
		return true
	}

	return false
}
