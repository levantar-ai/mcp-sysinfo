//go:build linux

package osinfo

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getOSInfo retrieves OS information on Linux.
func (c *Collector) getOSInfo() (*types.OSInfoResult, error) {
	result := &types.OSInfoResult{
		Platform:  "linux",
		Timestamp: time.Now(),
	}

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		result.Hostname = hostname
	}

	// Parse /etc/os-release for distro info
	// #nosec G304 -- reading from known path
	if f, err := os.Open("/etc/os-release"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := parts[0]
			value := strings.Trim(parts[1], `"`)

			switch key {
			case "NAME":
				result.Name = value
			case "VERSION_ID":
				result.Version = value
			case "VERSION_CODENAME":
				result.Codename = value
			case "ID":
				result.PlatformFamily = value
			case "BUILD_ID":
				result.Build = value
			case "PRETTY_NAME":
				result.PlatformVersion = value
			}
		}
	}

	// Fallback to /etc/lsb-release for older distros
	if result.Name == "" {
		// #nosec G304 -- reading from known path
		if f, err := os.Open("/etc/lsb-release"); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := parts[0]
				value := strings.Trim(parts[1], `"`)

				switch key {
				case "DISTRIB_ID":
					result.Name = value
				case "DISTRIB_RELEASE":
					result.Version = value
				case "DISTRIB_CODENAME":
					result.Codename = value
				case "DISTRIB_DESCRIPTION":
					result.PlatformVersion = value
				}
			}
		}
	}

	// Get kernel info via uname
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		result.KernelVersion = int8ArrayToString(uname.Release[:])
		result.KernelArch = int8ArrayToString(uname.Machine[:])
	}

	// Detect boot mode (UEFI vs BIOS)
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		result.BootMode = "UEFI"
	} else {
		result.BootMode = "BIOS"
	}

	return result, nil
}

// int8ArrayToString converts a null-terminated int8 array to string.
func int8ArrayToString(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

// getSystemProfile retrieves system profile on Linux.
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

	// Read /proc/cpuinfo for model and core counts
	// #nosec G304 -- reading from procfs
	if f, err := os.Open("/proc/cpuinfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		physicalIDs := make(map[string]bool)
		coreCount := 0

		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "model name":
				if summary.Model == "" {
					summary.Model = value
				}
			case "processor":
				coreCount++
			case "physical id":
				physicalIDs[value] = true
			case "cpu MHz":
				if summary.FrequencyMHz == 0 {
					summary.FrequencyMHz, _ = strconv.ParseFloat(value, 64)
				}
			}
		}

		summary.LogicalCores = coreCount
		if len(physicalIDs) > 0 {
			summary.Cores = len(physicalIDs)
		} else {
			summary.Cores = coreCount
		}
	}

	// Read /proc/stat for CPU usage
	// #nosec G304 -- reading from procfs
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "cpu ") {
				fields := strings.Fields(line)
				if len(fields) >= 5 {
					user, _ := strconv.ParseFloat(fields[1], 64)
					nice, _ := strconv.ParseFloat(fields[2], 64)
					system, _ := strconv.ParseFloat(fields[3], 64)
					idle, _ := strconv.ParseFloat(fields[4], 64)

					total := user + nice + system + idle
					if total > 0 {
						summary.UsagePercent = ((user + nice + system) / total) * 100
					}
				}
				break
			}
		}
	}

	return summary
}

func getMemorySummary() types.MemorySummary {
	summary := types.MemorySummary{}

	// Read /proc/meminfo
	// #nosec G304 -- reading from procfs
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)

		var memTotal, memAvailable, memFree, buffers, cached uint64
		var swapTotal, swapFree uint64

		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			key := strings.TrimSuffix(fields[0], ":")
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			val *= 1024 // Convert from KB to bytes

			switch key {
			case "MemTotal":
				memTotal = val
			case "MemAvailable":
				memAvailable = val
			case "MemFree":
				memFree = val
			case "Buffers":
				buffers = val
			case "Cached":
				cached = val
			case "SwapTotal":
				swapTotal = val
			case "SwapFree":
				swapFree = val
			}
		}

		// Calculate values
		if memAvailable == 0 {
			// Fallback for older kernels
			memAvailable = memFree + buffers + cached
		}
		memUsed := memTotal - memAvailable

		bytesToGB := func(b uint64) float64 {
			return float64(b) / (1024 * 1024 * 1024)
		}

		summary.TotalGB = bytesToGB(memTotal)
		summary.UsedGB = bytesToGB(memUsed)
		summary.AvailableGB = bytesToGB(memAvailable)
		if memTotal > 0 {
			summary.UsagePercent = (float64(memUsed) / float64(memTotal)) * 100
		}

		summary.SwapTotalGB = bytesToGB(swapTotal)
		summary.SwapUsedGB = bytesToGB(swapTotal - swapFree)
	}

	return summary
}

func getDiskSummary() types.DiskSummary {
	summary := types.DiskSummary{}

	var totalBytes, usedBytes, freeBytes uint64
	partitionCount := 0

	// Read /proc/mounts and get statfs for each
	// #nosec G304 -- reading from procfs
	if f, err := os.Open("/proc/mounts"); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		seenDevices := make(map[string]bool)

		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 {
				continue
			}

			device := fields[0]
			mountpoint := fields[1]

			// Skip virtual filesystems
			if !strings.HasPrefix(device, "/dev/") {
				continue
			}

			// Skip duplicates
			if seenDevices[device] {
				continue
			}
			seenDevices[device] = true

			var stat syscall.Statfs_t
			if err := syscall.Statfs(mountpoint, &stat); err == nil {
				// #nosec G115 -- Bsize is always positive for valid filesystems
				total := stat.Blocks * uint64(stat.Bsize)
				// #nosec G115 -- Bsize is always positive for valid filesystems
				free := stat.Bfree * uint64(stat.Bsize)
				used := total - free

				totalBytes += total
				usedBytes += used
				freeBytes += free
				partitionCount++
			}
		}
	}

	bytesToGB := func(b uint64) float64 {
		return float64(b) / (1024 * 1024 * 1024)
	}

	summary.TotalGB = bytesToGB(totalBytes)
	summary.UsedGB = bytesToGB(usedBytes)
	summary.FreeGB = bytesToGB(freeBytes)
	summary.Partitions = partitionCount
	if totalBytes > 0 {
		summary.UsagePercent = (float64(usedBytes) / float64(totalBytes)) * 100
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

// getServiceManagerInfo retrieves service manager info on Linux.
func (c *Collector) getServiceManagerInfo() (*types.ServiceManagerInfoResult, error) {
	result := &types.ServiceManagerInfoResult{
		Timestamp: time.Now(),
	}

	// Check for systemd (most common)
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("systemctl", "--version")
	if output, err := cmd.Output(); err == nil {
		result.Type = "systemd"
		result.Running = true

		// Parse version
		lines := strings.Split(string(output), "\n")
		if len(lines) > 0 {
			parts := strings.Fields(lines[0])
			if len(parts) >= 2 {
				result.Version = parts[1]
			}
		}

		// Get systemd PID (always PID 1 on systemd systems)
		result.PID = 1

		// Get default target
		// #nosec G204 -- no user input
		cmd = cmdexec.Command("systemctl", "get-default")
		if output, err := cmd.Output(); err == nil {
			result.DefaultTarget = strings.TrimSpace(string(output))
		}

		// Get unit counts
		// #nosec G204 -- no user input
		cmd = cmdexec.Command("systemctl", "list-units", "--all", "--no-legend", "--no-pager")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				result.TotalUnits++

				fields := strings.Fields(line)
				if len(fields) >= 3 {
					// Fields: UNIT LOAD ACTIVE SUB DESCRIPTION...
					activeState := fields[2]
					switch activeState {
					case "active":
						result.ActiveUnits++
					case "failed":
						result.FailedUnits++
					}
					if fields[1] == "loaded" {
						result.LoadedUnits++
					}
				}
			}
		}

		// Get current boot target
		// #nosec G204 -- no user input
		cmd = cmdexec.Command("systemctl", "list-units", "--type=target", "--state=active", "--no-legend", "--no-pager")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "graphical.target") {
					result.BootTarget = "graphical.target"
					break
				} else if strings.Contains(line, "multi-user.target") {
					result.BootTarget = "multi-user.target"
				}
			}
		}

		return result, nil
	}

	// Check for SysVinit or OpenRC
	if _, err := os.Stat("/etc/init.d"); err == nil {
		result.Type = "sysvinit"
		result.Running = true
		result.PID = 1
	}

	return result, nil
}

// getCloudEnvironment detects cloud provider on Linux.
func (c *Collector) getCloudEnvironment() (*types.CloudEnvironmentResult, error) {
	result := &types.CloudEnvironmentResult{
		Timestamp: time.Now(),
	}

	// Check DMI info first for quick detection
	// #nosec G304 -- reading from sysfs
	if productName, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
		product := strings.ToLower(strings.TrimSpace(string(productName)))

		if strings.Contains(product, "amazon ec2") || strings.Contains(product, "hvm domu") {
			result.IsCloud = true
			result.Provider = "aws"
			result.DetectionMethod = "dmi"
			c.fetchAWSMetadata(result)
			return result, nil
		}
		if strings.Contains(product, "google compute") {
			result.IsCloud = true
			result.Provider = "gcp"
			result.DetectionMethod = "dmi"
			c.fetchGCPMetadata(result)
			return result, nil
		}
		if strings.Contains(product, "virtual machine") {
			// Check manufacturer for Azure
			// #nosec G304 -- reading from sysfs
			if mfg, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
				if strings.Contains(strings.ToLower(string(mfg)), "microsoft") {
					result.IsCloud = true
					result.Provider = "azure"
					result.DetectionMethod = "dmi"
					c.fetchAzureMetadata(result)
					return result, nil
				}
			}
		}
	}

	// #nosec G304 -- reading from sysfs
	if chassisAssetTag, err := os.ReadFile("/sys/class/dmi/id/chassis_asset_tag"); err == nil {
		tag := strings.TrimSpace(string(chassisAssetTag))
		if strings.Contains(tag, "OracleCloud") {
			result.IsCloud = true
			result.Provider = "oci"
			result.DetectionMethod = "dmi"
			return result, nil
		}
		if strings.Contains(tag, "digitalocean") || tag == "Droplet" {
			result.IsCloud = true
			result.Provider = "digitalocean"
			result.DetectionMethod = "dmi"
			return result, nil
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

	// Try IMDSv2 first
	ctx := context.Background()
	tokenReq, _ := http.NewRequestWithContext(ctx, "PUT", "http://169.254.169.254/latest/api/token", nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		return false
	}
	defer tokenResp.Body.Close()

	token, _ := io.ReadAll(tokenResp.Body)

	// Fetch instance identity document
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

	// Get token for IMDSv2
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
				_ = resp.Body.Close()
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
	result.ImageID = fetchMeta("ami-id")
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
	client := &http.Client{Timeout: 2 * time.Second}
	ctx := context.Background()

	fetchMeta := func(path string) string {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://metadata.google.internal/computeMetadata/v1/"+path, nil)
		req.Header.Set("Metadata-Flavor", "Google")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				_ = resp.Body.Close()
			}
			return ""
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return string(body)
	}

	zone := fetchMeta("instance/zone")
	// Zone format: projects/PROJECT_NUM/zones/ZONE
	if parts := strings.Split(zone, "/"); len(parts) > 0 {
		result.Zone = parts[len(parts)-1]
		// Extract region from zone (e.g., us-central1-a -> us-central1)
		if zoneParts := strings.Split(result.Zone, "-"); len(zoneParts) >= 2 {
			result.Region = strings.Join(zoneParts[:len(zoneParts)-1], "-")
		}
	}

	result.InstanceID = filepath.Base(fetchMeta("instance/id"))
	result.InstanceType = fetchMeta("instance/machine-type")
	if parts := strings.Split(result.InstanceType, "/"); len(parts) > 0 {
		result.InstanceType = parts[len(parts)-1]
	}

	// Get network interfaces
	result.PrivateIP = fetchMeta("instance/network-interfaces/0/ip")
	result.PublicIP = fetchMeta("instance/network-interfaces/0/access-configs/0/external-ip")
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
				_ = resp.Body.Close()
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
	result.Zone = fetchMeta("compute/zone")
	result.PrivateIP = fetchMeta("network/interface/0/ipv4/ipAddress/0/privateIpAddress")
	result.PublicIP = fetchMeta("network/interface/0/ipv4/ipAddress/0/publicIpAddress")
}
