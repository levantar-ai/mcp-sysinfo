//go:build linux

package state

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getVMInfo detects virtualization on Linux.
func (c *Collector) getVMInfo() (*types.VMInfoResult, error) {
	result := &types.VMInfoResult{
		VMType:    "none",
		Timestamp: time.Now(),
	}

	// Check for container first
	if containerType := detectContainer(); containerType != "" {
		result.IsVM = true
		result.VMType = "container"
		result.ContainerType = containerType
		result.DetectionMethod = "cgroup/environment"
		return result, nil
	}

	// Check DMI info
	dmiPath := "/sys/class/dmi/id"
	// #nosec G304 -- reading from sysfs
	if productName, err := os.ReadFile(filepath.Join(dmiPath, "product_name")); err == nil {
		result.ProductName = strings.TrimSpace(string(productName))
	}
	// #nosec G304 -- reading from sysfs
	if manufacturer, err := os.ReadFile(filepath.Join(dmiPath, "sys_vendor")); err == nil {
		result.Manufacturer = strings.TrimSpace(string(manufacturer))
	}

	// Detect hypervisor from DMI
	productLower := strings.ToLower(result.ProductName)
	mfgLower := strings.ToLower(result.Manufacturer)

	hypervisors := map[string]string{
		"vmware":          "vmware",
		"virtualbox":      "virtualbox",
		"kvm":             "kvm",
		"qemu":            "qemu",
		"xen":             "xen",
		"microsoft":       "hyper-v",
		"parallels":       "parallels",
		"bochs":           "bochs",
		"bhyve":           "bhyve",
		"amazon ec2":      "aws",
		"google compute":  "gcp",
		"droplet":         "digitalocean",
	}

	for keyword, hvName := range hypervisors {
		if strings.Contains(productLower, keyword) || strings.Contains(mfgLower, keyword) {
			result.IsVM = true
			result.VMType = "vm"
			result.Hypervisor = hvName
			result.DetectionMethod = "dmi"
			return result, nil
		}
	}

	// Check cpuinfo for hypervisor flag
	// #nosec G304 -- reading from procfs
	if cpuinfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		if strings.Contains(string(cpuinfo), "hypervisor") {
			result.IsVM = true
			result.VMType = "vm"
			result.DetectionMethod = "cpuinfo"

			// Try to determine hypervisor type from other flags
			cpuinfoLower := strings.ToLower(string(cpuinfo))
			if strings.Contains(cpuinfoLower, "kvm") {
				result.Hypervisor = "kvm"
			} else if strings.Contains(cpuinfoLower, "vmware") {
				result.Hypervisor = "vmware"
			}
		}
	}

	return result, nil
}

// detectContainer checks if running inside a container.
func detectContainer() string {
	// Check for Docker
	// #nosec G304 -- reading from known path
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}

	// Check cgroup for container indicators
	// #nosec G304 -- reading from procfs
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") {
			return "docker"
		}
		if strings.Contains(content, "lxc") {
			return "lxc"
		}
		if strings.Contains(content, "kubepods") {
			return "kubernetes"
		}
		if strings.Contains(content, "podman") {
			return "podman"
		}
	}

	// Check for container runtime environment variable
	if os.Getenv("container") != "" {
		return os.Getenv("container")
	}

	return ""
}

// getTimezone retrieves timezone information on Linux.
func (c *Collector) getTimezone() (*types.TimezoneInfoResult, error) {
	now := time.Now()
	zone, offset := now.Zone()

	result := &types.TimezoneInfoResult{
		Abbreviation: zone,
		UTCOffset:    formatOffset(offset),
		LocalTime:    now,
		Timestamp:    time.Now(),
	}

	// Read timezone from /etc/timezone or /etc/localtime symlink
	// #nosec G304 -- reading from known path
	if tz, err := os.ReadFile("/etc/timezone"); err == nil {
		result.Timezone = strings.TrimSpace(string(tz))
	} else if target, err := os.Readlink("/etc/localtime"); err == nil {
		// Parse timezone from symlink target (e.g., /usr/share/zoneinfo/America/New_York)
		if idx := strings.Index(target, "zoneinfo/"); idx >= 0 {
			result.Timezone = target[idx+9:]
		}
	}

	// Check for DST
	_, dstOffset := time.Date(now.Year(), time.July, 1, 12, 0, 0, 0, now.Location()).Zone()
	_, stdOffset := time.Date(now.Year(), time.January, 1, 12, 0, 0, 0, now.Location()).Zone()
	result.DSTActive = dstOffset != stdOffset && offset == dstOffset

	// Get locale from environment
	if lang := os.Getenv("LANG"); lang != "" {
		result.Locale = lang
	} else if lcAll := os.Getenv("LC_ALL"); lcAll != "" {
		result.Locale = lcAll
	}

	return result, nil
}

// formatOffset formats a timezone offset in seconds to ±HH:MM format.
func formatOffset(seconds int) string {
	sign := "+"
	if seconds < 0 {
		sign = "-"
		seconds = -seconds
	}
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	return sign + strconv.Itoa(hours) + ":" + strconv.Itoa(minutes)
}

// getNTPStatus retrieves NTP status on Linux.
func (c *Collector) getNTPStatus() (*types.NTPStatusResult, error) {
	result := &types.NTPStatusResult{
		Timestamp: time.Now(),
	}

	// Try timedatectl (systemd)
	// #nosec G204 -- no user input
	cmd := exec.Command("timedatectl", "show")
	if output, err := cmd.Output(); err == nil {
		result.NTPService = "systemd-timesyncd"
		for _, line := range strings.Split(string(output), "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key, value := parts[0], parts[1]
			switch key {
			case "NTPSynchronized":
				result.Synchronized = value == "yes"
			}
		}
		return result, nil
	}

	// Try chronyc
	// #nosec G204 -- no user input
	cmd = exec.Command("chronyc", "tracking")
	if output, err := cmd.Output(); err == nil {
		result.NTPService = "chrony"
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "Reference ID") {
				result.Synchronized = !strings.Contains(line, "0.0.0.0")
			}
			if strings.HasPrefix(line, "Stratum") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					result.Stratum, _ = strconv.Atoi(parts[2])
				}
			}
			if strings.HasPrefix(line, "System time") {
				parts := strings.Fields(line)
				if len(parts) >= 4 {
					result.Offset = parts[3] + " " + parts[4]
				}
			}
		}
		return result, nil
	}

	// Try ntpq
	// #nosec G204 -- no user input
	cmd = exec.Command("ntpq", "-p")
	if output, err := cmd.Output(); err == nil {
		result.NTPService = "ntpd"
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "*") {
				result.Synchronized = true
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					result.CurrentServer = fields[0][1:] // Remove * prefix
				}
				break
			}
		}
		return result, nil
	}

	return result, nil
}

// getCoreDumps retrieves core dump information on Linux.
func (c *Collector) getCoreDumps() (*types.CoreDumpsResult, error) {
	result := &types.CoreDumpsResult{
		Timestamp: time.Now(),
	}

	// Common core dump locations
	dumpPaths := []string{
		"/var/crash",
		"/var/lib/systemd/coredump",
		"/var/spool/abrt",
		"/tmp",
	}

	for _, dumpPath := range dumpPaths {
		entries, err := os.ReadDir(dumpPath)
		if err != nil {
			continue
		}

		if result.DumpPath == "" {
			result.DumpPath = dumpPath
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			// Check for core dump patterns
			if !strings.HasPrefix(name, "core") && !strings.HasSuffix(name, ".core") &&
				!strings.Contains(name, "coredump") {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			dump := types.CoreDump{
				Path: filepath.Join(dumpPath, name),
				Time: info.ModTime(),
			}
			if size := info.Size(); size > 0 {
				dump.Size = uint64(size) // #nosec G115 -- checked for non-negative
			}

			// Try to extract process name from filename
			// Common patterns: core.PID, core-PROCESS-PID-..., PROCESS.core
			if strings.HasPrefix(name, "core.") {
				parts := strings.Split(name, ".")
				if len(parts) >= 2 {
					if pid, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
						dump.PID = int32(pid)
					}
				}
			} else if strings.HasPrefix(name, "core-") {
				parts := strings.Split(name, "-")
				if len(parts) >= 2 {
					dump.ProcessName = parts[1]
				}
			}

			result.CoreDumps = append(result.CoreDumps, dump)
			result.TotalSize += dump.Size
		}
	}

	result.Count = len(result.CoreDumps)
	return result, nil
}

// getPowerState retrieves power/battery state on Linux.
func (c *Collector) getPowerState() (*types.PowerStateResult, error) {
	result := &types.PowerStateResult{
		Timestamp: time.Now(),
	}

	powerSupplyPath := "/sys/class/power_supply"
	entries, err := os.ReadDir(powerSupplyPath)
	if err != nil {
		result.OnACPower = true // Assume AC if can't detect
		return result, nil
	}

	for _, entry := range entries {
		supplyPath := filepath.Join(powerSupplyPath, entry.Name())

		// Read supply type
		// #nosec G304 -- reading from sysfs
		typeData, err := os.ReadFile(filepath.Join(supplyPath, "type"))
		if err != nil {
			continue
		}
		supplyType := strings.TrimSpace(string(typeData))

		if supplyType == "Mains" || supplyType == "USB" {
			// AC adapter
			// #nosec G304 -- reading from sysfs
			if online, err := os.ReadFile(filepath.Join(supplyPath, "online")); err == nil {
				result.OnACPower = strings.TrimSpace(string(online)) == "1"
			}
		} else if supplyType == "Battery" {
			battery := types.BatteryInfo{
				Name: entry.Name(),
			}

			// Read battery status
			// #nosec G304 -- reading from sysfs
			if status, err := os.ReadFile(filepath.Join(supplyPath, "status")); err == nil {
				battery.Status = strings.TrimSpace(string(status))
			}

			// Read capacity percentage
			// #nosec G304 -- reading from sysfs
			if capacity, err := os.ReadFile(filepath.Join(supplyPath, "capacity")); err == nil {
				battery.Percent, _ = strconv.ParseFloat(strings.TrimSpace(string(capacity)), 64)
			}

			// Read energy/charge values
			// #nosec G304 -- reading from sysfs
			if energyNow, err := os.ReadFile(filepath.Join(supplyPath, "energy_now")); err == nil {
				val, _ := strconv.ParseUint(strings.TrimSpace(string(energyNow)), 10, 64)
				battery.Capacity = val / 1000 // Convert µWh to mWh
			}
			// #nosec G304 -- reading from sysfs
			if energyFull, err := os.ReadFile(filepath.Join(supplyPath, "energy_full")); err == nil {
				val, _ := strconv.ParseUint(strings.TrimSpace(string(energyFull)), 10, 64)
				battery.CapacityFull = val / 1000
			}

			// Read voltage
			// #nosec G304 -- reading from sysfs
			if voltage, err := os.ReadFile(filepath.Join(supplyPath, "voltage_now")); err == nil {
				val, _ := strconv.ParseFloat(strings.TrimSpace(string(voltage)), 64)
				battery.Voltage = val / 1000000 // Convert µV to V
			}

			// Read technology
			// #nosec G304 -- reading from sysfs
			if tech, err := os.ReadFile(filepath.Join(supplyPath, "technology")); err == nil {
				battery.Technology = strings.TrimSpace(string(tech))
			}

			// Read manufacturer
			// #nosec G304 -- reading from sysfs
			if mfg, err := os.ReadFile(filepath.Join(supplyPath, "manufacturer")); err == nil {
				battery.Manufacturer = strings.TrimSpace(string(mfg))
			}

			// Read model
			// #nosec G304 -- reading from sysfs
			if model, err := os.ReadFile(filepath.Join(supplyPath, "model_name")); err == nil {
				battery.Model = strings.TrimSpace(string(model))
			}

			// Read cycle count
			// #nosec G304 -- reading from sysfs
			if cycles, err := os.ReadFile(filepath.Join(supplyPath, "cycle_count")); err == nil {
				battery.CycleCount, _ = strconv.Atoi(strings.TrimSpace(string(cycles)))
			}

			result.Batteries = append(result.Batteries, battery)
		}
	}

	return result, nil
}

// getNUMATopology retrieves NUMA topology on Linux.
func (c *Collector) getNUMATopology() (*types.NUMATopologyResult, error) {
	result := &types.NUMATopologyResult{
		Timestamp: time.Now(),
	}

	numaPath := "/sys/devices/system/node"
	entries, err := os.ReadDir(numaPath)
	if err != nil {
		return result, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "node") {
			continue
		}

		nodeID, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), "node"))
		if err != nil {
			continue
		}

		nodePath := filepath.Join(numaPath, entry.Name())
		node := types.NUMANode{
			ID: nodeID,
		}

		// Read CPUs for this node
		// #nosec G304 -- reading from sysfs
		if cpulist, err := os.ReadFile(filepath.Join(nodePath, "cpulist")); err == nil {
			node.CPUs = parseCPUList(strings.TrimSpace(string(cpulist)))
		}

		// Read memory info
		// #nosec G304 -- reading from sysfs
		if meminfo, err := os.Open(filepath.Join(nodePath, "meminfo")); err == nil {
			scanner := bufio.NewScanner(meminfo)
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.Fields(line)
				if len(parts) < 4 {
					continue
				}
				// Format: Node X MemType: VALUE kB
				key := parts[2]
				val, _ := strconv.ParseUint(parts[3], 10, 64)
				val *= 1024 // Convert kB to bytes

				switch key {
				case "MemTotal:":
					node.MemoryTotal = val
				case "MemFree:":
					node.MemoryFree = val
				}
			}
			_ = meminfo.Close()
			node.MemoryUsed = node.MemoryTotal - node.MemoryFree
		}

		// Read distance to other nodes
		// #nosec G304 -- reading from sysfs
		if distance, err := os.ReadFile(filepath.Join(nodePath, "distance")); err == nil {
			for _, d := range strings.Fields(strings.TrimSpace(string(distance))) {
				if dist, err := strconv.Atoi(d); err == nil {
					node.Distances = append(node.Distances, dist)
				}
			}
		}

		result.Nodes = append(result.Nodes, node)
	}

	result.Count = len(result.Nodes)
	return result, nil
}

// parseCPUList parses a CPU list string like "0-3,8-11" into individual CPU numbers.
func parseCPUList(cpulist string) []int {
	var cpus []int
	if cpulist == "" {
		return cpus
	}

	for _, part := range strings.Split(cpulist, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			if len(bounds) == 2 {
				start, _ := strconv.Atoi(bounds[0])
				end, _ := strconv.Atoi(bounds[1])
				for i := start; i <= end; i++ {
					cpus = append(cpus, i)
				}
			}
		} else {
			if cpu, err := strconv.Atoi(part); err == nil {
				cpus = append(cpus, cpu)
			}
		}
	}

	return cpus
}
