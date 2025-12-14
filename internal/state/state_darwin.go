//go:build darwin

package state

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getVMInfo detects virtualization on macOS.
func (c *Collector) getVMInfo() (*types.VMInfoResult, error) {
	result := &types.VMInfoResult{
		VMType:    "none",
		Timestamp: time.Now(),
	}

	// Check kern.hv_support sysctl (indicates if hypervisor is present)
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("sysctl", "-n", "kern.hv_support")
	if output, err := cmd.Output(); err == nil {
		if strings.TrimSpace(string(output)) == "1" {
			// Running on a Mac with hypervisor support (could be host or VM)
		}
	}

	// Check system_profiler for hardware model
	// #nosec G204 -- no user input
	cmd = cmdexec.Command("system_profiler", "SPHardwareDataType")
	if output, err := cmd.Output(); err == nil {
		content := string(output)
		if strings.Contains(content, "Virtual") || strings.Contains(content, "VMware") ||
			strings.Contains(content, "Parallels") || strings.Contains(content, "VirtualBox") {
			result.IsVM = true
			result.VMType = "vm"
			result.DetectionMethod = "system_profiler"

			if strings.Contains(content, "VMware") {
				result.Hypervisor = "vmware"
			} else if strings.Contains(content, "Parallels") {
				result.Hypervisor = "parallels"
			} else if strings.Contains(content, "VirtualBox") {
				result.Hypervisor = "virtualbox"
			}
		}

		// Extract model name
		for _, line := range strings.Split(content, "\n") {
			if strings.Contains(line, "Model Name:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					result.ProductName = strings.TrimSpace(parts[1])
				}
			}
		}
	}

	result.Manufacturer = "Apple Inc."
	return result, nil
}

// getTimezone retrieves timezone information on macOS.
func (c *Collector) getTimezone() (*types.TimezoneInfoResult, error) {
	now := time.Now()
	zone, offset := now.Zone()

	result := &types.TimezoneInfoResult{
		Abbreviation: zone,
		UTCOffset:    formatOffset(offset),
		LocalTime:    now,
		Timestamp:    time.Now(),
	}

	// Get timezone from /etc/localtime symlink
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if idx := strings.Index(target, "zoneinfo/"); idx >= 0 {
			result.Timezone = target[idx+9:]
		}
	}

	// Check for DST
	_, dstOffset := time.Date(now.Year(), time.July, 1, 12, 0, 0, 0, now.Location()).Zone()
	_, stdOffset := time.Date(now.Year(), time.January, 1, 12, 0, 0, 0, now.Location()).Zone()
	result.DSTActive = dstOffset != stdOffset && offset == dstOffset

	// Get locale
	if lang := os.Getenv("LANG"); lang != "" {
		result.Locale = lang
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

// getNTPStatus retrieves NTP status on macOS.
func (c *Collector) getNTPStatus() (*types.NTPStatusResult, error) {
	result := &types.NTPStatusResult{
		Timestamp: time.Now(),
	}

	// Try sntp command
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("sntp", "-d", "time.apple.com")
	if output, err := cmd.Output(); err == nil {
		result.NTPService = "sntp"
		content := string(output)
		if strings.Contains(content, "offset") {
			result.Synchronized = true
		}
	}

	return result, nil
}

// getCoreDumps retrieves core dump information on macOS.
func (c *Collector) getCoreDumps() (*types.CoreDumpsResult, error) {
	result := &types.CoreDumpsResult{
		DumpPath:  "/cores",
		Timestamp: time.Now(),
	}

	entries, err := os.ReadDir("/cores")
	if err != nil {
		return result, nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, "core.") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		dump := types.CoreDump{
			Path: "/cores/" + name,
			Size: uint64(info.Size()),
			Time: info.ModTime(),
		}

		// Parse PID from filename (core.PID)
		parts := strings.Split(name, ".")
		if len(parts) >= 2 {
			if pid, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
				dump.PID = int32(pid)
			}
		}

		result.CoreDumps = append(result.CoreDumps, dump)
		result.TotalSize += dump.Size
	}

	result.Count = len(result.CoreDumps)
	return result, nil
}

// getPowerState retrieves power/battery state on macOS.
func (c *Collector) getPowerState() (*types.PowerStateResult, error) {
	result := &types.PowerStateResult{
		Timestamp: time.Now(),
	}

	// Use pmset to get power info
	// #nosec G204 -- no user input
	cmd := cmdexec.Command("pmset", "-g", "batt")
	if output, err := cmd.Output(); err == nil {
		content := string(output)

		// Check power source
		if strings.Contains(content, "'AC Power'") || strings.Contains(content, "AC attached") {
			result.OnACPower = true
		}

		// Parse battery info
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			if strings.Contains(line, "InternalBattery") {
				battery := types.BatteryInfo{
					Name: "InternalBattery",
				}

				// Parse percentage
				if idx := strings.Index(line, "%"); idx > 0 {
					start := idx - 1
					for start > 0 && (line[start] >= '0' && line[start] <= '9') {
						start--
					}
					if pct, err := strconv.ParseFloat(line[start+1:idx], 64); err == nil {
						battery.Percent = pct
					}
				}

				// Parse status
				if strings.Contains(line, "charging") {
					battery.Status = "Charging"
				} else if strings.Contains(line, "discharging") {
					battery.Status = "Discharging"
				} else if strings.Contains(line, "charged") {
					battery.Status = "Full"
				}

				result.Batteries = append(result.Batteries, battery)
			}
		}
	}

	return result, nil
}

// getNUMATopology returns empty result on macOS (not applicable).
func (c *Collector) getNUMATopology() (*types.NUMATopologyResult, error) {
	return &types.NUMATopologyResult{
		Nodes:     []types.NUMANode{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}
