//go:build windows

package state

import (
	"encoding/json"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getVMInfo detects virtualization on Windows.
func (c *Collector) getVMInfo() (*types.VMInfoResult, error) {
	result := &types.VMInfoResult{
		VMType:    "none",
		Timestamp: time.Now(),
	}

	// Query WMI for computer system info
	// #nosec G204 -- query is hardcoded
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-WmiObject Win32_ComputerSystem | Select-Object Manufacturer, Model | ConvertTo-Json")
	if output, err := cmd.Output(); err == nil {
		var cs struct {
			Manufacturer string `json:"Manufacturer"`
			Model        string `json:"Model"`
		}
		if err := json.Unmarshal(output, &cs); err == nil {
			result.Manufacturer = cs.Manufacturer
			result.ProductName = cs.Model

			mfgLower := strings.ToLower(cs.Manufacturer)
			modelLower := strings.ToLower(cs.Model)

			// Check for VM indicators
			vmIndicators := map[string]string{
				"vmware":      "vmware",
				"virtual":     "virtualbox",
				"microsoft corporation": "hyper-v",
				"xen":         "xen",
				"qemu":        "qemu",
				"parallels":   "parallels",
				"amazon ec2":  "aws",
				"google":      "gcp",
			}

			for keyword, hvName := range vmIndicators {
				if strings.Contains(mfgLower, keyword) || strings.Contains(modelLower, keyword) {
					result.IsVM = true
					result.VMType = "vm"
					result.Hypervisor = hvName
					result.DetectionMethod = "wmi"
					break
				}
			}
		}
	}

	return result, nil
}

// getTimezone retrieves timezone information on Windows.
func (c *Collector) getTimezone() (*types.TimezoneInfoResult, error) {
	now := time.Now()
	zone, offset := now.Zone()

	result := &types.TimezoneInfoResult{
		Abbreviation: zone,
		UTCOffset:    formatOffset(offset),
		LocalTime:    now,
		Timestamp:    time.Now(),
	}

	// Get timezone from Windows
	// #nosec G204 -- query is hardcoded
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"[System.TimeZoneInfo]::Local.Id")
	if output, err := cmd.Output(); err == nil {
		result.Timezone = strings.TrimSpace(string(output))
	}

	// Check for DST
	_, dstOffset := time.Date(now.Year(), time.July, 1, 12, 0, 0, 0, now.Location()).Zone()
	_, stdOffset := time.Date(now.Year(), time.January, 1, 12, 0, 0, 0, now.Location()).Zone()
	result.DSTActive = dstOffset != stdOffset && offset == dstOffset

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

// getNTPStatus retrieves NTP status on Windows.
func (c *Collector) getNTPStatus() (*types.NTPStatusResult, error) {
	result := &types.NTPStatusResult{
		Timestamp: time.Now(),
	}

	// Query w32tm for NTP status
	// #nosec G204 -- query is hardcoded
	cmd := exec.Command("w32tm", "/query", "/status")
	if output, err := cmd.Output(); err == nil {
		result.NTPService = "w32time"
		content := string(output)

		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Source:") {
				result.CurrentServer = strings.TrimSpace(strings.TrimPrefix(line, "Source:"))
				if result.CurrentServer != "Local CMOS Clock" && result.CurrentServer != "" {
					result.Synchronized = true
				}
			}
			if strings.HasPrefix(line, "Stratum:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					result.Stratum, _ = strconv.Atoi(parts[1])
				}
			}
		}
	}

	return result, nil
}

// getCoreDumps retrieves crash dump information on Windows.
func (c *Collector) getCoreDumps() (*types.CoreDumpsResult, error) {
	result := &types.CoreDumpsResult{
		DumpPath:  "C:\\Windows\\Minidump",
		Timestamp: time.Now(),
	}

	// Check minidump directory
	entries, err := os.ReadDir("C:\\Windows\\Minidump")
	if err != nil {
		// Try alternative location
		entries, err = os.ReadDir("C:\\Windows\\MEMORY.DMP")
		if err != nil {
			return result, nil
		}
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".dmp") {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		dump := types.CoreDump{
			Path: result.DumpPath + "\\" + name,
			Size: uint64(info.Size()),
			Time: info.ModTime(),
		}

		result.CoreDumps = append(result.CoreDumps, dump)
		result.TotalSize += dump.Size
	}

	result.Count = len(result.CoreDumps)
	return result, nil
}

// getPowerState retrieves power/battery state on Windows.
func (c *Collector) getPowerState() (*types.PowerStateResult, error) {
	result := &types.PowerStateResult{
		Timestamp: time.Now(),
	}

	// Query WMI for battery info
	// #nosec G204 -- query is hardcoded
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-WmiObject Win32_Battery | Select-Object Name, EstimatedChargeRemaining, BatteryStatus | ConvertTo-Json")
	if output, err := cmd.Output(); err == nil {
		// Handle both single object and array
		var batteries []struct {
			Name                     string `json:"Name"`
			EstimatedChargeRemaining int    `json:"EstimatedChargeRemaining"`
			BatteryStatus            int    `json:"BatteryStatus"`
		}

		outputStr := strings.TrimSpace(string(output))
		if outputStr == "" || outputStr == "null" {
			result.OnACPower = true
			return result, nil
		}

		if err := json.Unmarshal(output, &batteries); err != nil {
			// Try as single object
			var single struct {
				Name                     string `json:"Name"`
				EstimatedChargeRemaining int    `json:"EstimatedChargeRemaining"`
				BatteryStatus            int    `json:"BatteryStatus"`
			}
			if err := json.Unmarshal(output, &single); err == nil {
				batteries = append(batteries, single)
			}
		}

		for _, b := range batteries {
			battery := types.BatteryInfo{
				Name:    b.Name,
				Percent: float64(b.EstimatedChargeRemaining),
			}

			// BatteryStatus: 1=Discharging, 2=AC, 3=Fully Charged, 4=Low, 5=Critical
			switch b.BatteryStatus {
			case 1:
				battery.Status = "Discharging"
			case 2:
				battery.Status = "Charging"
				result.OnACPower = true
			case 3:
				battery.Status = "Full"
				result.OnACPower = true
			case 4:
				battery.Status = "Low"
			case 5:
				battery.Status = "Critical"
			}

			result.Batteries = append(result.Batteries, battery)
		}
	} else {
		result.OnACPower = true
	}

	return result, nil
}

// getNUMATopology returns NUMA topology on Windows.
func (c *Collector) getNUMATopology() (*types.NUMATopologyResult, error) {
	result := &types.NUMATopologyResult{
		Timestamp: time.Now(),
	}

	// Query WMI for NUMA info
	// #nosec G204 -- query is hardcoded
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-WmiObject Win32_Processor | Select-Object NumberOfLogicalProcessors, NumberOfCores | ConvertTo-Json")
	if output, err := cmd.Output(); err == nil {
		// Windows typically exposes NUMA through processor groups
		// For basic systems, assume single NUMA node
		var proc struct {
			NumberOfLogicalProcessors int `json:"NumberOfLogicalProcessors"`
			NumberOfCores             int `json:"NumberOfCores"`
		}
		if err := json.Unmarshal(output, &proc); err == nil {
			node := types.NUMANode{
				ID: 0,
			}
			for i := 0; i < proc.NumberOfLogicalProcessors; i++ {
				node.CPUs = append(node.CPUs, i)
			}
			result.Nodes = append(result.Nodes, node)
		}
	}

	result.Count = len(result.Nodes)
	return result, nil
}
