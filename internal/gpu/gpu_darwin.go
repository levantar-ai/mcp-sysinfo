//go:build darwin
// +build darwin

package gpu

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

func (c *Collector) getGPUInfo() (*types.GPUInfoResult, error) {
	result := &types.GPUInfoResult{
		GPUs:      []types.GPUDevice{},
		Timestamp: time.Now(),
	}

	// Use system_profiler to get GPU information
	cmd := cmdexec.Command("system_profiler", "SPDisplaysDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		result.Error = "Failed to query GPU information: " + err.Error()
		return result, nil
	}

	var profiler systemProfilerOutput
	if err := json.Unmarshal(output, &profiler); err != nil {
		result.Error = "Failed to parse GPU information: " + err.Error()
		return result, nil
	}

	index := 0
	for _, display := range profiler.SPDisplaysDataType {
		device := types.GPUDevice{
			Index:  index,
			Name:   display.ChipsetModel,
			Vendor: getVendorFromChipset(display.ChipsetModel),
		}

		// Parse VRAM
		if display.VRAM != "" {
			device.MemoryTotal = parseVRAM(display.VRAM)
		}

		// Parse device ID
		if display.DeviceID != "" {
			device.PCIBusID = display.DeviceID
		}

		// Bus info
		if display.Bus != "" {
			device.Architecture = display.Bus
		}

		// Metal support indicates GPU capability
		if display.MetalSupport != "" {
			device.ComputeMode = "Metal: " + display.MetalSupport
		}

		result.GPUs = append(result.GPUs, device)
		index++
	}

	result.Count = len(result.GPUs)
	return result, nil
}

type systemProfilerOutput struct {
	SPDisplaysDataType []displayInfo `json:"SPDisplaysDataType"`
}

type displayInfo struct {
	ChipsetModel string `json:"sppci_model"`
	Bus          string `json:"sppci_bus"`
	DeviceID     string `json:"sppci_device_id"`
	VRAM         string `json:"spdisplays_vram"`
	VRAMShared   string `json:"spdisplays_vram_shared"`
	MetalSupport string `json:"spdisplays_mtlgpufamilysupport"`
	Vendor       string `json:"sppci_vendor"`
}

func getVendorFromChipset(chipset string) string {
	chipsetLower := strings.ToLower(chipset)
	switch {
	case strings.Contains(chipsetLower, "apple"):
		return "apple"
	case strings.Contains(chipsetLower, "amd") || strings.Contains(chipsetLower, "radeon"):
		return "amd"
	case strings.Contains(chipsetLower, "nvidia") || strings.Contains(chipsetLower, "geforce"):
		return "nvidia"
	case strings.Contains(chipsetLower, "intel"):
		return "intel"
	default:
		return "unknown"
	}
}

func parseVRAM(vram string) uint64 {
	vram = strings.TrimSpace(vram)
	vram = strings.ToLower(vram)

	// Parse values like "8 GB" or "16384 MB"
	var value float64
	var unit string
	_, err := parseScanf(vram, "%f %s", &value, &unit)
	if err != nil {
		return 0
	}

	switch unit {
	case "gb":
		return uint64(value * 1024 * 1024 * 1024)
	case "mb":
		return uint64(value * 1024 * 1024)
	default:
		return uint64(value)
	}
}

func parseScanf(s string, format string, args ...interface{}) (int, error) {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return 0, nil
	}

	// Simple implementation for "value unit" format
	if len(args) >= 1 {
		if f, ok := args[0].(*float64); ok {
			var v float64
			for _, c := range parts[0] {
				if c >= '0' && c <= '9' || c == '.' {
					continue
				}
				break
			}
			_, _ = parseFloat(parts[0], &v)
			*f = v
		}
	}
	if len(args) >= 2 {
		if str, ok := args[1].(*string); ok {
			*str = parts[1]
		}
	}

	return len(args), nil
}

func parseFloat(s string, f *float64) (int, error) {
	// Extract numeric part
	var numStr string
	for _, c := range s {
		if c >= '0' && c <= '9' || c == '.' {
			numStr += string(c)
		} else {
			break
		}
	}

	if numStr == "" {
		return 0, nil
	}

	var val float64
	for i, c := range numStr {
		if c == '.' {
			// Handle decimal
			continue
		}
		digit := float64(c - '0')
		if strings.Contains(numStr[:i], ".") {
			// After decimal point
			decimalPos := strings.Index(numStr, ".")
			power := float64(i - decimalPos)
			for j := 0; j < int(power); j++ {
				digit /= 10
			}
			val += digit
		} else {
			val = val*10 + digit
		}
	}

	*f = val
	return 1, nil
}
