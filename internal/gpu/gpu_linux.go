//go:build linux
// +build linux

package gpu

import (
	"bufio"
	"encoding/xml"
	"os"
	"path/filepath"
	"strconv"
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

	// Try NVIDIA first (most common)
	nvidiaGPUs, err := c.getNVIDIAGPUs()
	if err == nil && len(nvidiaGPUs) > 0 {
		result.GPUs = append(result.GPUs, nvidiaGPUs...)
	}

	// Try AMD GPUs via sysfs
	amdGPUs, err := c.getAMDGPUs()
	if err == nil && len(amdGPUs) > 0 {
		result.GPUs = append(result.GPUs, amdGPUs...)
	}

	// Try Intel GPUs via sysfs
	intelGPUs, err := c.getIntelGPUs()
	if err == nil && len(intelGPUs) > 0 {
		result.GPUs = append(result.GPUs, intelGPUs...)
	}

	result.Count = len(result.GPUs)
	return result, nil
}

// getNVIDIAGPUs uses nvidia-smi to get NVIDIA GPU information.
func (c *Collector) getNVIDIAGPUs() ([]types.GPUDevice, error) {
	var gpus []types.GPUDevice

	// Check if nvidia-smi is available
	nvidiaSMI, err := cmdexec.LookPath("nvidia-smi")
	if err != nil {
		return nil, err
	}

	// Get XML output for comprehensive data
	cmd := cmdexec.Command(nvidiaSMI, "-q", "-x")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse XML
	var smiOutput nvidiaSMIOutput
	if err := xml.Unmarshal(output, &smiOutput); err != nil {
		return nil, err
	}

	for i, gpu := range smiOutput.GPUs {
		device := types.GPUDevice{
			Index:        i,
			Name:         gpu.ProductName,
			Vendor:       "nvidia",
			Driver:       smiOutput.DriverVersion,
			VBIOS:        gpu.VBIOSVersion,
			PCIBusID:     gpu.PCI.BusID,
			UUID:         gpu.UUID,
			Serial:       gpu.Serial,
			Architecture: gpu.ProductArchitecture,
		}

		// Parse memory
		if gpu.FBMemoryUsage.Total != "" {
			device.MemoryTotal = parseMemory(gpu.FBMemoryUsage.Total)
			device.MemoryUsed = parseMemory(gpu.FBMemoryUsage.Used)
			device.MemoryFree = parseMemory(gpu.FBMemoryUsage.Free)
			if device.MemoryTotal > 0 {
				device.MemoryUtil = float64(device.MemoryUsed) / float64(device.MemoryTotal) * 100
			}
		}

		// Parse utilization
		if gpu.Utilization.GPUUtil != "" {
			device.Utilization = parsePercent(gpu.Utilization.GPUUtil)
		}

		// Parse temperature
		if gpu.Temperature.GPUTemp != "" {
			device.Temperature = parseTemperature(gpu.Temperature.GPUTemp)
		}
		if gpu.Temperature.GPUTempMaxThreshold != "" {
			device.TemperatureMax = parseTemperature(gpu.Temperature.GPUTempMaxThreshold)
		}

		// Parse fan speed
		if gpu.FanSpeed != "" {
			device.FanSpeed = int(parsePercent(gpu.FanSpeed))
		}

		// Parse power
		if gpu.PowerReadings.PowerDraw != "" {
			device.PowerDraw = parsePower(gpu.PowerReadings.PowerDraw)
		}
		if gpu.PowerReadings.PowerLimit != "" {
			device.PowerLimit = parsePower(gpu.PowerReadings.PowerLimit)
		}

		// Parse clocks
		if gpu.Clocks.GraphicsClock != "" {
			device.ClockGraphics = parseClock(gpu.Clocks.GraphicsClock)
		}
		if gpu.Clocks.MemClock != "" {
			device.ClockMemory = parseClock(gpu.Clocks.MemClock)
		}
		if gpu.Clocks.SMClock != "" {
			device.ClockSM = parseClock(gpu.Clocks.SMClock)
		}

		// Compute mode
		device.ComputeMode = gpu.ComputeMode

		// Persistence mode
		device.PersistenceMode = strings.ToLower(gpu.PersistenceMode) == "enabled"

		// Parse processes
		for _, proc := range gpu.Processes.ProcessInfo {
			pid, _ := strconv.ParseInt(proc.PID, 10, 32)
			gpuProc := types.GPUProcess{
				PID:        int32(pid),
				Name:       proc.ProcessName,
				MemoryUsed: parseMemory(proc.UsedMemory),
				Type:       proc.Type,
			}
			device.Processes = append(device.Processes, gpuProc)
		}
		device.ProcessCount = len(device.Processes)

		// ECC errors
		if gpu.ECCErrors.Volatile.SingleBit.Total != "" {
			singleBit, _ := strconv.Atoi(gpu.ECCErrors.Volatile.SingleBit.Total)
			doubleBit, _ := strconv.Atoi(gpu.ECCErrors.Volatile.DoubleBit.Total)
			device.EccErrors = singleBit + doubleBit
		}

		gpus = append(gpus, device)
	}

	return gpus, nil
}

// getAMDGPUs reads AMD GPU information from sysfs.
func (c *Collector) getAMDGPUs() ([]types.GPUDevice, error) {
	var gpus []types.GPUDevice

	drmPath := "/sys/class/drm"
	entries, err := os.ReadDir(drmPath)
	if err != nil {
		return nil, err
	}

	index := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "card") || strings.Contains(entry.Name(), "-") {
			continue
		}

		cardPath := filepath.Join(drmPath, entry.Name())
		devicePath := filepath.Join(cardPath, "device")

		// Check if it's an AMD GPU
		vendorID := readSysfsFile(filepath.Join(devicePath, "vendor"))
		if vendorID != "0x1002" { // AMD vendor ID
			continue
		}

		device := types.GPUDevice{
			Index:  index,
			Vendor: "amd",
		}

		// Get device name from uevent or use device ID
		deviceID := readSysfsFile(filepath.Join(devicePath, "device"))
		device.Name = getAMDDeviceName(deviceID)

		// Get driver
		driverLink, err := os.Readlink(filepath.Join(devicePath, "driver"))
		if err == nil {
			device.Driver = filepath.Base(driverLink)
		}

		// Read VRAM info from hwmon or amdgpu sysfs
		hwmonPath := findHWMonPath(devicePath)
		if hwmonPath != "" {
			// Temperature
			temp := readSysfsFile(filepath.Join(hwmonPath, "temp1_input"))
			if temp != "" {
				tempVal, _ := strconv.ParseFloat(temp, 64)
				device.Temperature = tempVal / 1000.0 // Convert from millidegrees
			}

			// Fan speed (as percentage)
			fanInput := readSysfsFile(filepath.Join(hwmonPath, "fan1_input"))
			fanMax := readSysfsFile(filepath.Join(hwmonPath, "fan1_max"))
			if fanInput != "" && fanMax != "" {
				fanInputVal, _ := strconv.Atoi(fanInput)
				fanMaxVal, _ := strconv.Atoi(fanMax)
				if fanMaxVal > 0 {
					device.FanSpeed = (fanInputVal * 100) / fanMaxVal
				}
			}

			// Power
			power := readSysfsFile(filepath.Join(hwmonPath, "power1_average"))
			if power != "" {
				powerVal, _ := strconv.ParseFloat(power, 64)
				device.PowerDraw = powerVal / 1000000.0 // Convert from microwatts
			}
		}

		// Read VRAM from amdgpu sysfs
		vramTotal := readSysfsFile(filepath.Join(devicePath, "mem_info_vram_total"))
		vramUsed := readSysfsFile(filepath.Join(devicePath, "mem_info_vram_used"))
		if vramTotal != "" {
			device.MemoryTotal, _ = strconv.ParseUint(vramTotal, 10, 64)
		}
		if vramUsed != "" {
			device.MemoryUsed, _ = strconv.ParseUint(vramUsed, 10, 64)
			device.MemoryFree = device.MemoryTotal - device.MemoryUsed
			if device.MemoryTotal > 0 {
				device.MemoryUtil = float64(device.MemoryUsed) / float64(device.MemoryTotal) * 100
			}
		}

		// GPU utilization from gpu_busy_percent
		gpuBusy := readSysfsFile(filepath.Join(devicePath, "gpu_busy_percent"))
		if gpuBusy != "" {
			device.Utilization, _ = strconv.ParseFloat(gpuBusy, 64)
		}

		// Graphics clock
		gpuClock := readSysfsFile(filepath.Join(devicePath, "pp_dpm_sclk"))
		if gpuClock != "" {
			device.ClockGraphics = parseAMDClock(gpuClock)
		}

		// Memory clock
		memClock := readSysfsFile(filepath.Join(devicePath, "pp_dpm_mclk"))
		if memClock != "" {
			device.ClockMemory = parseAMDClock(memClock)
		}

		// PCI bus ID
		uevent := readSysfsFile(filepath.Join(devicePath, "uevent"))
		for _, line := range strings.Split(uevent, "\n") {
			if strings.HasPrefix(line, "PCI_SLOT_NAME=") {
				device.PCIBusID = strings.TrimPrefix(line, "PCI_SLOT_NAME=")
				break
			}
		}

		gpus = append(gpus, device)
		index++
	}

	return gpus, nil
}

// getIntelGPUs reads Intel GPU information from sysfs.
func (c *Collector) getIntelGPUs() ([]types.GPUDevice, error) {
	var gpus []types.GPUDevice

	drmPath := "/sys/class/drm"
	entries, err := os.ReadDir(drmPath)
	if err != nil {
		return nil, err
	}

	index := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "card") || strings.Contains(entry.Name(), "-") {
			continue
		}

		cardPath := filepath.Join(drmPath, entry.Name())
		devicePath := filepath.Join(cardPath, "device")

		// Check if it's an Intel GPU
		vendorID := readSysfsFile(filepath.Join(devicePath, "vendor"))
		if vendorID != "0x8086" { // Intel vendor ID
			continue
		}

		device := types.GPUDevice{
			Index:  index,
			Vendor: "intel",
		}

		// Get device name
		deviceID := readSysfsFile(filepath.Join(devicePath, "device"))
		device.Name = getIntelDeviceName(deviceID)

		// Get driver
		driverLink, err := os.Readlink(filepath.Join(devicePath, "driver"))
		if err == nil {
			device.Driver = filepath.Base(driverLink)
		}

		// Read from i915 specific sysfs
		i915Path := filepath.Join(devicePath, "drm", entry.Name())

		// Frequency info
		gtCurFreq := readSysfsFile(filepath.Join(i915Path, "gt_cur_freq_mhz"))
		if gtCurFreq != "" {
			device.ClockGraphics, _ = strconv.Atoi(gtCurFreq)
		}

		// Temperature from hwmon
		hwmonPath := findHWMonPath(devicePath)
		if hwmonPath != "" {
			temp := readSysfsFile(filepath.Join(hwmonPath, "temp1_input"))
			if temp != "" {
				tempVal, _ := strconv.ParseFloat(temp, 64)
				device.Temperature = tempVal / 1000.0
			}

			// Power
			power := readSysfsFile(filepath.Join(hwmonPath, "power1_average"))
			if power == "" {
				power = readSysfsFile(filepath.Join(hwmonPath, "energy1_input"))
			}
			if power != "" {
				powerVal, _ := strconv.ParseFloat(power, 64)
				device.PowerDraw = powerVal / 1000000.0
			}
		}

		// PCI bus ID
		uevent := readSysfsFile(filepath.Join(devicePath, "uevent"))
		for _, line := range strings.Split(uevent, "\n") {
			if strings.HasPrefix(line, "PCI_SLOT_NAME=") {
				device.PCIBusID = strings.TrimPrefix(line, "PCI_SLOT_NAME=")
				break
			}
		}

		// Intel GPUs typically share system memory
		// Read from /sys/kernel/debug/dri/*/i915_gem_objects if available (requires root)

		gpus = append(gpus, device)
		index++
	}

	return gpus, nil
}

// Helper functions

func readSysfsFile(path string) string {
	// #nosec G304 -- path is constructed from known sysfs locations, not user input
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func findHWMonPath(devicePath string) string {
	hwmonDir := filepath.Join(devicePath, "hwmon")
	entries, err := os.ReadDir(hwmonDir)
	if err != nil || len(entries) == 0 {
		return ""
	}
	return filepath.Join(hwmonDir, entries[0].Name())
}

func parseMemory(s string) uint64 {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)

	// Remove unit suffix and parse
	var multiplier uint64 = 1
	if strings.HasSuffix(s, " mib") {
		s = strings.TrimSuffix(s, " mib")
		multiplier = 1024 * 1024
	} else if strings.HasSuffix(s, " gib") {
		s = strings.TrimSuffix(s, " gib")
		multiplier = 1024 * 1024 * 1024
	} else if strings.HasSuffix(s, " mb") {
		s = strings.TrimSuffix(s, " mb")
		multiplier = 1000 * 1000
	} else if strings.HasSuffix(s, " gb") {
		s = strings.TrimSuffix(s, " gb")
		multiplier = 1000 * 1000 * 1000
	}

	val, _ := strconv.ParseFloat(s, 64)
	return uint64(val * float64(multiplier))
}

func parsePercent(s string) float64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " %")
	val, _ := strconv.ParseFloat(s, 64)
	return val
}

func parseTemperature(s string) float64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " C")
	val, _ := strconv.ParseFloat(s, 64)
	return val
}

func parsePower(s string) float64 {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " W")
	val, _ := strconv.ParseFloat(s, 64)
	return val
}

func parseClock(s string) int {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, " MHz")
	val, _ := strconv.Atoi(s)
	return val
}

func parseAMDClock(s string) int {
	// AMD pp_dpm_sclk format: "0: 300Mhz\n1: 500Mhz *\n2: 1000Mhz"
	// Find the active one (marked with *)
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "*") {
			// Extract MHz value
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasSuffix(strings.ToLower(part), "mhz") {
					part = strings.TrimSuffix(strings.ToLower(part), "mhz")
					val, _ := strconv.Atoi(part)
					return val
				}
			}
		}
	}
	return 0
}

func getAMDDeviceName(deviceID string) string {
	// Common AMD GPU device IDs - this is a simplified mapping
	names := map[string]string{
		"0x744c": "Radeon RX 7900 XTX",
		"0x7480": "Radeon RX 7900 GRE",
		"0x73df": "Radeon RX 6700 XT",
		"0x73bf": "Radeon RX 6800 XT",
		"0x73af": "Radeon RX 6900 XT",
		"0x731f": "Radeon RX 5700 XT",
		"0x7340": "Radeon RX 5500 XT",
		"0x1636": "Radeon Graphics (Ryzen APU)",
	}

	if name, ok := names[deviceID]; ok {
		return name
	}
	return "AMD GPU " + deviceID
}

func getIntelDeviceName(deviceID string) string {
	// Common Intel GPU device IDs
	names := map[string]string{
		"0x56a0": "Intel Arc A770",
		"0x56a1": "Intel Arc A750",
		"0x56a5": "Intel Arc A380",
		"0x9a49": "Intel Iris Xe Graphics",
		"0x4680": "Intel Alder Lake-P GT2",
		"0x46a6": "Intel Alder Lake-P GT2",
		"0x5917": "Intel UHD Graphics 620",
		"0x3e92": "Intel UHD Graphics 630",
	}

	if name, ok := names[deviceID]; ok {
		return name
	}
	return "Intel GPU " + deviceID
}

// nvidia-smi XML structures
type nvidiaSMIOutput struct {
	XMLName       xml.Name    `xml:"nvidia_smi_log"`
	DriverVersion string      `xml:"driver_version"`
	CUDAVersion   string      `xml:"cuda_version"`
	GPUs          []nvidiaGPU `xml:"gpu"`
}

type nvidiaGPU struct {
	ProductName         string `xml:"product_name"`
	ProductBrand        string `xml:"product_brand"`
	ProductArchitecture string `xml:"product_architecture"`
	UUID                string `xml:"uuid"`
	Serial              string `xml:"serial"`
	VBIOSVersion        string `xml:"vbios_version"`
	ComputeMode         string `xml:"compute_mode"`
	PersistenceMode     string `xml:"persistence_mode"`

	PCI struct {
		BusID string `xml:"pci_bus_id"`
	} `xml:"pci"`

	FBMemoryUsage struct {
		Total string `xml:"total"`
		Used  string `xml:"used"`
		Free  string `xml:"free"`
	} `xml:"fb_memory_usage"`

	Utilization struct {
		GPUUtil    string `xml:"gpu_util"`
		MemoryUtil string `xml:"memory_util"`
	} `xml:"utilization"`

	Temperature struct {
		GPUTemp             string `xml:"gpu_temp"`
		GPUTempMaxThreshold string `xml:"gpu_temp_max_threshold"`
	} `xml:"temperature"`

	FanSpeed string `xml:"fan_speed"`

	PowerReadings struct {
		PowerDraw  string `xml:"power_draw"`
		PowerLimit string `xml:"power_limit"`
	} `xml:"power_readings"`

	Clocks struct {
		GraphicsClock string `xml:"graphics_clock"`
		SMClock       string `xml:"sm_clock"`
		MemClock      string `xml:"mem_clock"`
	} `xml:"clocks"`

	ECCErrors struct {
		Volatile struct {
			SingleBit struct {
				Total string `xml:"total"`
			} `xml:"single_bit"`
			DoubleBit struct {
				Total string `xml:"total"`
			} `xml:"double_bit"`
		} `xml:"volatile"`
	} `xml:"ecc_errors"`

	Processes struct {
		ProcessInfo []struct {
			PID         string `xml:"pid"`
			Type        string `xml:"type"`
			ProcessName string `xml:"process_name"`
			UsedMemory  string `xml:"used_memory"`
		} `xml:"process_info"`
	} `xml:"processes"`
}
