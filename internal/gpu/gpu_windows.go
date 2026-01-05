//go:build windows
// +build windows

package gpu

import (
	"encoding/json"
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

	// Try nvidia-smi first for NVIDIA GPUs
	nvidiaGPUs := c.getNVIDIAGPUs()
	if len(nvidiaGPUs) > 0 {
		result.GPUs = append(result.GPUs, nvidiaGPUs...)
	}

	// Use WMI for other GPUs
	wmiGPUs := c.getWMIGPUs()
	for _, wmiGPU := range wmiGPUs {
		// Skip if we already have this GPU from nvidia-smi
		found := false
		for _, nv := range nvidiaGPUs {
			if strings.Contains(strings.ToLower(nv.Name), strings.ToLower(wmiGPU.Name)) {
				found = true
				break
			}
		}
		if !found {
			result.GPUs = append(result.GPUs, wmiGPU)
		}
	}

	// Reindex
	for i := range result.GPUs {
		result.GPUs[i].Index = i
	}

	result.Count = len(result.GPUs)
	return result, nil
}

func (c *Collector) getNVIDIAGPUs() []types.GPUDevice {
	var gpus []types.GPUDevice

	// Check if nvidia-smi is available
	nvidiaSMI, err := cmdexec.LookPath("nvidia-smi")
	if err != nil {
		return nil
	}

	// Get CSV output for key metrics
	cmd := cmdexec.Command(nvidiaSMI,
		"--query-gpu=index,name,uuid,driver_version,memory.total,memory.used,memory.free,utilization.gpu,utilization.memory,temperature.gpu,fan.speed,power.draw,power.limit,clocks.gr,clocks.mem",
		"--format=csv,noheader,nounits")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ", ")
		if len(parts) < 15 {
			continue
		}

		index, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
		memTotal, _ := strconv.ParseUint(strings.TrimSpace(parts[4]), 10, 64)
		memUsed, _ := strconv.ParseUint(strings.TrimSpace(parts[5]), 10, 64)
		memFree, _ := strconv.ParseUint(strings.TrimSpace(parts[6]), 10, 64)
		gpuUtil, _ := strconv.ParseFloat(strings.TrimSpace(parts[7]), 64)
		memUtil, _ := strconv.ParseFloat(strings.TrimSpace(parts[8]), 64)
		temp, _ := strconv.ParseFloat(strings.TrimSpace(parts[9]), 64)
		fan, _ := strconv.Atoi(strings.TrimSpace(parts[10]))
		powerDraw, _ := strconv.ParseFloat(strings.TrimSpace(parts[11]), 64)
		powerLimit, _ := strconv.ParseFloat(strings.TrimSpace(parts[12]), 64)
		clockGr, _ := strconv.Atoi(strings.TrimSpace(parts[13]))
		clockMem, _ := strconv.Atoi(strings.TrimSpace(parts[14]))

		gpu := types.GPUDevice{
			Index:         index,
			Name:          strings.TrimSpace(parts[1]),
			UUID:          strings.TrimSpace(parts[2]),
			Driver:        strings.TrimSpace(parts[3]),
			Vendor:        "nvidia",
			MemoryTotal:   memTotal * 1024 * 1024, // MiB to bytes
			MemoryUsed:    memUsed * 1024 * 1024,
			MemoryFree:    memFree * 1024 * 1024,
			Utilization:   gpuUtil,
			MemoryUtil:    memUtil,
			Temperature:   temp,
			FanSpeed:      fan,
			PowerDraw:     powerDraw,
			PowerLimit:    powerLimit,
			ClockGraphics: clockGr,
			ClockMemory:   clockMem,
		}

		gpus = append(gpus, gpu)
	}

	return gpus
}

func (c *Collector) getWMIGPUs() []types.GPUDevice {
	var gpus []types.GPUDevice

	// Use PowerShell to query WMI
	psScript := `Get-CimInstance -ClassName Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion,VideoProcessor,PNPDeviceID,CurrentRefreshRate | ConvertTo-Json -Compress`

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Try parsing as array first, then as single object
	var controllers []wmiVideoController
	if err := json.Unmarshal(output, &controllers); err != nil {
		var single wmiVideoController
		if err := json.Unmarshal(output, &single); err != nil {
			return nil
		}
		controllers = []wmiVideoController{single}
	}

	for i, ctrl := range controllers {
		gpu := types.GPUDevice{
			Index:  i,
			Name:   ctrl.Name,
			Driver: ctrl.DriverVersion,
		}

		// Determine vendor from name
		nameLower := strings.ToLower(ctrl.Name)
		switch {
		case strings.Contains(nameLower, "nvidia") || strings.Contains(nameLower, "geforce") || strings.Contains(nameLower, "quadro"):
			gpu.Vendor = "nvidia"
		case strings.Contains(nameLower, "amd") || strings.Contains(nameLower, "radeon"):
			gpu.Vendor = "amd"
		case strings.Contains(nameLower, "intel"):
			gpu.Vendor = "intel"
		default:
			gpu.Vendor = "unknown"
		}

		// AdapterRAM in bytes
		if ctrl.AdapterRAM > 0 {
			gpu.MemoryTotal = ctrl.AdapterRAM
		}

		// PCI device ID
		if ctrl.PNPDeviceID != "" {
			gpu.PCIBusID = ctrl.PNPDeviceID
		}

		gpus = append(gpus, gpu)
	}

	return gpus
}

type wmiVideoController struct {
	Name               string `json:"Name"`
	AdapterRAM         uint64 `json:"AdapterRAM"`
	DriverVersion      string `json:"DriverVersion"`
	VideoProcessor     string `json:"VideoProcessor"`
	PNPDeviceID        string `json:"PNPDeviceID"`
	CurrentRefreshRate int    `json:"CurrentRefreshRate"`
}
