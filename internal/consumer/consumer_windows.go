//go:build windows

package consumer

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getBluetoothDevices retrieves Bluetooth devices on Windows.
func (c *Collector) getBluetoothDevices() (*types.BluetoothDevicesResult, error) {
	result := &types.BluetoothDevicesResult{
		Timestamp: time.Now(),
	}

	// Get Bluetooth devices using Get-PnpDevice
	script := `Get-PnpDevice -Class Bluetooth -ErrorAction SilentlyContinue | Select-Object FriendlyName, InstanceId, Status, Class | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get Bluetooth devices: " + err.Error()
		return result, nil
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" || outputStr == "null" {
		result.Available = false
		return result, nil
	}

	var devices []struct {
		FriendlyName string `json:"FriendlyName"`
		InstanceId   string `json:"InstanceId"`
		Status       string `json:"Status"`
		Class        string `json:"Class"`
	}

	if err := json.Unmarshal(output, &devices); err != nil {
		// Try as single object
		var single struct {
			FriendlyName string `json:"FriendlyName"`
			InstanceId   string `json:"InstanceId"`
			Status       string `json:"Status"`
			Class        string `json:"Class"`
		}
		if err := json.Unmarshal(output, &single); err == nil {
			devices = append(devices, single)
		} else {
			result.Error = "failed to parse Bluetooth devices: " + err.Error()
			return result, nil
		}
	}

	for _, d := range devices {
		device := types.BluetoothDevice{
			Name:       d.FriendlyName,
			InstanceID: d.InstanceId,
			Status:     d.Status,
			Connected:  d.Status == "OK",
		}

		// Determine device type from instance ID
		instanceLower := strings.ToLower(d.InstanceId)
		if strings.Contains(instanceLower, "audio") || strings.Contains(instanceLower, "headset") {
			device.DeviceType = "Audio"
		} else if strings.Contains(instanceLower, "hid") || strings.Contains(instanceLower, "keyboard") || strings.Contains(instanceLower, "mouse") {
			device.DeviceType = "Input"
		} else if strings.Contains(instanceLower, "bthenum\\dev_") {
			device.DeviceType = "Peripheral"
			device.Paired = true
		} else if strings.Contains(instanceLower, "bthle\\") {
			device.DeviceType = "BLE"
		}

		// Check if this is a Bluetooth adapter (radio)
		if strings.Contains(instanceLower, "bth\\") && !strings.Contains(instanceLower, "bthenum") {
			adapter := types.BluetoothAdapter{
				Name:    d.FriendlyName,
				Status:  d.Status,
				Enabled: d.Status == "OK",
			}
			result.Adapters = append(result.Adapters, adapter)
		} else {
			result.Devices = append(result.Devices, device)
		}
	}

	result.Available = len(result.Adapters) > 0 || len(result.Devices) > 0
	return result, nil
}

// getAudioDevices retrieves audio devices on Windows.
func (c *Collector) getAudioDevices() (*types.AudioDevicesResult, error) {
	result := &types.AudioDevicesResult{
		Timestamp: time.Now(),
	}

	// Get audio devices using Win32_SoundDevice
	script := `Get-WmiObject Win32_SoundDevice | Select-Object Name, DeviceID, Manufacturer, Status | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get audio devices: " + err.Error()
		return result, nil
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" || outputStr == "null" {
		result.Available = false
		return result, nil
	}

	var devices []struct {
		Name         string `json:"Name"`
		DeviceID     string `json:"DeviceID"`
		Manufacturer string `json:"Manufacturer"`
		Status       string `json:"Status"`
	}

	if err := json.Unmarshal(output, &devices); err != nil {
		// Try as single object
		var single struct {
			Name         string `json:"Name"`
			DeviceID     string `json:"DeviceID"`
			Manufacturer string `json:"Manufacturer"`
			Status       string `json:"Status"`
		}
		if err := json.Unmarshal(output, &single); err == nil {
			devices = append(devices, single)
		} else {
			result.Error = "failed to parse audio devices: " + err.Error()
			return result, nil
		}
	}

	for _, d := range devices {
		device := types.AudioDevice{
			Name:         d.Name,
			DeviceID:     d.DeviceID,
			Manufacturer: d.Manufacturer,
			Status:       d.Status,
		}

		// Determine device type from name
		nameLower := strings.ToLower(d.Name)
		if strings.Contains(nameLower, "microphone") || strings.Contains(nameLower, "input") || strings.Contains(nameLower, "recording") {
			device.DeviceType = "Recording"
		} else {
			device.DeviceType = "Playback"
		}

		result.Devices = append(result.Devices, device)
	}

	result.Available = len(result.Devices) > 0
	return result, nil
}

// getPrinters retrieves printer information on Windows.
func (c *Collector) getPrinters() (*types.PrintersResult, error) {
	result := &types.PrintersResult{
		Timestamp: time.Now(),
	}

	// Get spooler service status
	spoolerScript := `(Get-Service Spooler -ErrorAction SilentlyContinue).Status`
	spoolerOutput, err := cmdexec.Command("powershell", "-NoProfile", "-Command", spoolerScript).Output()
	if err == nil {
		result.SpoolerStatus = strings.TrimSpace(string(spoolerOutput))
		result.SpoolerRunning = strings.EqualFold(result.SpoolerStatus, "Running")
	} else {
		result.SpoolerStatus = "Unknown"
	}

	// Get printers using Win32_Printer
	script := `Get-WmiObject Win32_Printer | Select-Object Name, PortName, DriverName, PrinterStatus, Default, Network, Shared, Location | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get printers: " + err.Error()
		return result, nil
	}

	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" || outputStr == "null" {
		result.Available = false
		return result, nil
	}

	var printers []struct {
		Name          string `json:"Name"`
		PortName      string `json:"PortName"`
		DriverName    string `json:"DriverName"`
		PrinterStatus int    `json:"PrinterStatus"`
		Default       bool   `json:"Default"`
		Network       bool   `json:"Network"`
		Shared        bool   `json:"Shared"`
		Location      string `json:"Location"`
	}

	if err := json.Unmarshal(output, &printers); err != nil {
		// Try as single object
		var single struct {
			Name          string `json:"Name"`
			PortName      string `json:"PortName"`
			DriverName    string `json:"DriverName"`
			PrinterStatus int    `json:"PrinterStatus"`
			Default       bool   `json:"Default"`
			Network       bool   `json:"Network"`
			Shared        bool   `json:"Shared"`
			Location      string `json:"Location"`
		}
		if err := json.Unmarshal(output, &single); err == nil {
			printers = append(printers, single)
		} else {
			result.Error = "failed to parse printers: " + err.Error()
			return result, nil
		}
	}

	for _, p := range printers {
		printer := types.PrinterInfo{
			Name:       p.Name,
			PortName:   p.PortName,
			DriverName: p.DriverName,
			StatusCode: p.PrinterStatus,
			IsDefault:  p.Default,
			IsNetwork:  p.Network,
			IsShared:   p.Shared,
			Location:   p.Location,
		}

		// Map PrinterStatus codes to human-readable strings
		// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-printer
		switch p.PrinterStatus {
		case 1:
			printer.Status = "Other"
		case 2:
			printer.Status = "Unknown"
		case 3:
			printer.Status = "Idle"
			printer.PrinterState = "Ready"
		case 4:
			printer.Status = "Printing"
			printer.PrinterState = "Printing"
		case 5:
			printer.Status = "Warmup"
			printer.PrinterState = "Warming up"
		case 6:
			printer.Status = "Stopped"
			printer.PrinterState = "Stopped printing"
		case 7:
			printer.Status = "Offline"
			printer.PrinterState = "Offline"
		default:
			printer.Status = "Unknown"
		}

		result.Printers = append(result.Printers, printer)
	}

	result.Available = len(result.Printers) > 0
	return result, nil
}

// getDisplayConfig retrieves display configuration on Windows.
func (c *Collector) getDisplayConfig() (*types.DisplayConfigResult, error) {
	result := &types.DisplayConfigResult{
		Timestamp: time.Now(),
	}

	// Get monitors using Win32_DesktopMonitor
	monitorScript := `Get-WmiObject Win32_DesktopMonitor | Select-Object Name, DeviceID, ScreenWidth, ScreenHeight, PixelsPerXLogicalInch, PixelsPerYLogicalInch, Status, MonitorType | ConvertTo-Json`
	monitorOutput, err := cmdexec.Command("powershell", "-NoProfile", "-Command", monitorScript).Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(monitorOutput))
		if outputStr != "" && outputStr != "null" {
			var monitors []struct {
				Name                  string `json:"Name"`
				DeviceID              string `json:"DeviceID"`
				ScreenWidth           int    `json:"ScreenWidth"`
				ScreenHeight          int    `json:"ScreenHeight"`
				PixelsPerXLogicalInch int    `json:"PixelsPerXLogicalInch"`
				PixelsPerYLogicalInch int    `json:"PixelsPerYLogicalInch"`
				Status                string `json:"Status"`
				MonitorType           string `json:"MonitorType"`
			}

			if err := json.Unmarshal(monitorOutput, &monitors); err != nil {
				// Try as single object
				var single struct {
					Name                  string `json:"Name"`
					DeviceID              string `json:"DeviceID"`
					ScreenWidth           int    `json:"ScreenWidth"`
					ScreenHeight          int    `json:"ScreenHeight"`
					PixelsPerXLogicalInch int    `json:"PixelsPerXLogicalInch"`
					PixelsPerYLogicalInch int    `json:"PixelsPerYLogicalInch"`
					Status                string `json:"Status"`
					MonitorType           string `json:"MonitorType"`
				}
				if err := json.Unmarshal(monitorOutput, &single); err == nil {
					monitors = append(monitors, single)
				}
			}

			for i, m := range monitors {
				monitor := types.MonitorInfo{
					Name:           m.Name,
					DeviceID:       m.DeviceID,
					ScreenWidth:    m.ScreenWidth,
					ScreenHeight:   m.ScreenHeight,
					PixelsPerXInch: m.PixelsPerXLogicalInch,
					PixelsPerYInch: m.PixelsPerYLogicalInch,
					Status:         m.Status,
					MonitorType:    m.MonitorType,
					IsPrimary:      i == 0, // First monitor is typically primary
				}
				result.Monitors = append(result.Monitors, monitor)
			}
		}
	}

	// Get video adapters using Win32_VideoController
	videoScript := `Get-WmiObject Win32_VideoController | Select-Object Name, DeviceID, AdapterRAM, DriverVersion, DriverDate, VideoProcessor, CurrentRefreshRate, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentBitsPerPixel, Status | ConvertTo-Json`
	videoOutput, err := cmdexec.Command("powershell", "-NoProfile", "-Command", videoScript).Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(videoOutput))
		if outputStr != "" && outputStr != "null" {
			var adapters []struct {
				Name                        string `json:"Name"`
				DeviceID                    string `json:"DeviceID"`
				AdapterRAM                  uint64 `json:"AdapterRAM"`
				DriverVersion               string `json:"DriverVersion"`
				DriverDate                  string `json:"DriverDate"`
				VideoProcessor              string `json:"VideoProcessor"`
				CurrentRefreshRate          int    `json:"CurrentRefreshRate"`
				CurrentHorizontalResolution int    `json:"CurrentHorizontalResolution"`
				CurrentVerticalResolution   int    `json:"CurrentVerticalResolution"`
				CurrentBitsPerPixel         int    `json:"CurrentBitsPerPixel"`
				Status                      string `json:"Status"`
			}

			if err := json.Unmarshal(videoOutput, &adapters); err != nil {
				// Try as single object
				var single struct {
					Name                        string `json:"Name"`
					DeviceID                    string `json:"DeviceID"`
					AdapterRAM                  uint64 `json:"AdapterRAM"`
					DriverVersion               string `json:"DriverVersion"`
					DriverDate                  string `json:"DriverDate"`
					VideoProcessor              string `json:"VideoProcessor"`
					CurrentRefreshRate          int    `json:"CurrentRefreshRate"`
					CurrentHorizontalResolution int    `json:"CurrentHorizontalResolution"`
					CurrentVerticalResolution   int    `json:"CurrentVerticalResolution"`
					CurrentBitsPerPixel         int    `json:"CurrentBitsPerPixel"`
					Status                      string `json:"Status"`
				}
				if err := json.Unmarshal(videoOutput, &single); err == nil {
					adapters = append(adapters, single)
				}
			}

			for _, a := range adapters {
				adapter := types.VideoAdapter{
					Name:                a.Name,
					DeviceID:            a.DeviceID,
					AdapterRAM:          a.AdapterRAM,
					DriverVersion:       a.DriverVersion,
					DriverDate:          a.DriverDate,
					VideoProcessor:      a.VideoProcessor,
					CurrentRefreshRate:  a.CurrentRefreshRate,
					CurrentResolutionH:  a.CurrentHorizontalResolution,
					CurrentResolutionV:  a.CurrentVerticalResolution,
					CurrentBitsPerPixel: a.CurrentBitsPerPixel,
					Status:              a.Status,
				}
				result.VideoAdapters = append(result.VideoAdapters, adapter)
			}
		}
	}

	result.Available = len(result.Monitors) > 0 || len(result.VideoAdapters) > 0
	if !result.Available && err != nil {
		result.Error = "failed to get display config: " + err.Error()
	}

	return result, nil
}
