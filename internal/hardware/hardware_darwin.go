//go:build darwin

package hardware

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// systemProfilerHardware represents the JSON structure from system_profiler.
type systemProfilerHardware struct {
	SPHardwareDataType []struct {
		MachineName          string `json:"machine_name"`
		MachineModel         string `json:"machine_model"`
		ModelNumber          string `json:"model_number"`
		ChipType             string `json:"chip_type"`
		NumberProcessors     string `json:"number_processors"`
		TotalNumberOfCores   string `json:"total_number_of_cores"`
		Memory               string `json:"physical_memory"`
		SerialNumber         string `json:"serial_number"`
		HardwareUUID         string `json:"platform_UUID"`
		ProvisioningUDID     string `json:"provisioning_UDID"`
		ActivationLockStatus string `json:"activation_lock_status"`
		BootROMVersion       string `json:"boot_rom_version"`
		SMCVersion           string `json:"SMC_version_system"`
	} `json:"SPHardwareDataType"`
}

// systemProfilerUSB represents USB data from system_profiler.
type systemProfilerUSB struct {
	SPUSBDataType []usbItem `json:"SPUSBDataType"`
}

type usbItem struct {
	Name         string    `json:"_name"`
	VendorID     string    `json:"vendor_id"`
	ProductID    string    `json:"product_id"`
	Manufacturer string    `json:"manufacturer"`
	Serial       string    `json:"serial_num"`
	Speed        string    `json:"device_speed"`
	BusPower     string    `json:"bus_power"`
	BusPowerUsed string    `json:"bus_power_used"`
	Items        []usbItem `json:"_items"`
}

// getHardwareInfo retrieves hardware info using system_profiler.
func (c *Collector) getHardwareInfo() (*types.HardwareInfoResult, error) {
	// #nosec G204 -- no user input
	cmd := exec.Command("system_profiler", "SPHardwareDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		return &types.HardwareInfoResult{
			Timestamp: time.Now(),
		}, nil
	}

	var profilerData systemProfilerHardware
	if err := json.Unmarshal(output, &profilerData); err != nil {
		return &types.HardwareInfoResult{
			Timestamp: time.Now(),
		}, nil
	}

	result := &types.HardwareInfoResult{
		System: types.SystemInfo{
			Manufacturer: "Apple Inc.",
			ProductName:  "",
			UUID:         "",
		},
		BIOS: types.BIOSInfo{
			Vendor: "Apple Inc.",
		},
		Baseboard: types.BaseboardInfo{
			Manufacturer: "Apple Inc.",
		},
		Timestamp: time.Now(),
	}

	if len(profilerData.SPHardwareDataType) > 0 {
		hw := profilerData.SPHardwareDataType[0]
		result.System.ProductName = hw.MachineName
		result.System.Version = hw.MachineModel
		result.System.SerialNumber = hw.SerialNumber
		result.System.UUID = hw.HardwareUUID
		result.System.SKU = hw.ModelNumber
		result.BIOS.Version = hw.BootROMVersion
		result.Baseboard.ProductName = hw.MachineModel
	}

	return result, nil
}

// getUSBDevices retrieves USB devices using system_profiler.
func (c *Collector) getUSBDevices() (*types.USBDevicesResult, error) {
	var devices []types.USBDevice

	// #nosec G204 -- no user input
	cmd := exec.Command("system_profiler", "SPUSBDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		return &types.USBDevicesResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	var profilerData systemProfilerUSB
	if err := json.Unmarshal(output, &profilerData); err != nil {
		return &types.USBDevicesResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// Recursively process USB items
	for _, item := range profilerData.SPUSBDataType {
		devices = append(devices, extractUSBDevices(item)...)
	}

	return &types.USBDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// extractUSBDevices recursively extracts USB devices from nested structure.
func extractUSBDevices(item usbItem) []types.USBDevice {
	var devices []types.USBDevice

	// Only add if has vendor/product ID (skip hubs/controllers)
	if item.VendorID != "" && item.ProductID != "" {
		device := types.USBDevice{
			Product:      item.Name,
			Manufacturer: item.Manufacturer,
			SerialNumber: item.Serial,
			Speed:        item.Speed,
		}

		// Parse vendor ID (format: "0x1234  (Apple Inc.)")
		if parts := strings.SplitN(item.VendorID, " ", 2); len(parts) >= 1 {
			device.VendorID = strings.TrimPrefix(parts[0], "0x")
			if len(parts) > 1 && device.Manufacturer == "" {
				// Extract vendor name from parentheses
				device.Vendor = strings.Trim(parts[1], " ()")
			}
		}

		// Parse product ID
		if parts := strings.SplitN(item.ProductID, " ", 2); len(parts) >= 1 {
			device.ProductID = strings.TrimPrefix(parts[0], "0x")
		}

		// Parse power usage
		if item.BusPowerUsed != "" {
			device.MaxPower = item.BusPowerUsed
		}

		devices = append(devices, device)
	}

	// Process nested items
	for _, child := range item.Items {
		devices = append(devices, extractUSBDevices(child)...)
	}

	return devices
}

// getPCIDevices retrieves PCI devices using system_profiler.
func (c *Collector) getPCIDevices() (*types.PCIDevicesResult, error) {
	var devices []types.PCIDevice

	// Use ioreg to get PCI devices
	// #nosec G204 -- no user input
	cmd := exec.Command("ioreg", "-r", "-c", "IOPCIDevice", "-a")
	output, err := cmd.Output()
	if err != nil {
		// Try system_profiler as fallback
		return c.getPCIDevicesFromSystemProfiler()
	}

	// Parse plist output
	devices = parsePCIFromIOReg(output)

	return &types.PCIDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// getPCIDevicesFromSystemProfiler uses system_profiler as fallback.
func (c *Collector) getPCIDevicesFromSystemProfiler() (*types.PCIDevicesResult, error) {
	var devices []types.PCIDevice

	// #nosec G204 -- no user input
	cmd := exec.Command("system_profiler", "SPPCIDataType")
	output, err := cmd.Output()
	if err != nil {
		return &types.PCIDevicesResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// Parse text output (not JSON for this data type)
	lines := strings.Split(string(output), "\n")
	var currentDevice *types.PCIDevice

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Device name starts a new entry (not indented much)
		if !strings.Contains(line, ":") && len(line) > 0 && line[0] != ' ' {
			if currentDevice != nil {
				devices = append(devices, *currentDevice)
			}
			currentDevice = &types.PCIDevice{
				Device: line,
			}
			continue
		}

		if currentDevice == nil {
			continue
		}

		// Parse key: value pairs
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])

			switch key {
			case "Slot":
				currentDevice.Slot = value
			case "Vendor ID":
				currentDevice.VendorID = strings.TrimPrefix(value, "0x")
			case "Device ID":
				currentDevice.DeviceID = strings.TrimPrefix(value, "0x")
			case "Revision ID":
				currentDevice.Revision = strings.TrimPrefix(value, "0x")
			case "Subsystem Vendor ID":
				currentDevice.SVendorID = strings.TrimPrefix(value, "0x")
			case "Subsystem ID":
				currentDevice.SDeviceID = strings.TrimPrefix(value, "0x")
			case "Driver Installed":
				currentDevice.Driver = value
			}
		}
	}

	if currentDevice != nil {
		devices = append(devices, *currentDevice)
	}

	return &types.PCIDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// parsePCIFromIOReg parses PCI devices from ioreg plist output.
func parsePCIFromIOReg(output []byte) []types.PCIDevice {
	var devices []types.PCIDevice

	// Simple parsing - look for vendor-id and device-id patterns
	lines := strings.Split(string(output), "\n")
	var currentDevice types.PCIDevice
	inDevice := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "IOPCIDevice") {
			if inDevice && currentDevice.VendorID != "" {
				devices = append(devices, currentDevice)
			}
			currentDevice = types.PCIDevice{}
			inDevice = true
			continue
		}

		if !inDevice {
			continue
		}

		// Parse key-value pairs from plist
		if strings.Contains(line, "<key>vendor-id</key>") {
			// Next line contains value
			continue
		}
		if strings.Contains(line, "<key>device-id</key>") {
			continue
		}
		if strings.Contains(line, "<key>name</key>") {
			continue
		}
		if strings.Contains(line, "<key>IOName</key>") {
			continue
		}

		// Extract data values
		if strings.HasPrefix(line, "<data>") && strings.HasSuffix(line, "</data>") {
			// Handle binary data (base64)
			continue
		}
		if strings.HasPrefix(line, "<string>") && strings.HasSuffix(line, "</string>") {
			value := strings.TrimPrefix(line, "<string>")
			value = strings.TrimSuffix(value, "</string>")
			if currentDevice.Device == "" {
				currentDevice.Device = value
			}
		}
	}

	if inDevice && currentDevice.VendorID != "" {
		devices = append(devices, currentDevice)
	}

	return devices
}

// getBlockDevices retrieves block devices using diskutil.
func (c *Collector) getBlockDevices() (*types.BlockDevicesResult, error) {
	var devices []types.BlockDevice

	// #nosec G204 -- no user input
	cmd := exec.Command("diskutil", "list", "-plist")
	output, err := cmd.Output()
	if err != nil {
		return &types.BlockDevicesResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// Parse plist output
	devices = parseDiskutilPlist(output)

	return &types.BlockDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// parseDiskutilPlist parses diskutil list -plist output.
func parseDiskutilPlist(output []byte) []types.BlockDevice {
	var devices []types.BlockDevice

	// Simple parsing - look for disk patterns
	lines := strings.Split(string(output), "\n")
	var currentDisk *types.BlockDevice
	var currentPartitions []types.BlockDevice
	inArray := false
	inDict := false
	lastKey := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "<key>AllDisks</key>") {
			continue
		}
		if strings.Contains(line, "<key>AllDisksAndPartitions</key>") {
			inArray = true
			continue
		}
		if inArray && line == "</array>" {
			inArray = false
			continue
		}
		if line == "<dict>" {
			if inArray && currentDisk == nil {
				currentDisk = &types.BlockDevice{Type: "disk"}
				currentPartitions = nil
			}
			inDict = true
			continue
		}
		if line == "</dict>" {
			inDict = false
			if currentDisk != nil && currentDisk.Name != "" {
				currentDisk.Children = currentPartitions
				devices = append(devices, *currentDisk)
				currentDisk = nil
			}
			continue
		}

		if !inDict {
			continue
		}

		// Parse keys
		if strings.HasPrefix(line, "<key>") && strings.HasSuffix(line, "</key>") {
			lastKey = strings.TrimPrefix(line, "<key>")
			lastKey = strings.TrimSuffix(lastKey, "</key>")
			continue
		}

		// Parse values
		if strings.HasPrefix(line, "<string>") && strings.HasSuffix(line, "</string>") {
			value := strings.TrimPrefix(line, "<string>")
			value = strings.TrimSuffix(value, "</string>")

			if currentDisk != nil {
				switch lastKey {
				case "DeviceIdentifier":
					currentDisk.Name = value
				case "MountPoint":
					currentDisk.Mountpoint = value
				case "Content":
					currentDisk.Fstype = value
				case "VolumeName":
					currentDisk.Label = value
				case "VolumeUUID":
					currentDisk.UUID = value
				}
			}
		}

		if strings.HasPrefix(line, "<integer>") && strings.HasSuffix(line, "</integer>") {
			value := strings.TrimPrefix(line, "<integer>")
			value = strings.TrimSuffix(value, "</integer>")

			if currentDisk != nil && lastKey == "Size" {
				if size, err := strconv.ParseUint(value, 10, 64); err == nil {
					currentDisk.Size = size
				}
			}
		}
	}

	return devices
}
