//go:build linux

package hardware

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getHardwareInfo retrieves hardware info from /sys/class/dmi/id/.
func (c *Collector) getHardwareInfo() (*types.HardwareInfoResult, error) {
	dmiPath := "/sys/class/dmi/id"

	result := &types.HardwareInfoResult{
		System: types.SystemInfo{
			Manufacturer: readDMIFile(dmiPath, "sys_vendor"),
			ProductName:  readDMIFile(dmiPath, "product_name"),
			Version:      readDMIFile(dmiPath, "product_version"),
			SerialNumber: readDMIFile(dmiPath, "product_serial"),
			UUID:         readDMIFile(dmiPath, "product_uuid"),
			Family:       readDMIFile(dmiPath, "product_family"),
			SKU:          readDMIFile(dmiPath, "product_sku"),
		},
		BIOS: types.BIOSInfo{
			Vendor:  readDMIFile(dmiPath, "bios_vendor"),
			Version: readDMIFile(dmiPath, "bios_version"),
			Date:    readDMIFile(dmiPath, "bios_date"),
			Release: readDMIFile(dmiPath, "bios_release"),
		},
		Baseboard: types.BaseboardInfo{
			Manufacturer: readDMIFile(dmiPath, "board_vendor"),
			ProductName:  readDMIFile(dmiPath, "board_name"),
			Version:      readDMIFile(dmiPath, "board_version"),
			SerialNumber: readDMIFile(dmiPath, "board_serial"),
			AssetTag:     readDMIFile(dmiPath, "board_asset_tag"),
		},
		Chassis: types.ChassisInfo{
			Manufacturer: readDMIFile(dmiPath, "chassis_vendor"),
			Type:         chassisTypeToString(readDMIFile(dmiPath, "chassis_type")),
			Version:      readDMIFile(dmiPath, "chassis_version"),
			SerialNumber: readDMIFile(dmiPath, "chassis_serial"),
			AssetTag:     readDMIFile(dmiPath, "chassis_asset_tag"),
		},
		Timestamp: time.Now(),
	}

	return result, nil
}

// readDMIFile reads a DMI sysfs file and returns trimmed content.
func readDMIFile(basePath, filename string) string {
	path := filepath.Join(basePath, filename)
	// #nosec G304 -- reading from sysfs
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// chassisTypeToString converts chassis type number to string.
func chassisTypeToString(typeStr string) string {
	if typeStr == "" {
		return ""
	}
	typeNum, err := strconv.Atoi(typeStr)
	if err != nil {
		return typeStr
	}

	// SMBIOS chassis types
	chassisTypes := map[int]string{
		1:  "Other",
		2:  "Unknown",
		3:  "Desktop",
		4:  "Low Profile Desktop",
		5:  "Pizza Box",
		6:  "Mini Tower",
		7:  "Tower",
		8:  "Portable",
		9:  "Laptop",
		10: "Notebook",
		11: "Hand Held",
		12: "Docking Station",
		13: "All in One",
		14: "Sub Notebook",
		15: "Space-saving",
		16: "Lunch Box",
		17: "Main Server Chassis",
		18: "Expansion Chassis",
		19: "SubChassis",
		20: "Bus Expansion Chassis",
		21: "Peripheral Chassis",
		22: "RAID Chassis",
		23: "Rack Mount Chassis",
		24: "Sealed-case PC",
		25: "Multi-system chassis",
		26: "Compact PCI",
		27: "Advanced TCA",
		28: "Blade",
		29: "Blade Enclosure",
		30: "Tablet",
		31: "Convertible",
		32: "Detachable",
		33: "IoT Gateway",
		34: "Embedded PC",
		35: "Mini PC",
		36: "Stick PC",
	}

	if name, ok := chassisTypes[typeNum]; ok {
		return name
	}
	return typeStr
}

// getUSBDevices retrieves USB device information from /sys/bus/usb/devices/.
func (c *Collector) getUSBDevices() (*types.USBDevicesResult, error) {
	var devices []types.USBDevice

	usbPath := "/sys/bus/usb/devices"
	entries, err := os.ReadDir(usbPath)
	if err != nil {
		return &types.USBDevicesResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		devPath := filepath.Join(usbPath, entry.Name())

		// Skip root hubs and interfaces (those with : in name)
		if strings.Contains(entry.Name(), ":") {
			continue
		}

		// Read device info
		vendorID := readSysFile(devPath, "idVendor")
		productID := readSysFile(devPath, "idProduct")

		// Skip if no vendor/product ID (root hubs without this info)
		if vendorID == "" || productID == "" {
			continue
		}

		device := types.USBDevice{
			VendorID:     vendorID,
			ProductID:    productID,
			Vendor:       readSysFile(devPath, "manufacturer"),
			Product:      readSysFile(devPath, "product"),
			Manufacturer: readSysFile(devPath, "manufacturer"),
			SerialNumber: readSysFile(devPath, "serial"),
			Speed:        readSysFile(devPath, "speed") + " Mbps",
			MaxPower:     readSysFile(devPath, "bMaxPower"),
			Path:         devPath,
		}

		// Parse bus and device number
		if busNum, err := strconv.Atoi(readSysFile(devPath, "busnum")); err == nil {
			device.BusNum = busNum
		}
		if devNum, err := strconv.Atoi(readSysFile(devPath, "devnum")); err == nil {
			device.DevNum = devNum
		}

		// Get device class
		deviceClass := readSysFile(devPath, "bDeviceClass")
		device.DeviceClass = usbClassToString(deviceClass)

		// Get driver if bound
		driverLink := filepath.Join(devPath, "driver")
		if target, err := os.Readlink(driverLink); err == nil {
			device.Driver = filepath.Base(target)
		}

		devices = append(devices, device)
	}

	return &types.USBDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// readSysFile reads a sysfs file and returns trimmed content.
func readSysFile(basePath, filename string) string {
	path := filepath.Join(basePath, filename)
	// #nosec G304 -- reading from sysfs
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// usbClassToString converts USB device class to string.
func usbClassToString(classStr string) string {
	if classStr == "" {
		return ""
	}
	classNum, err := strconv.ParseInt(classStr, 16, 64)
	if err != nil {
		return classStr
	}

	usbClasses := map[int64]string{
		0x00: "Per Interface",
		0x01: "Audio",
		0x02: "CDC Communications",
		0x03: "HID",
		0x05: "Physical",
		0x06: "Image",
		0x07: "Printer",
		0x08: "Mass Storage",
		0x09: "Hub",
		0x0A: "CDC Data",
		0x0B: "Smart Card",
		0x0D: "Content Security",
		0x0E: "Video",
		0x0F: "Personal Healthcare",
		0x10: "Audio/Video",
		0xDC: "Diagnostic",
		0xE0: "Wireless Controller",
		0xEF: "Miscellaneous",
		0xFE: "Application Specific",
		0xFF: "Vendor Specific",
	}

	if name, ok := usbClasses[classNum]; ok {
		return name
	}
	return classStr
}

// getPCIDevices retrieves PCI device information from /sys/bus/pci/devices/.
func (c *Collector) getPCIDevices() (*types.PCIDevicesResult, error) {
	var devices []types.PCIDevice

	pciPath := "/sys/bus/pci/devices"
	entries, err := os.ReadDir(pciPath)
	if err != nil {
		return &types.PCIDevicesResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		devPath := filepath.Join(pciPath, entry.Name())

		device := types.PCIDevice{
			Slot:      entry.Name(),
			VendorID:  readSysFile(devPath, "vendor"),
			DeviceID:  readSysFile(devPath, "device"),
			SVendorID: readSysFile(devPath, "subsystem_vendor"),
			SDeviceID: readSysFile(devPath, "subsystem_device"),
			ClassID:   readSysFile(devPath, "class"),
			Revision:  readSysFile(devPath, "revision"),
		}

		// Clean up vendor/device IDs (remove 0x prefix)
		device.VendorID = strings.TrimPrefix(device.VendorID, "0x")
		device.DeviceID = strings.TrimPrefix(device.DeviceID, "0x")
		device.SVendorID = strings.TrimPrefix(device.SVendorID, "0x")
		device.SDeviceID = strings.TrimPrefix(device.SDeviceID, "0x")
		device.ClassID = strings.TrimPrefix(device.ClassID, "0x")
		device.Revision = strings.TrimPrefix(device.Revision, "0x")

		// Get class name from class ID
		device.Class = pciClassToString(device.ClassID)

		// Get driver if bound
		driverLink := filepath.Join(devPath, "driver")
		if target, err := os.Readlink(driverLink); err == nil {
			device.Driver = filepath.Base(target)
		}

		// Get module if available
		moduleLink := filepath.Join(devPath, "driver", "module")
		if target, err := os.Readlink(moduleLink); err == nil {
			device.Module = filepath.Base(target)
		}

		// Get IRQ
		if irq, err := strconv.Atoi(readSysFile(devPath, "irq")); err == nil {
			device.IRQ = irq
		}

		// Get NUMA node
		if numaNode, err := strconv.Atoi(readSysFile(devPath, "numa_node")); err == nil {
			device.NumaNode = numaNode
		}

		// Get IOMMU group
		iommuLink := filepath.Join(devPath, "iommu_group")
		if target, err := os.Readlink(iommuLink); err == nil {
			device.IOMMUGroup = filepath.Base(target)
		}

		devices = append(devices, device)
	}

	return &types.PCIDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// pciClassToString converts PCI class ID to human-readable string.
func pciClassToString(classID string) string {
	if len(classID) < 2 {
		return ""
	}

	// Extract major class (first 2 digits)
	majorClass := classID[:2]

	pciClasses := map[string]string{
		"00": "Unclassified",
		"01": "Mass Storage Controller",
		"02": "Network Controller",
		"03": "Display Controller",
		"04": "Multimedia Controller",
		"05": "Memory Controller",
		"06": "Bridge",
		"07": "Communication Controller",
		"08": "System Peripheral",
		"09": "Input Device Controller",
		"0a": "Docking Station",
		"0b": "Processor",
		"0c": "Serial Bus Controller",
		"0d": "Wireless Controller",
		"0e": "Intelligent Controller",
		"0f": "Satellite Communication Controller",
		"10": "Encryption Controller",
		"11": "Signal Processing Controller",
		"12": "Processing Accelerator",
		"13": "Non-Essential Instrumentation",
		"40": "Co-processor",
		"ff": "Unassigned Class",
	}

	if name, ok := pciClasses[strings.ToLower(majorClass)]; ok {
		return name
	}
	return ""
}

// getBlockDevices retrieves block device topology from /sys/block/.
func (c *Collector) getBlockDevices() (*types.BlockDevicesResult, error) {
	var devices []types.BlockDevice

	blockPath := "/sys/block"
	entries, err := os.ReadDir(blockPath)
	if err != nil {
		return &types.BlockDevicesResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		devPath := filepath.Join(blockPath, entry.Name())
		device := c.readBlockDevice(entry.Name(), devPath, "disk")

		// Read partitions (children)
		partEntries, err := os.ReadDir(devPath)
		if err == nil {
			for _, partEntry := range partEntries {
				if !partEntry.IsDir() {
					continue
				}
				// Partition directories start with device name
				if !strings.HasPrefix(partEntry.Name(), entry.Name()) {
					continue
				}
				partPath := filepath.Join(devPath, partEntry.Name())
				partition := c.readBlockDevice(partEntry.Name(), partPath, "part")
				device.Children = append(device.Children, partition)
			}
		}

		devices = append(devices, device)
	}

	return &types.BlockDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// readBlockDevice reads block device information from sysfs.
func (c *Collector) readBlockDevice(name, path, devType string) types.BlockDevice {
	device := types.BlockDevice{
		Name: name,
		Type: devType,
	}

	// Read size (in 512-byte sectors)
	if sizeStr := readSysFile(path, "size"); sizeStr != "" {
		if sectors, err := strconv.ParseUint(sizeStr, 10, 64); err == nil {
			device.Size = sectors * 512
		}
	}

	// Read device model
	device.Model = strings.TrimSpace(readSysFile(path, "device/model"))
	device.Vendor = strings.TrimSpace(readSysFile(path, "device/vendor"))

	// Read dev (major:minor)
	device.MajMin = readSysFile(path, "dev")

	// Read rotational (0 = SSD, 1 = HDD)
	if rotStr := readSysFile(path, "queue/rotational"); rotStr != "" {
		if rotStr == "0" {
			device.RotType = "SSD"
		} else {
			device.RotType = "HDD"
		}
	}

	// Read read-only flag
	if roStr := readSysFile(path, "ro"); roStr == "1" {
		device.ReadOnly = true
	}

	// Read removable flag
	if remStr := readSysFile(path, "removable"); remStr == "1" {
		device.Removable = true
	}

	// Try to get filesystem info from /dev/disk/by-* links
	devName := "/dev/" + name

	// Get UUID
	uuidPath := "/dev/disk/by-uuid"
	if uuidEntries, err := os.ReadDir(uuidPath); err == nil {
		for _, uuidEntry := range uuidEntries {
			linkPath := filepath.Join(uuidPath, uuidEntry.Name())
			if target, err := os.Readlink(linkPath); err == nil {
				if filepath.Base(target) == name {
					device.UUID = uuidEntry.Name()
					break
				}
			}
		}
	}

	// Get label
	labelPath := "/dev/disk/by-label"
	if labelEntries, err := os.ReadDir(labelPath); err == nil {
		for _, labelEntry := range labelEntries {
			linkPath := filepath.Join(labelPath, labelEntry.Name())
			if target, err := os.Readlink(linkPath); err == nil {
				if filepath.Base(target) == name {
					device.Label = labelEntry.Name()
					break
				}
			}
		}
	}

	// Get mountpoint from /proc/mounts
	device.Mountpoint, device.Fstype = getMountInfo(devName)

	return device
}

// getMountInfo gets mountpoint and fstype for a device from /proc/mounts.
func getMountInfo(device string) (mountpoint, fstype string) {
	// #nosec G304 -- reading from procfs
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			if fields[0] == device {
				return fields[1], fields[2]
			}
		}
	}

	return "", ""
}
