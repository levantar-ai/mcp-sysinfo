//go:build windows

package hardware

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// wmiComputerSystem represents Win32_ComputerSystem WMI class.
type wmiComputerSystem struct {
	Manufacturer string `json:"Manufacturer"`
	Model        string `json:"Model"`
	Name         string `json:"Name"`
	SystemFamily string `json:"SystemFamily"`
	SystemType   string `json:"SystemType"`
}

// wmiBIOS represents Win32_BIOS WMI class.
type wmiBIOS struct {
	Manufacturer    string `json:"Manufacturer"`
	Name            string `json:"Name"`
	ReleaseDate     string `json:"ReleaseDate"`
	SerialNumber    string `json:"SerialNumber"`
	SMBIOSBIOSVersion string `json:"SMBIOSBIOSVersion"`
	Version         string `json:"Version"`
}

// wmiBaseBoard represents Win32_BaseBoard WMI class.
type wmiBaseBoard struct {
	Manufacturer string `json:"Manufacturer"`
	Product      string `json:"Product"`
	SerialNumber string `json:"SerialNumber"`
	Version      string `json:"Version"`
	Tag          string `json:"Tag"`
}

// wmiSystemEnclosure represents Win32_SystemEnclosure WMI class.
type wmiSystemEnclosure struct {
	Manufacturer string `json:"Manufacturer"`
	ChassisTypes []int  `json:"ChassisTypes"`
	SerialNumber string `json:"SerialNumber"`
	SMBIOSAssetTag string `json:"SMBIOSAssetTag"`
	Version      string `json:"Version"`
}

// wmiUSBDevice represents Win32_USBControllerDevice WMI class.
type wmiUSBDevice struct {
	DeviceID    string `json:"DeviceID"`
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Status      string `json:"Status"`
	Manufacturer string `json:"Manufacturer"`
	Service     string `json:"Service"`
}

// wmiPnPEntity represents Win32_PnPEntity for USB/PCI devices.
type wmiPnPEntity struct {
	DeviceID        string `json:"DeviceID"`
	Name            string `json:"Name"`
	Description     string `json:"Description"`
	Manufacturer    string `json:"Manufacturer"`
	Service         string `json:"Service"`
	HardwareID      []string `json:"HardwareID"`
	CompatibleID    []string `json:"CompatibleID"`
	ClassGuid       string `json:"ClassGuid"`
	PNPClass        string `json:"PNPClass"`
}

// wmiDiskDrive represents Win32_DiskDrive WMI class.
type wmiDiskDrive struct {
	DeviceID     string `json:"DeviceID"`
	Model        string `json:"Model"`
	Size         string `json:"Size"`
	MediaType    string `json:"MediaType"`
	SerialNumber string `json:"SerialNumber"`
	InterfaceType string `json:"InterfaceType"`
	Partitions   int    `json:"Partitions"`
	Index        int    `json:"Index"`
}

// wmiLogicalDisk represents Win32_LogicalDisk WMI class.
type wmiLogicalDisk struct {
	DeviceID     string `json:"DeviceID"`
	VolumeName   string `json:"VolumeName"`
	VolumeSerialNumber string `json:"VolumeSerialNumber"`
	FileSystem   string `json:"FileSystem"`
	Size         string `json:"Size"`
	FreeSpace    string `json:"FreeSpace"`
	DriveType    int    `json:"DriveType"`
}

// getHardwareInfo retrieves hardware info using WMI.
func (c *Collector) getHardwareInfo() (*types.HardwareInfoResult, error) {
	result := &types.HardwareInfoResult{
		Timestamp: time.Now(),
	}

	// Get computer system info
	cs := queryWMISingle[wmiComputerSystem]("SELECT * FROM Win32_ComputerSystem")
	if cs != nil {
		result.System = types.SystemInfo{
			Manufacturer: cs.Manufacturer,
			ProductName:  cs.Model,
			Family:       cs.SystemFamily,
		}
	}

	// Get BIOS info
	bios := queryWMISingle[wmiBIOS]("SELECT * FROM Win32_BIOS")
	if bios != nil {
		result.BIOS = types.BIOSInfo{
			Vendor:  bios.Manufacturer,
			Version: bios.SMBIOSBIOSVersion,
			Date:    parseCIMDateTime(bios.ReleaseDate),
		}
		result.System.SerialNumber = bios.SerialNumber
	}

	// Get baseboard info
	bb := queryWMISingle[wmiBaseBoard]("SELECT * FROM Win32_BaseBoard")
	if bb != nil {
		result.Baseboard = types.BaseboardInfo{
			Manufacturer: bb.Manufacturer,
			ProductName:  bb.Product,
			Version:      bb.Version,
			SerialNumber: bb.SerialNumber,
		}
	}

	// Get chassis info
	enc := queryWMISingle[wmiSystemEnclosure]("SELECT * FROM Win32_SystemEnclosure")
	if enc != nil {
		result.Chassis = types.ChassisInfo{
			Manufacturer: enc.Manufacturer,
			Version:      enc.Version,
			SerialNumber: enc.SerialNumber,
			AssetTag:     enc.SMBIOSAssetTag,
		}
		if len(enc.ChassisTypes) > 0 {
			result.Chassis.Type = chassisTypeToString(enc.ChassisTypes[0])
		}
	}

	// Get system UUID from ComputerSystemProduct
	uuid := queryWMIValue("SELECT UUID FROM Win32_ComputerSystemProduct", "UUID")
	if uuid != "" {
		result.System.UUID = uuid
	}

	return result, nil
}

// chassisTypeToString converts Windows chassis type to string.
func chassisTypeToString(chassisType int) string {
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
		17: "Main System Chassis",
		18: "Expansion Chassis",
		19: "SubChassis",
		20: "Bus Expansion Chassis",
		21: "Peripheral Chassis",
		22: "Storage Chassis",
		23: "Rack Mount Chassis",
		24: "Sealed-Case PC",
		30: "Tablet",
		31: "Convertible",
		32: "Detachable",
	}

	if name, ok := chassisTypes[chassisType]; ok {
		return name
	}
	return strconv.Itoa(chassisType)
}

// parseCIMDateTime parses WMI CIM_DATETIME format.
func parseCIMDateTime(cimDate string) string {
	if len(cimDate) < 8 {
		return cimDate
	}
	// Format: YYYYMMDD...
	return cimDate[:4] + "-" + cimDate[4:6] + "-" + cimDate[6:8]
}

// getUSBDevices retrieves USB devices using WMI.
func (c *Collector) getUSBDevices() (*types.USBDevicesResult, error) {
	var devices []types.USBDevice

	// Query USB devices
	pnpDevices := queryWMIMultiple[wmiPnPEntity]("SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'USB%'")

	for _, pnp := range pnpDevices {
		device := types.USBDevice{
			Product:      pnp.Name,
			Manufacturer: pnp.Manufacturer,
			Driver:       pnp.Service,
			DeviceClass:  pnp.PNPClass,
			Path:         pnp.DeviceID,
		}

		// Parse VID/PID from DeviceID (format: USB\VID_XXXX&PID_YYYY\...)
		if strings.Contains(pnp.DeviceID, "VID_") && strings.Contains(pnp.DeviceID, "PID_") {
			parts := strings.Split(pnp.DeviceID, "\\")
			if len(parts) >= 2 {
				vidPid := parts[1]
				if vidIdx := strings.Index(vidPid, "VID_"); vidIdx >= 0 {
					endIdx := vidIdx + 8 // VID_XXXX
					if endIdx <= len(vidPid) {
						device.VendorID = vidPid[vidIdx+4 : endIdx]
					}
				}
				if pidIdx := strings.Index(vidPid, "PID_"); pidIdx >= 0 {
					endIdx := pidIdx + 8 // PID_YYYY
					if endIdx <= len(vidPid) {
						device.ProductID = vidPid[pidIdx+4 : endIdx]
					}
				}
			}
			// Serial number may be in third part
			if len(parts) >= 3 {
				device.SerialNumber = parts[2]
			}
		}

		devices = append(devices, device)
	}

	return &types.USBDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// getPCIDevices retrieves PCI devices using WMI.
func (c *Collector) getPCIDevices() (*types.PCIDevicesResult, error) {
	var devices []types.PCIDevice

	// Query PCI devices
	pnpDevices := queryWMIMultiple[wmiPnPEntity]("SELECT * FROM Win32_PnPEntity WHERE DeviceID LIKE 'PCI%'")

	for _, pnp := range pnpDevices {
		device := types.PCIDevice{
			Device:  pnp.Name,
			Vendor:  pnp.Manufacturer,
			Driver:  pnp.Service,
			Class:   pnp.PNPClass,
		}

		// Parse VEN/DEV from DeviceID (format: PCI\VEN_XXXX&DEV_YYYY&SUBSYS_...\...)
		if strings.Contains(pnp.DeviceID, "VEN_") && strings.Contains(pnp.DeviceID, "DEV_") {
			parts := strings.Split(pnp.DeviceID, "\\")
			if len(parts) >= 2 {
				venDev := parts[1]
				if venIdx := strings.Index(venDev, "VEN_"); venIdx >= 0 {
					endIdx := venIdx + 8 // VEN_XXXX
					if endIdx <= len(venDev) {
						device.VendorID = venDev[venIdx+4 : endIdx]
					}
				}
				if devIdx := strings.Index(venDev, "DEV_"); devIdx >= 0 {
					endIdx := devIdx + 8 // DEV_YYYY
					if endIdx <= len(venDev) {
						device.DeviceID = venDev[devIdx+4 : endIdx]
					}
				}
				if subIdx := strings.Index(venDev, "SUBSYS_"); subIdx >= 0 {
					endIdx := subIdx + 15 // SUBSYS_XXXXXXXX
					if endIdx <= len(venDev) {
						subsys := venDev[subIdx+7 : endIdx]
						if len(subsys) >= 8 {
							device.SDeviceID = subsys[:4]
							device.SVendorID = subsys[4:8]
						}
					}
				}
				if revIdx := strings.Index(venDev, "REV_"); revIdx >= 0 {
					endIdx := revIdx + 6 // REV_XX
					if endIdx <= len(venDev) {
						device.Revision = venDev[revIdx+4 : endIdx]
					}
				}
			}
			// Slot info may be in third part
			if len(parts) >= 3 {
				device.Slot = parts[2]
			}
		}

		devices = append(devices, device)
	}

	return &types.PCIDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// getBlockDevices retrieves block devices using WMI.
func (c *Collector) getBlockDevices() (*types.BlockDevicesResult, error) {
	var devices []types.BlockDevice

	// Query disk drives
	drives := queryWMIMultiple[wmiDiskDrive]("SELECT * FROM Win32_DiskDrive")

	for _, drive := range drives {
		device := types.BlockDevice{
			Name:   drive.DeviceID,
			Model:  drive.Model,
			Serial: drive.SerialNumber,
			Type:   "disk",
		}

		// Parse size
		if size, err := strconv.ParseUint(drive.Size, 10, 64); err == nil {
			device.Size = size
		}

		// Determine SSD vs HDD
		if strings.Contains(strings.ToLower(drive.MediaType), "ssd") ||
			strings.Contains(strings.ToLower(drive.Model), "ssd") ||
			strings.Contains(strings.ToLower(drive.InterfaceType), "nvme") {
			device.RotType = "SSD"
		} else if strings.Contains(strings.ToLower(drive.MediaType), "fixed") {
			device.RotType = "HDD"
		}

		// Check if removable
		if strings.Contains(strings.ToLower(drive.MediaType), "removable") {
			device.Removable = true
		}

		devices = append(devices, device)
	}

	// Add logical disk info (partitions with mount points)
	logicalDisks := queryWMIMultiple[wmiLogicalDisk]("SELECT * FROM Win32_LogicalDisk")
	for _, ld := range logicalDisks {
		partition := types.BlockDevice{
			Name:       ld.DeviceID,
			Label:      ld.VolumeName,
			Fstype:     ld.FileSystem,
			Mountpoint: ld.DeviceID + "\\",
			Type:       "part",
		}

		if size, err := strconv.ParseUint(ld.Size, 10, 64); err == nil {
			partition.Size = size
		}

		// Check drive type
		switch ld.DriveType {
		case 2:
			partition.Removable = true
		case 5:
			partition.Type = "rom"
		}

		// Add as child to first disk (simplified - could use Win32_DiskDriveToDiskPartition)
		if len(devices) > 0 {
			devices[0].Children = append(devices[0].Children, partition)
		} else {
			devices = append(devices, partition)
		}
	}

	return &types.BlockDevicesResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// queryWMISingle queries WMI and returns the first result.
func queryWMISingle[T any](query string) *T {
	results := queryWMIMultiple[T](query)
	if len(results) > 0 {
		return &results[0]
	}
	return nil
}

// queryWMIMultiple queries WMI and returns all results.
func queryWMIMultiple[T any](query string) []T {
	// Use PowerShell to query WMI and output as JSON
	// #nosec G204 -- query is hardcoded
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-WmiObject -Query '"+query+"' | ConvertTo-Json -Compress")
	output, err := cmd.Output()
	if err != nil {
		return nil
	}

	// Handle empty result
	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" || outputStr == "null" {
		return nil
	}

	var results []T

	// Try parsing as array first
	if err := json.Unmarshal([]byte(outputStr), &results); err != nil {
		// Try parsing as single object
		var single T
		if err := json.Unmarshal([]byte(outputStr), &single); err == nil {
			results = append(results, single)
		}
	}

	return results
}

// queryWMIValue queries WMI for a single value.
func queryWMIValue(query, field string) string {
	// #nosec G204 -- query and field are hardcoded
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-WmiObject -Query '"+query+"')."+field)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}
