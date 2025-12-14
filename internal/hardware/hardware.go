// Package hardware provides system hardware information collection.
package hardware

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects hardware information.
type Collector struct{}

// NewCollector creates a new hardware collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetHardwareInfo retrieves system/motherboard/BIOS information.
func (c *Collector) GetHardwareInfo() (*types.HardwareInfoResult, error) {
	return c.getHardwareInfo()
}

// GetUSBDevices retrieves USB device information.
func (c *Collector) GetUSBDevices() (*types.USBDevicesResult, error) {
	return c.getUSBDevices()
}

// GetPCIDevices retrieves PCI device information.
func (c *Collector) GetPCIDevices() (*types.PCIDevicesResult, error) {
	return c.getPCIDevices()
}

// GetBlockDevices retrieves block device topology.
func (c *Collector) GetBlockDevices() (*types.BlockDevicesResult, error) {
	return c.getBlockDevices()
}
