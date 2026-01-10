// Package consumer provides consumer-focused diagnostics for common end-user
// hardware issues including Bluetooth, audio devices, printers, and displays.
// These queries address the most common Windows 10/11 consumer support issues.
package consumer

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects consumer device diagnostics.
type Collector struct{}

// NewCollector creates a new consumer diagnostics collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetBluetoothDevices retrieves Bluetooth devices and adapter status.
func (c *Collector) GetBluetoothDevices() (*types.BluetoothDevicesResult, error) {
	return c.getBluetoothDevices()
}

// GetAudioDevices retrieves audio playback and recording devices.
func (c *Collector) GetAudioDevices() (*types.AudioDevicesResult, error) {
	return c.getAudioDevices()
}

// GetPrinters retrieves printer information and spooler status.
func (c *Collector) GetPrinters() (*types.PrintersResult, error) {
	return c.getPrinters()
}

// GetDisplayConfig retrieves display/monitor configuration and video adapters.
func (c *Collector) GetDisplayConfig() (*types.DisplayConfigResult, error) {
	return c.getDisplayConfig()
}
