//go:build darwin

package consumer

import (
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getBluetoothDevices returns not-implemented on macOS.
// Future: Could use system_profiler SPBluetoothDataType.
func (c *Collector) getBluetoothDevices() (*types.BluetoothDevicesResult, error) {
	return &types.BluetoothDevicesResult{
		Error:     "Bluetooth device enumeration not implemented on macOS",
		Available: false,
		Timestamp: time.Now(),
	}, nil
}

// getAudioDevices returns not-implemented on macOS.
// Future: Could use system_profiler SPAudioDataType.
func (c *Collector) getAudioDevices() (*types.AudioDevicesResult, error) {
	return &types.AudioDevicesResult{
		Error:     "Audio device enumeration not implemented on macOS",
		Available: false,
		Timestamp: time.Now(),
	}, nil
}

// getPrinters returns not-implemented on macOS.
// Future: Could use lpstat or system_profiler SPPrintersDataType.
func (c *Collector) getPrinters() (*types.PrintersResult, error) {
	return &types.PrintersResult{
		Error:     "Printer enumeration not implemented on macOS",
		Available: false,
		Timestamp: time.Now(),
	}, nil
}

// getDisplayConfig returns not-implemented on macOS.
// Future: Could use system_profiler SPDisplaysDataType.
func (c *Collector) getDisplayConfig() (*types.DisplayConfigResult, error) {
	return &types.DisplayConfigResult{
		Error:     "Display configuration not implemented on macOS",
		Available: false,
		Timestamp: time.Now(),
	}, nil
}
