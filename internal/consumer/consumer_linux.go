//go:build linux

package consumer

import (
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getBluetoothDevices returns not-implemented on Linux.
// Future: Could use bluetoothctl or D-Bus API.
func (c *Collector) getBluetoothDevices() (*types.BluetoothDevicesResult, error) {
	return &types.BluetoothDevicesResult{
		Error:     "Bluetooth device enumeration not implemented on Linux",
		Available: false,
		Timestamp: time.Now(),
	}, nil
}

// getAudioDevices returns not-implemented on Linux.
// Future: Could use PulseAudio/PipeWire or ALSA.
func (c *Collector) getAudioDevices() (*types.AudioDevicesResult, error) {
	return &types.AudioDevicesResult{
		Error:     "Audio device enumeration not implemented on Linux",
		Available: false,
		Timestamp: time.Now(),
	}, nil
}

// getPrinters returns not-implemented on Linux.
// Future: Could use CUPS lpstat command.
func (c *Collector) getPrinters() (*types.PrintersResult, error) {
	return &types.PrintersResult{
		Error:     "Printer enumeration not implemented on Linux",
		Available: false,
		Timestamp: time.Now(),
	}, nil
}

// getDisplayConfig returns not-implemented on Linux.
// Future: Could use xrandr or DRM/KMS.
func (c *Collector) getDisplayConfig() (*types.DisplayConfigResult, error) {
	return &types.DisplayConfigResult{
		Error:     "Display configuration not implemented on Linux",
		Available: false,
		Timestamp: time.Now(),
	}, nil
}
