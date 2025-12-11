//go:build windows

package temperature

import (
	"time"

	"github.com/yourusername/mcp-sysinfo/pkg/types"
)

// collect gathers temperature sensor information on Windows.
// Note: Windows temperature reading requires WMI or OpenHardwareMonitor.
// This is a stub implementation.
func (c *Collector) collect() (*types.TemperatureInfo, error) {
	// Windows temperature reading typically requires:
	// 1. WMI queries (Win32_TemperatureProbe is often empty)
	// 2. Open Hardware Monitor library
	// 3. Or vendor-specific tools

	// For now, return empty sensors
	// A full implementation would use WMI like:
	// SELECT * FROM MSAcpi_ThermalZoneTemperature
	// Or use OpenHardwareMonitorLib

	return &types.TemperatureInfo{
		Sensors:   []types.SensorInfo{},
		Timestamp: time.Now(),
	}, nil
}
