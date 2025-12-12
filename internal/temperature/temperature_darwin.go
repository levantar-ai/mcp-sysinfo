//go:build darwin

package temperature

import (
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers temperature sensor information on macOS.
// Note: macOS requires SMC access which needs elevated privileges or
// third-party tools. This is a stub implementation.
func (c *Collector) collect() (*types.TemperatureInfo, error) {
	// macOS temperature reading requires SMC access
	// This typically requires:
	// 1. Root privileges
	// 2. IOKit framework with SMCReadKey
	// 3. Or using external tools like 'osx-cpu-temp'

	// For now, return empty sensors
	// A full implementation would use IOKit to read SMC keys like:
	// TC0P - CPU proximity
	// TC0D - CPU die
	// TG0P - GPU proximity
	// etc.

	return &types.TemperatureInfo{
		Sensors:   []types.SensorInfo{},
		Timestamp: time.Now(),
	}, nil
}
