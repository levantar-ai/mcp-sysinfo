// Package state provides system state information collection.
package state

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects system state information.
type Collector struct{}

// NewCollector creates a new state collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetVMInfo detects if running in a virtual machine or container.
func (c *Collector) GetVMInfo() (*types.VMInfoResult, error) {
	return c.getVMInfo()
}

// GetTimezone retrieves timezone and locale information.
func (c *Collector) GetTimezone() (*types.TimezoneInfoResult, error) {
	return c.getTimezone()
}

// GetNTPStatus retrieves NTP synchronization status.
func (c *Collector) GetNTPStatus() (*types.NTPStatusResult, error) {
	return c.getNTPStatus()
}

// GetCoreDumps retrieves core dump information.
func (c *Collector) GetCoreDumps() (*types.CoreDumpsResult, error) {
	return c.getCoreDumps()
}

// GetPowerState retrieves power/battery state.
func (c *Collector) GetPowerState() (*types.PowerStateResult, error) {
	return c.getPowerState()
}

// GetNUMATopology retrieves NUMA topology information.
func (c *Collector) GetNUMATopology() (*types.NUMATopologyResult, error) {
	return c.getNUMATopology()
}
