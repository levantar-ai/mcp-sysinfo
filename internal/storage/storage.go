// Package storage provides storage diagnostics including SMART health,
// I/O latency, volume status (ZFS/LVM/RAID), and mount monitoring.
package storage

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects storage diagnostics.
type Collector struct{}

// NewCollector creates a new storage collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetSMARTHealth retrieves SMART disk health information.
// Requires smartctl or platform-specific APIs.
func (c *Collector) GetSMARTHealth() (*types.SMARTHealthResult, error) {
	return c.getSMARTHealth()
}

// GetIOLatency retrieves disk I/O latency statistics.
func (c *Collector) GetIOLatency() (*types.IOLatencyResult, error) {
	return c.getIOLatency()
}

// GetVolumeStatus retrieves volume manager status (ZFS, LVM, RAID, Storage Spaces).
func (c *Collector) GetVolumeStatus() (*types.VolumeStatusResult, error) {
	return c.getVolumeStatus()
}

// GetMountChanges retrieves current mounts and recent mount changes.
func (c *Collector) GetMountChanges() (*types.MountChangesResult, error) {
	return c.getMountChanges()
}

// GetFSEvents returns information about filesystem event monitoring capabilities.
// Note: This is informational only - real-time event streaming requires a different approach.
func (c *Collector) GetFSEvents() (*types.FSEventsResult, error) {
	return c.getFSEvents()
}
