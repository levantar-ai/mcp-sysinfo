// Package filesystem provides filesystem information collection.
package filesystem

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects filesystem information.
type Collector struct{}

// NewCollector creates a new filesystem collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetMounts retrieves mounted filesystems.
func (c *Collector) GetMounts() (*types.MountsResult, error) {
	return c.getMounts()
}

// GetDiskIO retrieves disk I/O statistics.
func (c *Collector) GetDiskIO() (*types.DiskIOResult, error) {
	return c.getDiskIO()
}

// GetOpenFiles retrieves open file descriptors.
func (c *Collector) GetOpenFiles() (*types.OpenFilesResult, error) {
	return c.getOpenFiles()
}

// GetInodeUsage retrieves inode usage for filesystems.
func (c *Collector) GetInodeUsage() (*types.InodeUsageResult, error) {
	return c.getInodeUsage()
}
