// Package disk provides disk metrics collection across platforms.
package disk

import (
	"github.com/yourusername/mcp-sysinfo/pkg/types"
)

// Collector collects disk metrics.
type Collector struct{}

// NewCollector creates a new disk collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers disk partition information.
// Platform-specific implementations are in disk_linux.go, disk_darwin.go, disk_windows.go
func (c *Collector) Collect() (*types.DiskInfo, error) {
	return c.collect()
}

// GetIOCounters returns disk I/O statistics.
func (c *Collector) GetIOCounters() (map[string]*types.DiskIOCounters, error) {
	return c.getIOCounters()
}

// calculatePercent calculates the percentage of used disk space.
func calculatePercent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

// bytesToHuman converts bytes to human-readable format.
func bytesToHuman(bytes uint64) (float64, string) {
	const unit = 1024
	if bytes < unit {
		return float64(bytes), "B"
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return float64(bytes) / float64(div), units[exp]
}
