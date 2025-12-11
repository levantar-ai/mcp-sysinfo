// Package memory provides memory metrics collection across platforms.
package memory

import (
	"github.com/yourusername/mcp-sysinfo/pkg/types"
)

// Collector collects memory metrics.
type Collector struct{}

// NewCollector creates a new memory collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers memory information.
// Platform-specific implementations are in memory_linux.go, memory_darwin.go, memory_windows.go
func (c *Collector) Collect() (*types.MemoryInfo, error) {
	return c.collect()
}

// GetSwap returns swap memory information.
func (c *Collector) GetSwap() (*types.SwapInfo, error) {
	return c.getSwap()
}

// calculatePercent calculates the percentage of used memory.
func calculatePercent(used, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(used) / float64(total) * 100
}

// bytesToHuman converts bytes to human-readable format (for logging/debugging).
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
