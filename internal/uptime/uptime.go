// Package uptime provides system uptime collection across platforms.
package uptime

import (
	"fmt"
	"time"

	"github.com/yourusername/mcp-sysinfo/pkg/types"
)

// Collector collects uptime metrics.
type Collector struct{}

// NewCollector creates a new uptime collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers system uptime information.
func (c *Collector) Collect() (*types.UptimeInfo, error) {
	return c.collect()
}

// formatUptime formats duration as human-readable string.
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%d days, %d hours, %d minutes, %d seconds", days, hours, minutes, seconds)
	}
	if hours > 0 {
		return fmt.Sprintf("%d hours, %d minutes, %d seconds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%d minutes, %d seconds", minutes, seconds)
	}
	return fmt.Sprintf("%d seconds", seconds)
}
