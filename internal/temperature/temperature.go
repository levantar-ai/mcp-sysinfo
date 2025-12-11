// Package temperature provides temperature sensor collection across platforms.
package temperature

import (
	"github.com/yourusername/mcp-sysinfo/pkg/types"
)

// Collector collects temperature metrics.
type Collector struct{}

// NewCollector creates a new temperature collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers temperature sensor information.
func (c *Collector) Collect() (*types.TemperatureInfo, error) {
	return c.collect()
}
