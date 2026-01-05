// Package gpu provides GPU diagnostics collection across platforms.
package gpu

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects GPU information.
type Collector struct{}

// NewCollector creates a new GPU collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetGPUInfo returns comprehensive GPU information.
func (c *Collector) GetGPUInfo() (*types.GPUInfoResult, error) {
	return c.getGPUInfo()
}
