// Package kernel provides kernel module and driver information collection.
package kernel

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects kernel module and driver information.
type Collector struct{}

// NewCollector creates a new kernel collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetKernelModules retrieves loaded kernel modules.
func (c *Collector) GetKernelModules() (*types.KernelModulesResult, error) {
	return c.getKernelModules()
}

// GetLoadedDrivers retrieves loaded device drivers.
func (c *Collector) GetLoadedDrivers() (*types.LoadedDriversResult, error) {
	return c.getLoadedDrivers()
}
