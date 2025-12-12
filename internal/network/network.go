// Package network provides network metrics collection across platforms.
package network

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects network metrics.
type Collector struct{}

// NewCollector creates a new network collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers network interface information.
func (c *Collector) Collect() (*types.NetworkInfo, error) {
	return c.collect()
}

// GetIOCounters returns network I/O statistics per interface.
func (c *Collector) GetIOCounters() (map[string]*types.NetworkIOCounters, error) {
	return c.getIOCounters()
}

// GetConnections returns active network connections.
func (c *Collector) GetConnections(kind string) ([]types.ConnectionInfo, error) {
	return c.getConnections(kind)
}
