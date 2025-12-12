// Package process provides process metrics collection across platforms.
package process

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects process metrics.
type Collector struct{}

// NewCollector creates a new process collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers a list of all running processes.
func (c *Collector) Collect() (*types.ProcessList, error) {
	return c.collect()
}

// GetProcess returns information about a specific process by PID.
func (c *Collector) GetProcess(pid int32) (*types.ProcessInfo, error) {
	return c.getProcess(pid)
}

// GetTopProcesses returns the top N processes by CPU or memory usage.
func (c *Collector) GetTopProcesses(n int, sortBy string) ([]types.ProcessInfo, error) {
	return c.getTopProcesses(n, sortBy)
}
