// Package resources provides process and system resource information collection.
package resources

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects process and system resource information.
type Collector struct{}

// NewCollector creates a new resources collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetProcessEnviron retrieves environment variables for a process.
func (c *Collector) GetProcessEnviron(pid int32) (*types.ProcessEnvironResult, error) {
	return c.getProcessEnviron(pid)
}

// GetIPCResources retrieves System V IPC resources (shared memory, semaphores, message queues).
func (c *Collector) GetIPCResources() (*types.IPCResourcesResult, error) {
	return c.getIPCResources()
}

// GetNamespaces retrieves Linux namespace information.
func (c *Collector) GetNamespaces() (*types.NamespacesResult, error) {
	return c.getNamespaces()
}

// GetCgroups retrieves cgroup information and limits.
func (c *Collector) GetCgroups() (*types.CgroupsResult, error) {
	return c.getCgroups()
}

// GetCapabilities retrieves process capabilities.
func (c *Collector) GetCapabilities(pid int32) (*types.CapabilitiesResult, error) {
	return c.getCapabilities(pid)
}
