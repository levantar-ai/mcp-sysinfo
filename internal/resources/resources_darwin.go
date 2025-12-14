//go:build darwin

package resources

import (
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getProcessEnviron returns empty result on macOS (Linux-specific feature).
func (c *Collector) getProcessEnviron(pid int32) (*types.ProcessEnvironResult, error) {
	return &types.ProcessEnvironResult{
		PID:       pid,
		Environ:   make(map[string]string),
		Timestamp: time.Now(),
	}, nil
}

// getIPCResources returns empty result on macOS.
// System V IPC is available on macOS but accessed differently.
func (c *Collector) getIPCResources() (*types.IPCResourcesResult, error) {
	return &types.IPCResourcesResult{
		Timestamp: time.Now(),
	}, nil
}

// getNamespaces returns empty result on macOS (Linux-specific feature).
func (c *Collector) getNamespaces() (*types.NamespacesResult, error) {
	return &types.NamespacesResult{
		Namespaces: []types.Namespace{},
		Count:      0,
		Timestamp:  time.Now(),
	}, nil
}

// getCgroups returns empty result on macOS (Linux-specific feature).
func (c *Collector) getCgroups() (*types.CgroupsResult, error) {
	return &types.CgroupsResult{
		Version:   0,
		Groups:    []types.CgroupInfo{},
		Timestamp: time.Now(),
	}, nil
}

// getCapabilities returns empty result on macOS (Linux-specific feature).
func (c *Collector) getCapabilities(pid int32) (*types.CapabilitiesResult, error) {
	return &types.CapabilitiesResult{
		PID:       pid,
		Timestamp: time.Now(),
	}, nil
}
