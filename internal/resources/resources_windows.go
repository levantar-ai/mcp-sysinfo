//go:build windows

package resources

import (
	"fmt"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getProcessEnviron returns a not implemented error on Windows.
func (c *Collector) getProcessEnviron(pid int32) (*types.ProcessEnvironResult, error) {
	return nil, fmt.Errorf("process environ not available on Windows")
}

// getIPCResources returns empty result on Windows.
func (c *Collector) getIPCResources() (*types.IPCResourcesResult, error) {
	return &types.IPCResourcesResult{
		Timestamp: time.Now(),
	}, nil
}

// getNamespaces returns empty result on Windows (Linux-specific feature).
func (c *Collector) getNamespaces() (*types.NamespacesResult, error) {
	return &types.NamespacesResult{
		Namespaces: []types.Namespace{},
		Count:      0,
		Timestamp:  time.Now(),
	}, nil
}

// getCgroups returns empty result on Windows (Linux-specific feature).
func (c *Collector) getCgroups() (*types.CgroupsResult, error) {
	return &types.CgroupsResult{
		Version:   0,
		Groups:    []types.CgroupInfo{},
		Timestamp: time.Now(),
	}, nil
}

// getCapabilities returns a not implemented error on Windows.
func (c *Collector) getCapabilities(pid int32) (*types.CapabilitiesResult, error) {
	return nil, fmt.Errorf("capabilities not available on Windows")
}
