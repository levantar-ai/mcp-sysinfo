// Package osinfo provides OS and system profile information collection.
package osinfo

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects OS and system profile information.
type Collector struct{}

// NewCollector creates a new osinfo collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetOSInfo retrieves OS version, kernel, and platform information.
func (c *Collector) GetOSInfo() (*types.OSInfoResult, error) {
	return c.getOSInfo()
}

// GetSystemProfile retrieves a summary of CPU, memory, disk, and network.
func (c *Collector) GetSystemProfile() (*types.SystemProfileResult, error) {
	return c.getSystemProfile()
}

// GetServiceManagerInfo retrieves service manager status (systemd/launchd/SCM).
func (c *Collector) GetServiceManagerInfo() (*types.ServiceManagerInfoResult, error) {
	return c.getServiceManagerInfo()
}

// GetCloudEnvironment detects cloud provider and instance metadata.
func (c *Collector) GetCloudEnvironment() (*types.CloudEnvironmentResult, error) {
	return c.getCloudEnvironment()
}
