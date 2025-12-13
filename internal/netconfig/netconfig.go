// Package netconfig provides network configuration information collection.
package netconfig

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects network configuration information.
type Collector struct{}

// NewCollector creates a new network configuration collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetDNSServers retrieves configured DNS servers.
func (c *Collector) GetDNSServers() (*types.DNSServersResult, error) {
	return c.getDNSServers()
}

// GetRoutes retrieves the routing table.
func (c *Collector) GetRoutes() (*types.RoutesResult, error) {
	return c.getRoutes()
}

// GetFirewallRules retrieves firewall rules.
func (c *Collector) GetFirewallRules() (*types.FirewallRulesResult, error) {
	return c.getFirewallRules()
}

// GetListeningPorts retrieves listening network ports.
func (c *Collector) GetListeningPorts() (*types.ListeningPortsResult, error) {
	return c.getListeningPorts()
}

// GetARPTable retrieves the ARP table.
func (c *Collector) GetARPTable() (*types.ARPTableResult, error) {
	return c.getARPTable()
}

// GetNetworkStats retrieves network stack statistics.
func (c *Collector) GetNetworkStats() (*types.NetworkStatsResult, error) {
	return c.getNetworkStats()
}
