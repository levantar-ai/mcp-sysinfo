// Package netconfig provides network configuration information collection.
package netconfig

import (
	"context"
	"net"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// GetConnectionTracking retrieves detailed connection tracking with process mapping.
func (c *Collector) GetConnectionTracking() (*types.ConnectionTrackingResult, error) {
	return c.getConnectionTracking()
}

// GetDNSStats retrieves DNS resolution statistics.
func (c *Collector) GetDNSStats() (*types.DNSStatsResult, error) {
	return c.getDNSStats()
}

// GetFirewallDeep retrieves comprehensive firewall analysis.
func (c *Collector) GetFirewallDeep() (*types.FirewallDeepResult, error) {
	return c.getFirewallDeep()
}

// GetWiFiMetrics retrieves WiFi signal and quality metrics.
func (c *Collector) GetWiFiMetrics() (*types.WiFiMetricsResult, error) {
	return c.getWiFiMetrics()
}

// GetNetworkLatency performs network latency probes.
func (c *Collector) GetNetworkLatency(targets []string) (*types.NetworkLatencyResult, error) {
	return c.getNetworkLatency(targets)
}

// tcpPing performs a TCP connect probe and returns the latency.
func tcpPing(host string, port string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start), nil
}

// httpPing performs an HTTP probe and returns the latency.
func httpPing(ctx context.Context, url string, timeout time.Duration) (time.Duration, error) {
	start := time.Now()
	// Simple TCP connection to HTTP port as a basic check
	// Full HTTP would require http package
	host := url
	port := "80"
	if len(url) > 8 && url[:8] == "https://" {
		host = url[8:]
		port = "443"
	} else if len(url) > 7 && url[:7] == "http://" {
		host = url[7:]
	}
	// Strip path
	for i, c := range host {
		if c == '/' {
			host = host[:i]
			break
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	return time.Since(start), nil
}
