//go:build darwin

package netconfig

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getDNSServers retrieves DNS servers on macOS.
func (c *Collector) getDNSServers() (*types.DNSServersResult, error) {
	var servers []types.DNSServer

	// Use scutil to get DNS configuration
	cmd := exec.Command("/usr/sbin/scutil", "--dns")
	output, err := cmd.Output()
	if err == nil {
		servers = parseScutilDNS(output)
	}

	// Fallback to /etc/resolv.conf
	if len(servers) == 0 {
		// #nosec G304 -- reading from known system file
		content, err := os.ReadFile("/etc/resolv.conf")
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(content))
			priority := 1
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "nameserver") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						servers = append(servers, types.DNSServer{
							Address:  fields[1],
							Type:     "system",
							Priority: priority,
						})
						priority++
					}
				}
			}
		}
	}

	return &types.DNSServersResult{
		Servers:   servers,
		Count:     len(servers),
		Timestamp: time.Now(),
	}, nil
}

// parseScutilDNS parses scutil --dns output.
func parseScutilDNS(output []byte) []types.DNSServer {
	var servers []types.DNSServer
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentInterface string
	priority := 1

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "resolver #") {
			currentInterface = ""
		} else if strings.Contains(line, "if_index") {
			if idx := strings.Index(line, ":"); idx > 0 {
				parts := strings.Fields(line[idx+1:])
				if len(parts) >= 2 {
					currentInterface = parts[1]
					currentInterface = strings.Trim(currentInterface, "()")
				}
			}
		} else if strings.Contains(line, "nameserver") {
			if idx := strings.Index(line, ":"); idx > 0 {
				addr := strings.TrimSpace(line[idx+1:])
				if addr != "" {
					servers = append(servers, types.DNSServer{
						Address:   addr,
						Interface: currentInterface,
						Type:      "scutil",
						Priority:  priority,
					})
					priority++
				}
			}
		}
	}

	return servers
}

// getRoutes retrieves the routing table on macOS.
func (c *Collector) getRoutes() (*types.RoutesResult, error) {
	var routes []types.Route

	cmd := exec.Command("/usr/sbin/netstat", "-rn")
	output, err := cmd.Output()
	if err != nil {
		return &types.RoutesResult{
			Routes:    routes,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	routes = parseNetstatRoute(output)

	return &types.RoutesResult{
		Routes:    routes,
		Count:     len(routes),
		Timestamp: time.Now(),
	}, nil
}

// parseNetstatRoute parses netstat -rn output on macOS.
func parseNetstatRoute(output []byte) []types.Route {
	var routes []types.Route
	scanner := bufio.NewScanner(bytes.NewReader(output))

	inRoutes := false
	for scanner.Scan() {
		line := scanner.Text()

		// Skip until we hit the routing table
		if strings.HasPrefix(line, "Destination") {
			inRoutes = true
			continue
		}
		if !inRoutes {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		route := types.Route{
			Destination: fields[0],
			Gateway:     fields[1],
			Flags:       fields[2],
		}

		// Interface is usually the last field
		route.Interface = fields[len(fields)-1]

		routes = append(routes, route)
	}

	return routes
}

// getFirewallRules retrieves firewall rules from pf on macOS.
func (c *Collector) getFirewallRules() (*types.FirewallRulesResult, error) {
	var rules []types.FirewallRule
	enabled := false

	// Check if pf is enabled
	cmd := exec.Command("/sbin/pfctl", "-s", "info")
	output, err := cmd.Output()
	if err == nil {
		if strings.Contains(string(output), "Enabled") {
			enabled = true
		}
	}

	// Get rules (requires root)
	// #nosec G204 -- pfctl is a system tool
	rulesCmd := exec.Command("/sbin/pfctl", "-s", "rules")
	rulesOutput, err := rulesCmd.Output()
	if err == nil {
		rules = parsePFRules(rulesOutput)
	}

	return &types.FirewallRulesResult{
		Rules:     rules,
		Count:     len(rules),
		Source:    "pf",
		Enabled:   enabled,
		Timestamp: time.Now(),
	}, nil
}

// parsePFRules parses pfctl rules output.
func parsePFRules(output []byte) []types.FirewallRule {
	var rules []types.FirewallRule
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		rule := types.FirewallRule{
			Enabled: true,
		}

		// Parse action
		if strings.HasPrefix(line, "pass") {
			rule.Action = "ACCEPT"
		} else if strings.HasPrefix(line, "block") {
			rule.Action = "DROP"
		} else {
			continue
		}

		// Parse direction
		if strings.Contains(line, " in ") {
			rule.Direction = "in"
		} else if strings.Contains(line, " out ") {
			rule.Direction = "out"
		}

		// Parse protocol
		if strings.Contains(line, "proto tcp") {
			rule.Protocol = "tcp"
		} else if strings.Contains(line, "proto udp") {
			rule.Protocol = "udp"
		} else if strings.Contains(line, "proto icmp") {
			rule.Protocol = "icmp"
		}

		// Parse interface
		if idx := strings.Index(line, " on "); idx > 0 {
			rest := line[idx+4:]
			if spaceIdx := strings.Index(rest, " "); spaceIdx > 0 {
				rule.Interface = rest[:spaceIdx]
			}
		}

		rules = append(rules, rule)
	}

	return rules
}

// getListeningPorts retrieves listening ports on macOS.
func (c *Collector) getListeningPorts() (*types.ListeningPortsResult, error) {
	var ports []types.ListeningPort

	// Use lsof for listening ports
	cmd := exec.Command("/usr/sbin/lsof", "-i", "-n", "-P")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to netstat
		return c.getListeningPortsNetstat()
	}

	ports = parseLsof(output)

	return &types.ListeningPortsResult{
		Ports:     ports,
		Count:     len(ports),
		Timestamp: time.Now(),
	}, nil
}

// parseLsof parses lsof output for listening ports.
func parseLsof(output []byte) []types.ListeningPort {
	var ports []types.ListeningPort
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	seen := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		// Check for LISTEN state
		if !strings.Contains(line, "LISTEN") && !strings.Contains(fields[7], "UDP") {
			continue
		}

		processName := fields[0]
		pidStr := fields[1]
		pid, _ := strconv.ParseInt(pidStr, 10, 32)

		// Parse address:port from fields[8]
		addr := fields[8]
		if idx := strings.LastIndex(addr, ":"); idx > 0 {
			address := addr[:idx]
			portStr := addr[idx+1:]
			port, _ := strconv.ParseUint(portStr, 10, 16)

			protocol := "tcp"
			if strings.Contains(fields[7], "UDP") {
				protocol = "udp"
			}

			// Avoid duplicates
			key := protocol + ":" + address + ":" + portStr
			if seen[key] {
				continue
			}
			seen[key] = true

			ports = append(ports, types.ListeningPort{
				Protocol:    protocol,
				Address:     address,
				Port:        uint16(port),
				PID:         int32(pid),
				ProcessName: processName,
				State:       "LISTEN",
			})
		}
	}

	return ports
}

// getListeningPortsNetstat uses netstat as fallback.
func (c *Collector) getListeningPortsNetstat() (*types.ListeningPortsResult, error) {
	var ports []types.ListeningPort

	cmd := exec.Command("/usr/sbin/netstat", "-an")
	output, err := cmd.Output()
	if err != nil {
		return &types.ListeningPortsResult{
			Ports:     ports,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "LISTEN") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address
		local := fields[3]
		if idx := strings.LastIndex(local, "."); idx > 0 {
			address := local[:idx]
			portStr := local[idx+1:]
			port, _ := strconv.ParseUint(portStr, 10, 16)

			protocol := "tcp"
			if strings.HasPrefix(fields[0], "udp") {
				protocol = "udp"
			}

			ports = append(ports, types.ListeningPort{
				Protocol: protocol,
				Address:  address,
				Port:     uint16(port),
				State:    "LISTEN",
			})
		}
	}

	return &types.ListeningPortsResult{
		Ports:     ports,
		Count:     len(ports),
		Timestamp: time.Now(),
	}, nil
}

// getARPTable retrieves the ARP table on macOS.
func (c *Collector) getARPTable() (*types.ARPTableResult, error) {
	var entries []types.ARPEntry

	cmd := exec.Command("/usr/sbin/arp", "-an")
	output, err := cmd.Output()
	if err != nil {
		return &types.ARPTableResult{
			Entries:   entries,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// Pattern: ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
	pattern := regexp.MustCompile(`\(([^)]+)\)\s+at\s+([^\s]+)\s+on\s+(\S+)`)

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		entryType := "dynamic"
		if strings.Contains(line, "permanent") {
			entryType = "static"
		}

		entries = append(entries, types.ARPEntry{
			IPAddress:  matches[1],
			MACAddress: matches[2],
			Interface:  matches[3],
			Type:       entryType,
			State:      "reachable",
		})
	}

	return &types.ARPTableResult{
		Entries:   entries,
		Count:     len(entries),
		Timestamp: time.Now(),
	}, nil
}

// getNetworkStats retrieves network statistics on macOS.
func (c *Collector) getNetworkStats() (*types.NetworkStatsResult, error) {
	stats := types.NetworkStats{}

	// Get TCP connection stats using netstat
	cmd := exec.Command("/usr/sbin/netstat", "-s", "-p", "tcp")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.Contains(line, "connection") {
				if n := extractNumber(line); n > 0 {
					stats.TCPConnections += n
				}
			}
		}
	}

	// Get interface stats
	ifCmd := exec.Command("/usr/sbin/netstat", "-ib")
	ifOutput, err := ifCmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(ifOutput))
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 10 {
				// Skip loopback
				if strings.HasPrefix(fields[0], "lo") {
					continue
				}
				if pktsIn, err := strconv.ParseUint(fields[4], 10, 64); err == nil {
					stats.PacketsReceived += pktsIn
				}
				if pktsOut, err := strconv.ParseUint(fields[6], 10, 64); err == nil {
					stats.PacketsSent += pktsOut
				}
				if bytesIn, err := strconv.ParseUint(fields[5], 10, 64); err == nil {
					stats.BytesReceived += bytesIn
				}
				if bytesOut, err := strconv.ParseUint(fields[8], 10, 64); err == nil {
					stats.BytesSent += bytesOut
				}
			}
		}
	}

	return &types.NetworkStatsResult{
		Stats:     stats,
		Timestamp: time.Now(),
	}, nil
}

// extractNumber extracts the first number from a string.
func extractNumber(s string) int {
	pattern := regexp.MustCompile(`(\d+)`)
	matches := pattern.FindStringSubmatch(s)
	if matches != nil {
		n, _ := strconv.Atoi(matches[1])
		return n
	}
	return 0
}
