//go:build windows

package netconfig

import (
	"bufio"
	"bytes"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getDNSServers retrieves DNS servers on Windows.
func (c *Collector) getDNSServers() (*types.DNSServersResult, error) {
	var servers []types.DNSServer

	// Use PowerShell to get DNS configuration
	psCmd := `Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq 2} | Select-Object InterfaceAlias,ServerAddresses | ConvertTo-Json`
	// #nosec G204 -- PowerShell is a system tool
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err == nil {
		servers = parsePowerShellDNS(output)
	}

	// Fallback to netsh
	if len(servers) == 0 {
		// #nosec G204 -- netsh is a system tool
		nsCmd := exec.Command("netsh", "interface", "ip", "show", "dns")
		nsOutput, err := nsCmd.Output()
		if err == nil {
			servers = parseNetshDNS(nsOutput)
		}
	}

	return &types.DNSServersResult{
		Servers:   servers,
		Count:     len(servers),
		Timestamp: time.Now(),
	}, nil
}

// parsePowerShellDNS parses PowerShell DNS output.
func parsePowerShellDNS(output []byte) []types.DNSServer {
	var servers []types.DNSServer
	content := string(output)

	// Simple parsing - look for IP addresses
	ipPattern := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	var currentInterface string
	priority := 1

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "InterfaceAlias") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentInterface = strings.Trim(line[idx+1:], `", `)
			}
		}
		if strings.Contains(line, "ServerAddresses") || strings.Contains(line, "\"") {
			matches := ipPattern.FindAllString(line, -1)
			for _, ip := range matches {
				servers = append(servers, types.DNSServer{
					Address:   ip,
					Interface: currentInterface,
					Type:      "interface",
					Priority:  priority,
				})
				priority++
			}
		}
	}

	return servers
}

// parseNetshDNS parses netsh dns output.
func parseNetshDNS(output []byte) []types.DNSServer {
	var servers []types.DNSServer
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentInterface string
	priority := 1

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Configuration for interface") {
			if idx := strings.Index(line, `"`); idx > 0 {
				end := strings.LastIndex(line, `"`)
				if end > idx {
					currentInterface = line[idx+1 : end]
				}
			}
		} else if strings.Contains(line, "DNS servers") || strings.Contains(line, "Statically Configured DNS") {
			// Next line should contain the IP
		} else if strings.TrimSpace(line) != "" && !strings.Contains(line, "Register") {
			ip := strings.TrimSpace(line)
			if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+\.\d+$`, ip); matched {
				servers = append(servers, types.DNSServer{
					Address:   ip,
					Interface: currentInterface,
					Type:      "interface",
					Priority:  priority,
				})
				priority++
			}
		}
	}

	return servers
}

// getRoutes retrieves the routing table on Windows.
func (c *Collector) getRoutes() (*types.RoutesResult, error) {
	var routes []types.Route

	// Use route print
	// #nosec G204 -- route is a system tool
	cmd := exec.Command("route", "print")
	output, err := cmd.Output()
	if err != nil {
		return &types.RoutesResult{
			Routes:    routes,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	routes = parseRouteWindows(output)

	return &types.RoutesResult{
		Routes:    routes,
		Count:     len(routes),
		Timestamp: time.Now(),
	}, nil
}

// parseRouteWindows parses Windows route print output.
func parseRouteWindows(output []byte) []types.Route {
	var routes []types.Route
	scanner := bufio.NewScanner(bytes.NewReader(output))

	inRoutes := false
	for scanner.Scan() {
		line := scanner.Text()

		// Look for IPv4 routes section
		if strings.Contains(line, "Network Destination") {
			inRoutes = true
			continue
		}
		if strings.Contains(line, "Persistent Routes") {
			inRoutes = false
			continue
		}

		if !inRoutes {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip headers and separators
		if fields[0] == "Network" || strings.HasPrefix(fields[0], "=") {
			continue
		}

		route := types.Route{
			Destination: fields[0],
			Mask:        fields[1],
			Gateway:     fields[2],
		}

		if len(fields) >= 4 {
			route.Interface = fields[3]
		}
		if len(fields) >= 5 {
			if metric, err := strconv.Atoi(fields[4]); err == nil {
				route.Metric = metric
			}
		}

		routes = append(routes, route)
	}

	return routes
}

// getFirewallRules retrieves Windows Firewall rules.
func (c *Collector) getFirewallRules() (*types.FirewallRulesResult, error) {
	var rules []types.FirewallRule
	enabled := false

	// Check if firewall is enabled
	// #nosec G204 -- netsh is a system tool
	statusCmd := exec.Command("netsh", "advfirewall", "show", "allprofiles", "state")
	statusOutput, err := statusCmd.Output()
	if err == nil {
		if strings.Contains(string(statusOutput), "ON") {
			enabled = true
		}
	}

	// Get firewall rules (may require admin)
	// #nosec G204 -- netsh is a system tool
	rulesCmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all")
	rulesOutput, err := rulesCmd.Output()
	if err == nil {
		rules = parseNetshFirewall(rulesOutput)
	}

	return &types.FirewallRulesResult{
		Rules:     rules,
		Count:     len(rules),
		Source:    "windows",
		Enabled:   enabled,
		Timestamp: time.Now(),
	}, nil
}

// parseNetshFirewall parses netsh firewall rules output.
func parseNetshFirewall(output []byte) []types.FirewallRule {
	var rules []types.FirewallRule
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentRule types.FirewallRule
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "Rule Name:") {
			// Save previous rule if exists
			if currentRule.Description != "" {
				rules = append(rules, currentRule)
			}
			currentRule = types.FirewallRule{
				Description: strings.TrimPrefix(line, "Rule Name:"),
				Enabled:     true,
			}
			currentRule.Description = strings.TrimSpace(currentRule.Description)
		} else if strings.HasPrefix(line, "Enabled:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Enabled:"))
			currentRule.Enabled = strings.EqualFold(val, "Yes")
		} else if strings.HasPrefix(line, "Direction:") {
			currentRule.Direction = strings.TrimSpace(strings.TrimPrefix(line, "Direction:"))
		} else if strings.HasPrefix(line, "Action:") {
			action := strings.TrimSpace(strings.TrimPrefix(line, "Action:"))
			if strings.EqualFold(action, "Allow") {
				currentRule.Action = "ACCEPT"
			} else if strings.EqualFold(action, "Block") {
				currentRule.Action = "DROP"
			} else {
				currentRule.Action = action
			}
		} else if strings.HasPrefix(line, "Protocol:") {
			currentRule.Protocol = strings.TrimSpace(strings.TrimPrefix(line, "Protocol:"))
		} else if strings.HasPrefix(line, "LocalPort:") {
			currentRule.Port = strings.TrimSpace(strings.TrimPrefix(line, "LocalPort:"))
		}
	}

	// Add last rule
	if currentRule.Description != "" {
		rules = append(rules, currentRule)
	}

	return rules
}

// getListeningPorts retrieves listening ports on Windows.
func (c *Collector) getListeningPorts() (*types.ListeningPortsResult, error) {
	var ports []types.ListeningPort

	// Use netstat with process names
	// #nosec G204 -- netstat is a system tool
	cmd := exec.Command("netstat", "-ano")
	output, err := cmd.Output()
	if err != nil {
		return &types.ListeningPortsResult{
			Ports:     ports,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	ports = parseNetstatWindows(output)

	return &types.ListeningPortsResult{
		Ports:     ports,
		Count:     len(ports),
		Timestamp: time.Now(),
	}, nil
}

// parseNetstatWindows parses Windows netstat output.
func parseNetstatWindows(output []byte) []types.ListeningPort {
	var ports []types.ListeningPort
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "LISTENING") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		protocol := strings.ToLower(fields[0])
		local := fields[1]

		// Parse address:port
		if idx := strings.LastIndex(local, ":"); idx > 0 {
			address := local[:idx]
			portStr := local[idx+1:]
			port, _ := strconv.ParseUint(portStr, 10, 16)

			var pid int32
			if len(fields) >= 5 {
				if p, err := strconv.ParseInt(fields[len(fields)-1], 10, 32); err == nil {
					pid = int32(p)
				}
			}

			ports = append(ports, types.ListeningPort{
				Protocol: protocol,
				Address:  address,
				Port:     uint16(port),
				PID:      pid,
				State:    "LISTEN",
			})
		}
	}

	return ports
}

// getARPTable retrieves the ARP table on Windows.
func (c *Collector) getARPTable() (*types.ARPTableResult, error) {
	var entries []types.ARPEntry

	// #nosec G204 -- arp is a system tool
	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return &types.ARPTableResult{
			Entries:   entries,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	entries = parseARPWindows(output)

	return &types.ARPTableResult{
		Entries:   entries,
		Count:     len(entries),
		Timestamp: time.Now(),
	}, nil
}

// parseARPWindows parses Windows arp -a output.
func parseARPWindows(output []byte) []types.ARPEntry {
	var entries []types.ARPEntry
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentInterface string
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "Interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentInterface = parts[1]
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// Check if first field looks like an IP
		if !strings.Contains(fields[0], ".") {
			continue
		}

		entryType := "dynamic"
		if strings.Contains(line, "static") {
			entryType = "static"
		}

		entries = append(entries, types.ARPEntry{
			IPAddress:  fields[0],
			MACAddress: fields[1],
			Interface:  currentInterface,
			Type:       entryType,
			State:      "reachable",
		})
	}

	return entries
}

// getNetworkStats retrieves network statistics on Windows.
func (c *Collector) getNetworkStats() (*types.NetworkStatsResult, error) {
	stats := types.NetworkStats{}

	// Get TCP stats
	// #nosec G204 -- netstat is a system tool
	cmd := exec.Command("netstat", "-s", "-p", "tcp")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.Contains(line, "Active Opens") {
				stats.TCPConnections = extractFirstNumber(line)
			}
		}
	}

	// Count connections by state
	// #nosec G204 -- netstat is a system tool
	stateCmd := exec.Command("netstat", "-an")
	stateOutput, err := stateCmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(stateOutput))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "ESTABLISHED") {
				stats.TCPEstablished++
			} else if strings.Contains(line, "TIME_WAIT") {
				stats.TCPTimeWait++
			} else if strings.Contains(line, "CLOSE_WAIT") {
				stats.TCPCloseWait++
			}
			if strings.HasPrefix(strings.TrimSpace(line), "UDP") {
				stats.UDPConnections++
			}
		}
	}

	return &types.NetworkStatsResult{
		Stats:     stats,
		Timestamp: time.Now(),
	}, nil
}

// extractFirstNumber extracts the first number from a string.
func extractFirstNumber(s string) int {
	pattern := regexp.MustCompile(`(\d+)`)
	matches := pattern.FindStringSubmatch(s)
	if matches != nil {
		n, _ := strconv.Atoi(matches[1])
		return n
	}
	return 0
}
