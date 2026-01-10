//go:build windows

package netconfig

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getConnectionTracking retrieves detailed connection tracking on Windows.
func (c *Collector) getConnectionTracking() (*types.ConnectionTrackingResult, error) {
	var connections []types.TrackedConnection
	byState := make(map[string]int)
	byProtocol := make(map[string]int)
	byProcess := make(map[string]int)
	remoteIPs := make(map[string]struct{})

	// Use netstat with process info
	netstat, err := cmdexec.LookPath("netstat")
	if err == nil {
		// #nosec G204 -- netstat path is from LookPath
		cmd := cmdexec.Command(netstat, "-ano")
		output, err := cmd.Output()
		if err == nil {
			connections = parseNetstatWindows(output)
		}
	}

	// Build summary
	for _, conn := range connections {
		byState[conn.State]++
		byProtocol[conn.Protocol]++
		if conn.ProcessName != "" {
			byProcess[conn.ProcessName]++
		}
		if conn.RemoteAddr != "" && conn.RemoteAddr != "0.0.0.0" && conn.RemoteAddr != "::" {
			remoteIPs[conn.RemoteAddr] = struct{}{}
		}
	}

	return &types.ConnectionTrackingResult{
		Connections: connections,
		Summary: types.ConnectionSummary{
			TotalConnections: len(connections),
			ByState:          byState,
			ByProtocol:       byProtocol,
			ByProcess:        byProcess,
			UniqueRemoteIPs:  len(remoteIPs),
		},
		Count:     len(connections),
		Timestamp: time.Now(),
	}, nil
}

// parseNetstatWindows parses netstat -ano output on Windows.
func parseNetstatWindows(output []byte) []types.TrackedConnection {
	var connections []types.TrackedConnection
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Skip header lines
		if fields[0] == "Proto" || fields[0] == "Active" {
			continue
		}

		conn := types.TrackedConnection{}

		// Protocol
		proto := strings.ToLower(fields[0])
		if strings.HasPrefix(proto, "tcp") {
			conn.Protocol = "tcp"
		} else if strings.HasPrefix(proto, "udp") {
			conn.Protocol = "udp"
		} else {
			continue
		}

		// Local address
		local := fields[1]
		if idx := strings.LastIndex(local, ":"); idx >= 0 {
			conn.LocalAddr = local[:idx]
			if port, err := strconv.ParseUint(local[idx+1:], 10, 16); err == nil {
				conn.LocalPort = uint16(port)
			}
		}

		// Remote address
		remote := fields[2]
		if idx := strings.LastIndex(remote, ":"); idx >= 0 {
			conn.RemoteAddr = remote[:idx]
			if port, err := strconv.ParseUint(remote[idx+1:], 10, 16); err == nil {
				conn.RemotePort = uint16(port)
			}
		}

		// State (TCP only)
		stateIdx := 3
		if conn.Protocol == "tcp" && len(fields) > stateIdx {
			conn.State = fields[stateIdx]
			stateIdx++
		}

		// PID
		if len(fields) > stateIdx {
			if pid, err := strconv.ParseInt(fields[stateIdx], 10, 32); err == nil {
				conn.PID = int32(pid)
			}
		}

		connections = append(connections, conn)
	}

	return connections
}

// getDNSStats retrieves DNS resolution statistics on Windows.
func (c *Collector) getDNSStats() (*types.DNSStatsResult, error) {
	result := &types.DNSStatsResult{
		Timestamp: time.Now(),
	}

	// Use PowerShell to get DNS client configuration
	ps, err := cmdexec.LookPath("powershell")
	if err == nil {
		// Get DNS servers
		// #nosec G204 -- powershell path is from LookPath
		cmd := cmdexec.Command(ps, "-NoProfile", "-Command",
			"Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(output)), "\n")
			priority := 1
			for _, line := range lines {
				addr := strings.TrimSpace(line)
				if addr != "" {
					result.Servers = append(result.Servers, types.DNSServerStats{
						Address:  addr,
						Type:     "system",
						Priority: priority,
					})
					priority++
				}
			}
		}

		// Get DNS cache statistics
		// #nosec G204 -- powershell path is from LookPath
		cacheCmd := cmdexec.Command(ps, "-NoProfile", "-Command",
			"(Get-DnsClientCache | Measure-Object).Count")
		cacheOutput, err := cacheCmd.Output()
		if err == nil {
			count, _ := strconv.Atoi(strings.TrimSpace(string(cacheOutput)))
			result.Cache = &types.DNSCache{
				Entries: count,
			}
		}
	}

	// Test DNS server reachability
	for i := range result.Servers {
		start := time.Now()
		conn, err := net.DialTimeout("udp", result.Servers[i].Address+":53", 2*time.Second)
		if err == nil {
			result.Servers[i].Reachable = true
			result.Servers[i].LatencyMs = float64(time.Since(start).Microseconds()) / 1000
			conn.Close()
		}
	}

	return result, nil
}

// getFirewallDeep retrieves comprehensive firewall analysis on Windows.
func (c *Collector) getFirewallDeep() (*types.FirewallDeepResult, error) {
	result := &types.FirewallDeepResult{
		Backend:   "windows_firewall",
		Timestamp: time.Now(),
	}

	ps, err := cmdexec.LookPath("powershell")
	if err != nil {
		return result, nil
	}

	// Get firewall profile status
	// #nosec G204 -- powershell path is from LookPath
	cmd := cmdexec.Command(ps, "-NoProfile", "-Command",
		"Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json")
	output, err := cmd.Output()
	if err == nil {
		result.Zones = parseWindowsFirewallProfiles(output)
		for _, zone := range result.Zones {
			if zone.Active {
				result.Enabled = true
				break
			}
		}
	}

	// Get firewall rules (limited to first 100 for performance)
	// #nosec G204 -- powershell path is from LookPath
	rulesCmd := cmdexec.Command(ps, "-NoProfile", "-Command",
		"Get-NetFirewallRule -Enabled True | Select-Object -First 100 Name, DisplayName, Direction, Action, Protocol | ConvertTo-Json")
	rulesOutput, err := rulesCmd.Output()
	if err == nil {
		table := parseWindowsFirewallRules(rulesOutput)
		result.Tables = []types.FirewallTable{table}
	}

	// Calculate statistics
	for _, table := range result.Tables {
		for _, chain := range table.Chains {
			for _, rule := range chain.Rules {
				result.Statistics.TotalRules++
				switch strings.ToLower(rule.Action) {
				case "allow":
					result.Statistics.AcceptRules++
				case "block":
					result.Statistics.DropRules++
				}
			}
		}
	}

	return result, nil
}

// parseWindowsFirewallProfiles parses firewall profile JSON.
func parseWindowsFirewallProfiles(output []byte) []types.FirewallZone {
	var zones []types.FirewallZone

	// Simple parsing - look for key patterns
	lines := strings.Split(string(output), "\n")
	var current *types.FirewallZone

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\"Name\":") {
			if current != nil {
				zones = append(zones, *current)
			}
			current = &types.FirewallZone{}
			// Extract name
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				current.Name = strings.Trim(strings.TrimSuffix(parts[1], ","), "\" ")
			}
		} else if current != nil {
			if strings.Contains(line, "\"Enabled\":") {
				current.Active = strings.Contains(line, "true") || strings.Contains(line, "True")
			} else if strings.Contains(line, "\"DefaultInboundAction\":") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					current.Target = strings.Trim(strings.TrimSuffix(parts[1], ","), "\" ")
				}
			}
		}
	}

	if current != nil {
		zones = append(zones, *current)
	}

	return zones
}

// parseWindowsFirewallRules parses firewall rules JSON.
func parseWindowsFirewallRules(output []byte) types.FirewallTable {
	table := types.FirewallTable{
		Name:   "filter",
		Family: "inet",
	}

	inbound := types.FirewallChain{Name: "Inbound"}
	outbound := types.FirewallChain{Name: "Outbound"}

	lines := strings.Split(string(output), "\n")
	var current *types.FirewallRuleDeep
	ruleNum := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\"Name\":") {
			if current != nil {
				if current.Direction == "Inbound" {
					inbound.Rules = append(inbound.Rules, *current)
				} else {
					outbound.Rules = append(outbound.Rules, *current)
				}
			}
			ruleNum++
			current = &types.FirewallRuleDeep{
				Number:  ruleNum,
				Enabled: true,
			}
		} else if current != nil {
			if strings.Contains(line, "\"Direction\":") {
				if strings.Contains(line, "1") || strings.Contains(line, "Inbound") {
					current.Direction = "Inbound"
				} else {
					current.Direction = "Outbound"
				}
			} else if strings.Contains(line, "\"Action\":") {
				if strings.Contains(line, "2") || strings.Contains(line, "Allow") {
					current.Action = "ALLOW"
				} else {
					current.Action = "BLOCK"
				}
			} else if strings.Contains(line, "\"Protocol\":") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					proto := strings.Trim(strings.TrimSuffix(parts[1], ","), "\" ")
					switch proto {
					case "6":
						current.Protocol = "tcp"
					case "17":
						current.Protocol = "udp"
					default:
						current.Protocol = proto
					}
				}
			}
		}
	}

	if current != nil {
		if current.Direction == "Inbound" {
			inbound.Rules = append(inbound.Rules, *current)
		} else {
			outbound.Rules = append(outbound.Rules, *current)
		}
	}

	table.Chains = []types.FirewallChain{inbound, outbound}
	return table
}

// getWiFiMetrics retrieves WiFi metrics on Windows.
func (c *Collector) getWiFiMetrics() (*types.WiFiMetricsResult, error) {
	result := &types.WiFiMetricsResult{
		Timestamp: time.Now(),
	}

	netsh, err := cmdexec.LookPath("netsh")
	if err == nil {
		// #nosec G204 -- netsh path is from LookPath
		cmd := cmdexec.Command(netsh, "wlan", "show", "interfaces")
		output, err := cmd.Output()
		if err == nil {
			iface := parseNetshWlan(output)
			if iface.Name != "" {
				result.Interfaces = []types.WiFiInterface{iface}
			}
		}
	}

	result.Available = len(result.Interfaces) > 0
	return result, nil
}

// parseNetshWlan parses netsh wlan show interfaces output.
func parseNetshWlan(output []byte) types.WiFiInterface {
	iface := types.WiFiInterface{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])

			switch key {
			case "Name":
				iface.Name = value
			case "SSID":
				iface.SSID = value
				iface.Connected = true
			case "BSSID":
				iface.BSSID = value
			case "Channel":
				iface.Channel, _ = strconv.Atoi(value)
			case "Signal":
				// Remove % sign
				value = strings.TrimSuffix(value, "%")
				iface.SignalQuality, _ = strconv.Atoi(value)
				// Convert to dBm approximation
				iface.SignalLevel = -100 + iface.SignalQuality/2
			case "Radio type":
				iface.Mode = value
			case "Authentication":
				iface.Security = value
			case "Receive rate (Mbps)":
				iface.BitRate, _ = strconv.ParseFloat(value, 64)
			}
		}
	}

	return iface
}

// getNetworkLatency performs network latency probes on Windows.
func (c *Collector) getNetworkLatency(targets []string) (*types.NetworkLatencyResult, error) {
	result := &types.NetworkLatencyResult{
		Timestamp: time.Now(),
	}

	if len(targets) == 0 {
		targets = []string{"8.8.8.8", "1.1.1.1"}
	}

	var totalLatency float64
	var minLatency float64 = -1
	var maxLatency float64

	for _, target := range targets {
		probe := types.LatencyProbe{
			Target:      target,
			PacketsSent: 3,
		}

		// Determine probe type
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			probe.Type = "http"
			probe.Port = 80
			if strings.HasPrefix(target, "https://") {
				probe.Port = 443
			}
		} else if strings.Contains(target, ":") {
			parts := strings.Split(target, ":")
			probe.Type = "tcp"
			probe.Port, _ = strconv.Atoi(parts[1])
			target = parts[0]
		} else {
			probe.Type = "icmp"
		}

		// Perform probes
		var latencies []float64
		for i := 0; i < probe.PacketsSent; i++ {
			var latency time.Duration
			var err error

			switch probe.Type {
			case "icmp":
				latency, err = icmpPing(target)
			case "tcp":
				latency, err = tcpPing(target, fmt.Sprintf("%d", probe.Port), 5*time.Second)
			case "http":
				latency, err = httpPing(nil, target, 5*time.Second)
			}

			if err == nil {
				probe.PacketsRecv++
				ms := float64(latency.Microseconds()) / 1000
				latencies = append(latencies, ms)
			} else if probe.Error == "" {
				probe.Error = err.Error()
			}
		}

		if len(latencies) > 0 {
			probe.Success = true
			probe.MinMs = latencies[0]
			probe.MaxMs = latencies[0]
			var sum float64
			for _, l := range latencies {
				sum += l
				if l < probe.MinMs {
					probe.MinMs = l
				}
				if l > probe.MaxMs {
					probe.MaxMs = l
				}
			}
			probe.AvgMs = sum / float64(len(latencies))
			probe.LatencyMs = probe.AvgMs

			totalLatency += probe.AvgMs
			if minLatency < 0 || probe.MinMs < minLatency {
				minLatency = probe.MinMs
			}
			if probe.MaxMs > maxLatency {
				maxLatency = probe.MaxMs
			}
		}

		probe.PacketLoss = float64(probe.PacketsSent-probe.PacketsRecv) / float64(probe.PacketsSent) * 100
		result.Probes = append(result.Probes, probe)
	}

	// Calculate summary
	successCount := 0
	for _, p := range result.Probes {
		if p.Success {
			successCount++
		}
	}

	result.Summary = types.LatencySummary{
		TotalProbes:   len(result.Probes),
		SuccessProbes: successCount,
		FailedProbes:  len(result.Probes) - successCount,
	}
	if successCount > 0 {
		result.Summary.AvgLatencyMs = totalLatency / float64(successCount)
		result.Summary.MinLatencyMs = minLatency
		result.Summary.MaxLatencyMs = maxLatency
	}

	return result, nil
}

// icmpPing performs an ICMP ping using ping command on Windows.
func icmpPing(host string) (time.Duration, error) {
	ping, err := cmdexec.LookPath("ping")
	if err != nil {
		return 0, err
	}

	start := time.Now()
	// #nosec G204 -- ping path is from LookPath
	cmd := cmdexec.Command(ping, "-n", "1", "-w", "2000", host)
	err = cmd.Run()
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
