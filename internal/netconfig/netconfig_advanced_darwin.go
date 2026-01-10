//go:build darwin

package netconfig

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getConnectionTracking retrieves detailed connection tracking on macOS.
func (c *Collector) getConnectionTracking() (*types.ConnectionTrackingResult, error) {
	var connections []types.TrackedConnection
	byState := make(map[string]int)
	byProtocol := make(map[string]int)
	byProcess := make(map[string]int)
	remoteIPs := make(map[string]struct{})

	// Use lsof for connection info with process mapping
	lsof, err := cmdexec.LookPath("lsof")
	if err == nil {
		// #nosec G204 -- lsof path is from LookPath
		cmd := cmdexec.Command(lsof, "-i", "-n", "-P")
		output, err := cmd.Output()
		if err == nil {
			connections = parseLsofConnections(output)
		}
	}

	// Fallback to netstat
	if len(connections) == 0 {
		netstat, err := cmdexec.LookPath("netstat")
		if err == nil {
			// #nosec G204 -- netstat path is from LookPath
			cmd := cmdexec.Command(netstat, "-anv", "-p", "tcp")
			output, err := cmd.Output()
			if err == nil {
				connections = append(connections, parseNetstatConnections(output, "tcp")...)
			}

			// #nosec G204 -- netstat path is from LookPath
			cmdUDP := cmdexec.Command(netstat, "-anv", "-p", "udp")
			outputUDP, err := cmdUDP.Output()
			if err == nil {
				connections = append(connections, parseNetstatConnections(outputUDP, "udp")...)
			}
		}
	}

	// Build summary
	for _, conn := range connections {
		byState[conn.State]++
		byProtocol[conn.Protocol]++
		if conn.ProcessName != "" {
			byProcess[conn.ProcessName]++
		}
		if conn.RemoteAddr != "" && conn.RemoteAddr != "*" {
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

// parseLsofConnections parses lsof -i output.
func parseLsofConnections(output []byte) []types.TrackedConnection {
	var connections []types.TrackedConnection
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		conn := types.TrackedConnection{
			ProcessName: fields[0],
		}

		// Parse PID
		if pid, err := strconv.ParseInt(fields[1], 10, 32); err == nil {
			conn.PID = int32(pid)
		}

		// Parse user
		conn.Username = fields[2]

		// Parse protocol and state
		nameField := fields[8]
		if strings.Contains(nameField, "->") {
			// Connection with remote
			parts := strings.Split(nameField, "->")
			if len(parts) == 2 {
				local := parts[0]
				remote := parts[1]

				// Parse local
				if lastColon := strings.LastIndex(local, ":"); lastColon >= 0 {
					conn.LocalAddr = local[:lastColon]
					if port, err := strconv.ParseUint(local[lastColon+1:], 10, 16); err == nil {
						conn.LocalPort = uint16(port)
					}
				}

				// Parse remote (may have state in parentheses)
				if idx := strings.Index(remote, "("); idx > 0 {
					conn.State = strings.Trim(remote[idx:], "()")
					remote = remote[:idx]
				}
				if lastColon := strings.LastIndex(remote, ":"); lastColon >= 0 {
					conn.RemoteAddr = remote[:lastColon]
					if port, err := strconv.ParseUint(remote[lastColon+1:], 10, 16); err == nil {
						conn.RemotePort = uint16(port)
					}
				}
			}
		} else if strings.Contains(nameField, "*:") {
			// Listening
			conn.State = "LISTEN"
			if lastColon := strings.LastIndex(nameField, ":"); lastColon >= 0 {
				if port, err := strconv.ParseUint(nameField[lastColon+1:], 10, 16); err == nil {
					conn.LocalPort = uint16(port)
				}
			}
		}

		// Determine protocol from type field
		if strings.Contains(fields[4], "TCP") {
			conn.Protocol = "tcp"
		} else if strings.Contains(fields[4], "UDP") {
			conn.Protocol = "udp"
		}

		connections = append(connections, conn)
	}

	return connections
}

// parseNetstatConnections parses netstat output on macOS.
func parseNetstatConnections(output []byte, protocol string) []types.TrackedConnection {
	var connections []types.TrackedConnection
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Skip header lines
		if fields[0] == "Proto" || fields[0] == "Active" {
			continue
		}

		conn := types.TrackedConnection{
			Protocol: protocol,
		}

		// Parse local address
		local := fields[3]
		if lastDot := strings.LastIndex(local, "."); lastDot >= 0 {
			conn.LocalAddr = local[:lastDot]
			if port, err := strconv.ParseUint(local[lastDot+1:], 10, 16); err == nil {
				conn.LocalPort = uint16(port)
			}
		}

		// Parse remote address
		remote := fields[4]
		if lastDot := strings.LastIndex(remote, "."); lastDot >= 0 {
			conn.RemoteAddr = remote[:lastDot]
			if port, err := strconv.ParseUint(remote[lastDot+1:], 10, 16); err == nil {
				conn.RemotePort = uint16(port)
			}
		}

		// Parse state
		if len(fields) > 5 {
			conn.State = fields[5]
		}

		connections = append(connections, conn)
	}

	return connections
}

// getDNSStats retrieves DNS resolution statistics on macOS.
func (c *Collector) getDNSStats() (*types.DNSStatsResult, error) {
	result := &types.DNSStatsResult{
		Timestamp: time.Now(),
	}

	// Use scutil --dns for DNS info
	scutil, err := cmdexec.LookPath("scutil")
	if err == nil {
		// #nosec G204 -- scutil path is from LookPath
		cmd := cmdexec.Command(scutil, "--dns")
		output, err := cmd.Output()
		if err == nil {
			result.Servers, result.SearchDomains = parseScutilDNS(output)
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

// parseScutilDNS parses scutil --dns output.
func parseScutilDNS(output []byte) ([]types.DNSServerStats, []string) {
	var servers []types.DNSServerStats
	var searchDomains []string
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(bytes.NewReader(output))
	var currentInterface string
	priority := 1

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "resolver #") {
			currentInterface = ""
		} else if strings.HasPrefix(line, "if_index : ") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				currentInterface = parts[4]
			}
		} else if strings.HasPrefix(line, "nameserver[") {
			re := regexp.MustCompile(`nameserver\[\d+\]\s*:\s*(.+)`)
			if matches := re.FindStringSubmatch(line); matches != nil {
				addr := matches[1]
				if !seen[addr] {
					seen[addr] = true
					servers = append(servers, types.DNSServerStats{
						Address:   addr,
						Interface: currentInterface,
						Type:      "system",
						Priority:  priority,
					})
					priority++
				}
			}
		} else if strings.HasPrefix(line, "search domain[") {
			re := regexp.MustCompile(`search domain\[\d+\]\s*:\s*(.+)`)
			if matches := re.FindStringSubmatch(line); matches != nil {
				searchDomains = append(searchDomains, matches[1])
			}
		}
	}

	return servers, searchDomains
}

// getFirewallDeep retrieves comprehensive firewall analysis on macOS.
func (c *Collector) getFirewallDeep() (*types.FirewallDeepResult, error) {
	result := &types.FirewallDeepResult{
		Backend:   "pf",
		Timestamp: time.Now(),
	}

	// Check pf status
	pfctl, err := cmdexec.LookPath("pfctl")
	if err == nil {
		// Get pf status
		// #nosec G204 -- pfctl path is from LookPath
		cmd := cmdexec.Command(pfctl, "-s", "info")
		output, err := cmd.Output()
		if err == nil {
			result.Enabled = strings.Contains(string(output), "Status: Enabled")
		}

		// Get rules
		// #nosec G204 -- pfctl path is from LookPath
		rulesCmd := cmdexec.Command(pfctl, "-s", "rules")
		rulesOutput, err := rulesCmd.Output()
		if err == nil {
			result.Tables = []types.FirewallTable{parsePfRules(rulesOutput)}
		}
	}

	// Also check Application Firewall
	socketfilterfw, err := cmdexec.LookPath("/usr/libexec/ApplicationFirewall/socketfilterfw")
	if err == nil {
		// #nosec G204 -- socketfilterfw path is from LookPath
		cmd := cmdexec.Command(socketfilterfw, "--getglobalstate")
		output, err := cmd.Output()
		if err == nil && strings.Contains(string(output), "enabled") {
			result.Backend = "pf+alf"
		}
	}

	// Calculate statistics
	for _, table := range result.Tables {
		for _, chain := range table.Chains {
			for _, rule := range chain.Rules {
				result.Statistics.TotalRules++
				switch strings.ToLower(rule.Action) {
				case "pass":
					result.Statistics.AcceptRules++
				case "block":
					result.Statistics.DropRules++
				}
			}
		}
	}

	return result, nil
}

// parsePfRules parses pfctl rules output.
func parsePfRules(output []byte) types.FirewallTable {
	table := types.FirewallTable{
		Name:   "filter",
		Family: "inet",
	}

	chain := types.FirewallChain{
		Name: "main",
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	ruleNum := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ruleNum++
		rule := types.FirewallRuleDeep{
			Number:  ruleNum,
			Enabled: true,
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// First word is action
		rule.Action = fields[0]

		// Parse rest of rule
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "in":
				rule.Direction = "in"
			case "out":
				rule.Direction = "out"
			case "on":
				if i+1 < len(fields) {
					rule.Interface = fields[i+1]
					i++
				}
			case "proto":
				if i+1 < len(fields) {
					rule.Protocol = fields[i+1]
					i++
				}
			case "from":
				if i+1 < len(fields) {
					rule.Source = fields[i+1]
					i++
				}
			case "to":
				if i+1 < len(fields) {
					rule.Destination = fields[i+1]
					i++
				}
			case "port":
				if i+1 < len(fields) {
					rule.DstPort = fields[i+1]
					i++
				}
			}
		}

		chain.Rules = append(chain.Rules, rule)
	}

	table.Chains = []types.FirewallChain{chain}
	return table
}

// getWiFiMetrics retrieves WiFi metrics on macOS.
func (c *Collector) getWiFiMetrics() (*types.WiFiMetricsResult, error) {
	result := &types.WiFiMetricsResult{
		Timestamp: time.Now(),
	}

	// Use airport command
	airport, err := cmdexec.LookPath("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
	if err == nil {
		// #nosec G204 -- airport path is from LookPath
		cmd := cmdexec.Command(airport, "-I")
		output, err := cmd.Output()
		if err == nil {
			iface := parseAirportInfo(output)
			result.Interfaces = []types.WiFiInterface{iface}
		}
	}

	result.Available = len(result.Interfaces) > 0
	return result, nil
}

// parseAirportInfo parses airport -I output.
func parseAirportInfo(output []byte) types.WiFiInterface {
	iface := types.WiFiInterface{
		Name: "en0",
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "SSID":
			iface.SSID = value
			iface.Connected = true
		case "BSSID":
			iface.BSSID = value
		case "channel":
			// Parse channel (e.g., "36,1")
			if idx := strings.Index(value, ","); idx > 0 {
				iface.Channel, _ = strconv.Atoi(value[:idx])
			} else {
				iface.Channel, _ = strconv.Atoi(value)
			}
		case "agrCtlRSSI":
			iface.SignalLevel, _ = strconv.Atoi(value)
			iface.SignalQuality = signalToQuality(iface.SignalLevel)
		case "agrCtlNoise":
			iface.NoiseLevel, _ = strconv.Atoi(value)
		case "lastTxRate":
			iface.BitRate, _ = strconv.ParseFloat(value, 64)
		case "link auth":
			iface.Security = value
		}
	}

	return iface
}

// signalToQuality converts signal level (dBm) to quality percentage.
func signalToQuality(dBm int) int {
	if dBm >= -50 {
		return 100
	}
	if dBm <= -100 {
		return 0
	}
	return 2 * (dBm + 100)
}

// getNetworkLatency performs network latency probes on macOS.
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

// icmpPing performs an ICMP ping using ping command.
func icmpPing(host string) (time.Duration, error) {
	ping, err := cmdexec.LookPath("ping")
	if err != nil {
		return 0, err
	}

	start := time.Now()
	// #nosec G204 -- ping path is from LookPath
	cmd := cmdexec.Command(ping, "-c", "1", "-W", "2000", host)
	err = cmd.Run()
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
