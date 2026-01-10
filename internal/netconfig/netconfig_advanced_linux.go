//go:build linux

package netconfig

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getConnectionTracking retrieves detailed connection tracking on Linux.
func (c *Collector) getConnectionTracking() (*types.ConnectionTrackingResult, error) {
	var connections []types.TrackedConnection
	byState := make(map[string]int)
	byProtocol := make(map[string]int)
	byProcess := make(map[string]int)
	remoteIPs := make(map[string]struct{})

	// Use ss command for detailed connection info
	ss, err := cmdexec.LookPath("ss")
	if err == nil {
		// Get TCP connections
		// #nosec G204 -- ss path is from LookPath
		cmd := cmdexec.Command(ss, "-tnp")
		output, err := cmd.Output()
		if err == nil {
			conns := parseSSConnections(output, "tcp")
			connections = append(connections, conns...)
		}

		// Get UDP connections
		// #nosec G204 -- ss path is from LookPath
		cmdUDP := cmdexec.Command(ss, "-unp")
		outputUDP, err := cmdUDP.Output()
		if err == nil {
			conns := parseSSConnections(outputUDP, "udp")
			connections = append(connections, conns...)
		}
	}

	// Fallback to /proc/net if ss not available
	if len(connections) == 0 {
		connections = append(connections, readProcNetConnections("/proc/net/tcp", "tcp")...)
		connections = append(connections, readProcNetConnections("/proc/net/tcp6", "tcp6")...)
		connections = append(connections, readProcNetConnections("/proc/net/udp", "udp")...)
		connections = append(connections, readProcNetConnections("/proc/net/udp6", "udp6")...)
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

// parseSSConnections parses ss command output for connections.
func parseSSConnections(output []byte, protocol string) []types.TrackedConnection {
	var connections []types.TrackedConnection
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	pidPattern := regexp.MustCompile(`pid=(\d+)`)
	procPattern := regexp.MustCompile(`"([^"]+)"`)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		conn := types.TrackedConnection{
			Protocol: protocol,
			State:    fields[0],
		}

		// Parse local address
		local := fields[3]
		if lastColon := strings.LastIndex(local, ":"); lastColon >= 0 {
			conn.LocalAddr = local[:lastColon]
			if port, err := strconv.ParseUint(local[lastColon+1:], 10, 16); err == nil {
				conn.LocalPort = uint16(port)
			}
		}

		// Parse remote address
		remote := fields[4]
		if lastColon := strings.LastIndex(remote, ":"); lastColon >= 0 {
			conn.RemoteAddr = remote[:lastColon]
			if port, err := strconv.ParseUint(remote[lastColon+1:], 10, 16); err == nil {
				conn.RemotePort = uint16(port)
			}
		}

		// Extract process info
		if len(fields) > 5 {
			rest := strings.Join(fields[5:], " ")
			if matches := pidPattern.FindStringSubmatch(rest); matches != nil {
				if pid, err := strconv.ParseInt(matches[1], 10, 32); err == nil {
					conn.PID = int32(pid)
				}
			}
			if matches := procPattern.FindStringSubmatch(rest); matches != nil {
				conn.ProcessName = matches[1]
			}
		}

		connections = append(connections, conn)
	}

	return connections
}

// readProcNetConnections reads connections from /proc/net files.
func readProcNetConnections(path, protocol string) []types.TrackedConnection {
	var connections []types.TrackedConnection

	// #nosec G304 -- reading from procfs
	content, err := os.ReadFile(path)
	if err != nil {
		return connections
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Scan() // skip header

	stateMap := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		// Parse local address
		localParts := strings.Split(fields[1], ":")
		if len(localParts) != 2 {
			continue
		}
		localAddr := hexToIP(localParts[0])
		localPort, _ := strconv.ParseUint(localParts[1], 16, 16)

		// Parse remote address
		remoteParts := strings.Split(fields[2], ":")
		if len(remoteParts) != 2 {
			continue
		}
		remoteAddr := hexToIP(remoteParts[0])
		remotePort, _ := strconv.ParseUint(remoteParts[1], 16, 16)

		state := stateMap[fields[3]]
		if state == "" {
			state = fields[3]
		}

		connections = append(connections, types.TrackedConnection{
			Protocol:   protocol,
			LocalAddr:  localAddr,
			LocalPort:  uint16(localPort),
			RemoteAddr: remoteAddr,
			RemotePort: uint16(remotePort),
			State:      state,
		})
	}

	return connections
}

// getDNSStats retrieves DNS resolution statistics on Linux.
func (c *Collector) getDNSStats() (*types.DNSStatsResult, error) {
	result := &types.DNSStatsResult{
		Timestamp: time.Now(),
	}

	// Read resolv.conf
	// #nosec G304 -- reading from known system file
	content, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		result.ResolvConf = string(content)
		result.Servers, result.SearchDomains = parseResolvConfStats(content)
	}

	// Try to get statistics from systemd-resolved
	resolvectl, err := cmdexec.LookPath("resolvectl")
	if err == nil {
		// #nosec G204 -- resolvectl path is from LookPath
		cmd := cmdexec.Command(resolvectl, "statistics")
		output, err := cmd.Output()
		if err == nil {
			result.QueryStats = parseResolvectlStats(output)
		}

		// Get cache info
		// #nosec G204 -- resolvectl path is from LookPath
		cacheCmd := cmdexec.Command(resolvectl, "show-cache")
		cacheOutput, err := cacheCmd.Output()
		if err == nil {
			result.Cache = parseResolvectlCache(cacheOutput)
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

// parseResolvConfStats parses resolv.conf for DNS servers.
func parseResolvConfStats(content []byte) ([]types.DNSServerStats, []string) {
	var servers []types.DNSServerStats
	var searchDomains []string

	scanner := bufio.NewScanner(bytes.NewReader(content))
	priority := 1
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "nameserver":
			servers = append(servers, types.DNSServerStats{
				Address:  fields[1],
				Type:     "system",
				Priority: priority,
			})
			priority++
		case "search", "domain":
			searchDomains = append(searchDomains, fields[1:]...)
		}
	}

	return servers, searchDomains
}

// parseResolvectlStats parses resolvectl statistics output.
func parseResolvectlStats(output []byte) types.DNSQueryStats {
	var stats types.DNSQueryStats
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Total Transactions:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				stats.TotalQueries, _ = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
			}
		} else if strings.Contains(line, "Cache Hits:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				stats.CacheHits, _ = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
			}
		} else if strings.Contains(line, "Cache Misses:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				stats.CacheMisses, _ = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
			}
		}
	}

	stats.SuccessQueries = stats.CacheHits + stats.CacheMisses
	return stats
}

// parseResolvectlCache parses resolvectl cache output.
func parseResolvectlCache(output []byte) *types.DNSCache {
	cache := &types.DNSCache{}
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Cache Size:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				cache.Entries, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		}
	}

	return cache
}

// getFirewallDeep retrieves comprehensive firewall analysis on Linux.
func (c *Collector) getFirewallDeep() (*types.FirewallDeepResult, error) {
	result := &types.FirewallDeepResult{
		Timestamp: time.Now(),
	}

	// Try iptables first
	iptables, err := cmdexec.LookPath("iptables")
	if err == nil {
		result.Backend = "iptables"
		result.Enabled = true

		// Get filter table with verbose stats
		// #nosec G204 -- iptables path is from LookPath
		cmd := cmdexec.Command(iptables, "-L", "-n", "-v", "--line-numbers")
		output, err := cmd.Output()
		if err == nil {
			table := parseIptablesDeep(output, "filter")
			result.Tables = append(result.Tables, table)
		}

		// Get nat table
		// #nosec G204 -- iptables path is from LookPath
		natCmd := cmdexec.Command(iptables, "-t", "nat", "-L", "-n", "-v", "--line-numbers")
		natOutput, err := natCmd.Output()
		if err == nil {
			table := parseIptablesDeep(natOutput, "nat")
			result.Tables = append(result.Tables, table)
		}
	}

	// Try nftables if iptables not found or empty
	if len(result.Tables) == 0 {
		nft, err := cmdexec.LookPath("nft")
		if err == nil {
			// #nosec G204 -- nft path is from LookPath
			cmd := cmdexec.Command(nft, "-j", "list", "ruleset")
			output, err := cmd.Output()
			if err == nil && len(output) > 0 {
				result.Backend = "nftables"
				result.Enabled = true
				result.Tables = parseNftablesDeep(output)
			}
		}
	}

	// Try ufw
	ufw, err := cmdexec.LookPath("ufw")
	if err == nil {
		// #nosec G204 -- ufw path is from LookPath
		cmd := cmdexec.Command(ufw, "status", "verbose")
		output, err := cmd.Output()
		if err == nil {
			zones := parseUFWZones(output)
			result.Zones = zones
			if len(zones) > 0 {
				result.Backend = "ufw"
				result.Enabled = strings.Contains(string(output), "Status: active")
			}
		}
	}

	// Calculate statistics
	for _, table := range result.Tables {
		for _, chain := range table.Chains {
			for _, rule := range chain.Rules {
				result.Statistics.TotalRules++
				switch strings.ToUpper(rule.Action) {
				case "ACCEPT":
					result.Statistics.AcceptRules++
				case "DROP":
					result.Statistics.DropRules++
				case "REJECT":
					result.Statistics.RejectRules++
				case "LOG":
					result.Statistics.LogRules++
				}
				result.Statistics.TotalPackets += rule.Packets
				result.Statistics.TotalBytes += rule.Bytes
			}
		}
	}

	return result, nil
}

// parseIptablesDeep parses iptables verbose output.
func parseIptablesDeep(output []byte, tableName string) types.FirewallTable {
	table := types.FirewallTable{
		Name:   tableName,
		Family: "ip",
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	var currentChain *types.FirewallChain
	ruleNum := 0

	for scanner.Scan() {
		line := scanner.Text()

		// Chain header
		if strings.HasPrefix(line, "Chain ") {
			if currentChain != nil {
				table.Chains = append(table.Chains, *currentChain)
			}
			parts := strings.Fields(line)
			currentChain = &types.FirewallChain{
				Name: parts[1],
			}
			// Extract policy
			if strings.Contains(line, "(policy") {
				re := regexp.MustCompile(`\(policy (\w+)\)`)
				if matches := re.FindStringSubmatch(line); matches != nil {
					currentChain.Policy = matches[1]
				}
			}
			ruleNum = 0
			continue
		}

		// Skip headers
		if strings.Contains(line, "pkts") || strings.TrimSpace(line) == "" {
			continue
		}

		if currentChain == nil {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		ruleNum++
		rule := types.FirewallRuleDeep{
			Number:  ruleNum,
			Enabled: true,
		}

		// Parse packets and bytes
		rule.Packets, _ = parsePacketCount(fields[0])
		rule.Bytes, _ = parseByteCount(fields[1])

		// Target/Action
		rule.Action = fields[2]

		// Protocol
		if fields[3] != "all" && fields[3] != "--" {
			rule.Protocol = fields[3]
		}

		// Source and destination
		if len(fields) > 7 && fields[7] != "0.0.0.0/0" && fields[7] != "anywhere" {
			rule.Source = fields[7]
		}
		if len(fields) > 8 && fields[8] != "0.0.0.0/0" && fields[8] != "anywhere" {
			rule.Destination = fields[8]
		}

		// Look for port info
		for i := 9; i < len(fields); i++ {
			if strings.HasPrefix(fields[i], "dpt:") {
				rule.DstPort = strings.TrimPrefix(fields[i], "dpt:")
			}
			if strings.HasPrefix(fields[i], "spt:") {
				rule.SrcPort = strings.TrimPrefix(fields[i], "spt:")
			}
		}

		currentChain.Rules = append(currentChain.Rules, rule)
	}

	if currentChain != nil {
		table.Chains = append(table.Chains, *currentChain)
	}

	return table
}

// parsePacketCount parses packet count with K/M/G suffix.
func parsePacketCount(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	multiplier := uint64(1)
	if strings.HasSuffix(s, "K") {
		multiplier = 1000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "M") {
		multiplier = 1000000
		s = s[:len(s)-1]
	} else if strings.HasSuffix(s, "G") {
		multiplier = 1000000000
		s = s[:len(s)-1]
	}
	val, err := strconv.ParseUint(s, 10, 64)
	return val * multiplier, err
}

// parseByteCount parses byte count with K/M/G suffix.
func parseByteCount(s string) (uint64, error) {
	return parsePacketCount(s) // Same logic
}

// parseNftablesDeep parses nftables JSON output.
func parseNftablesDeep(output []byte) []types.FirewallTable {
	// For simplicity, parse non-JSON format
	var tables []types.FirewallTable
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentTable *types.FirewallTable
	var currentChain *types.FirewallChain
	ruleNum := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "table ") {
			if currentTable != nil && currentChain != nil {
				currentTable.Chains = append(currentTable.Chains, *currentChain)
			}
			if currentTable != nil {
				tables = append(tables, *currentTable)
			}
			parts := strings.Fields(line)
			currentTable = &types.FirewallTable{}
			if len(parts) >= 3 {
				currentTable.Family = parts[1]
				currentTable.Name = strings.TrimSuffix(parts[2], "{")
			}
			currentChain = nil
		} else if strings.HasPrefix(line, "chain ") {
			if currentChain != nil && currentTable != nil {
				currentTable.Chains = append(currentTable.Chains, *currentChain)
			}
			parts := strings.Fields(line)
			currentChain = &types.FirewallChain{}
			if len(parts) >= 2 {
				currentChain.Name = strings.TrimSuffix(parts[1], "{")
			}
			ruleNum = 0
		} else if currentChain != nil && (strings.Contains(line, "accept") || strings.Contains(line, "drop") || strings.Contains(line, "reject")) {
			ruleNum++
			rule := types.FirewallRuleDeep{
				Number:  ruleNum,
				Enabled: true,
			}

			if strings.Contains(line, "accept") {
				rule.Action = "ACCEPT"
			} else if strings.Contains(line, "drop") {
				rule.Action = "DROP"
			} else if strings.Contains(line, "reject") {
				rule.Action = "REJECT"
			}

			if strings.Contains(line, "tcp") {
				rule.Protocol = "tcp"
			} else if strings.Contains(line, "udp") {
				rule.Protocol = "udp"
			}

			currentChain.Rules = append(currentChain.Rules, rule)
		}
	}

	if currentChain != nil && currentTable != nil {
		currentTable.Chains = append(currentTable.Chains, *currentChain)
	}
	if currentTable != nil {
		tables = append(tables, *currentTable)
	}

	return tables
}

// parseUFWZones parses ufw status output.
func parseUFWZones(output []byte) []types.FirewallZone {
	var zones []types.FirewallZone
	scanner := bufio.NewScanner(bytes.NewReader(output))

	zone := types.FirewallZone{
		Name:   "default",
		Active: false,
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Status: active") {
			zone.Active = true
		}
		if strings.Contains(line, "Default:") {
			parts := strings.Split(line, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.Contains(p, "incoming") {
					zone.Target = strings.Fields(p)[0]
				}
			}
		}
	}

	zones = append(zones, zone)
	return zones
}

// getWiFiMetrics retrieves WiFi metrics on Linux.
func (c *Collector) getWiFiMetrics() (*types.WiFiMetricsResult, error) {
	result := &types.WiFiMetricsResult{
		Timestamp: time.Now(),
	}

	// Try iw command
	iw, err := cmdexec.LookPath("iw")
	if err == nil {
		// Find wireless interfaces
		// #nosec G204 -- iw path is from LookPath
		cmd := cmdexec.Command(iw, "dev")
		output, err := cmd.Output()
		if err == nil {
			interfaces := parseIWDev(output)
			for _, iface := range interfaces {
				// Get link info
				// #nosec G204 -- iw path is from LookPath
				linkCmd := cmdexec.Command(iw, iface.Name, "link")
				linkOutput, err := linkCmd.Output()
				if err == nil {
					parseIWLink(&iface, linkOutput)
				}
				result.Interfaces = append(result.Interfaces, iface)
			}
		}
	}

	// Fallback to /proc/net/wireless
	if len(result.Interfaces) == 0 {
		// #nosec G304 -- reading from procfs
		content, err := os.ReadFile("/proc/net/wireless")
		if err == nil {
			result.Interfaces = parseProcNetWireless(content)
		}
	}

	result.Available = len(result.Interfaces) > 0
	return result, nil
}

// parseIWDev parses iw dev output.
func parseIWDev(output []byte) []types.WiFiInterface {
	var interfaces []types.WiFiInterface
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var current *types.WiFiInterface
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Interface ") {
			if current != nil {
				interfaces = append(interfaces, *current)
			}
			current = &types.WiFiInterface{
				Name: strings.TrimPrefix(line, "Interface "),
			}
		} else if current != nil {
			if strings.HasPrefix(line, "type ") {
				current.Mode = strings.TrimPrefix(line, "type ")
			}
		}
	}
	if current != nil {
		interfaces = append(interfaces, *current)
	}

	return interfaces
}

// parseIWLink parses iw link output.
func parseIWLink(iface *types.WiFiInterface, output []byte) {
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Connected to ") {
			iface.Connected = true
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				iface.BSSID = parts[2]
			}
		} else if strings.HasPrefix(line, "SSID: ") {
			iface.SSID = strings.TrimPrefix(line, "SSID: ")
		} else if strings.HasPrefix(line, "freq: ") {
			freq, _ := strconv.ParseFloat(strings.TrimPrefix(line, "freq: "), 64)
			iface.Frequency = freq
			iface.Channel = freqToChannel(int(freq))
		} else if strings.HasPrefix(line, "signal: ") {
			parts := strings.Fields(strings.TrimPrefix(line, "signal: "))
			if len(parts) >= 1 {
				iface.SignalLevel, _ = strconv.Atoi(parts[0])
				// Convert dBm to quality percentage (rough approximation)
				iface.SignalQuality = signalToQuality(iface.SignalLevel)
			}
		} else if strings.HasPrefix(line, "tx bitrate: ") {
			parts := strings.Fields(strings.TrimPrefix(line, "tx bitrate: "))
			if len(parts) >= 1 {
				iface.BitRate, _ = strconv.ParseFloat(parts[0], 64)
			}
		}
	}
}

// freqToChannel converts frequency to channel number.
func freqToChannel(freq int) int {
	if freq >= 2412 && freq <= 2484 {
		if freq == 2484 {
			return 14
		}
		return (freq - 2407) / 5
	}
	if freq >= 5170 && freq <= 5825 {
		return (freq - 5000) / 5
	}
	return 0
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

// parseProcNetWireless parses /proc/net/wireless.
func parseProcNetWireless(content []byte) []types.WiFiInterface {
	var interfaces []types.WiFiInterface
	scanner := bufio.NewScanner(bytes.NewReader(content))

	// Skip headers
	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}

		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(parts[1])
		if len(fields) < 4 {
			continue
		}

		iface := types.WiFiInterface{
			Name:      name,
			Connected: true,
		}

		// Link quality (field 1)
		if lq := strings.TrimSuffix(fields[1], "."); lq != "" {
			iface.LinkQuality = lq
		}

		// Signal level (field 2)
		if sl := strings.TrimSuffix(fields[2], "."); sl != "" {
			iface.SignalLevel, _ = strconv.Atoi(sl)
		}

		// Noise level (field 3)
		if nl := strings.TrimSuffix(fields[3], "."); nl != "" {
			iface.NoiseLevel, _ = strconv.Atoi(nl)
		}

		interfaces = append(interfaces, iface)
	}

	return interfaces
}

// getNetworkLatency performs network latency probes on Linux.
func (c *Collector) getNetworkLatency(targets []string) (*types.NetworkLatencyResult, error) {
	result := &types.NetworkLatencyResult{
		Timestamp: time.Now(),
	}

	if len(targets) == 0 {
		// Default targets
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
			// Has port specified
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

// icmpPing performs an ICMP ping (requires root or setcap).
func icmpPing(host string) (time.Duration, error) {
	// Try using ping command since raw ICMP requires privileges
	ping, err := cmdexec.LookPath("ping")
	if err != nil {
		return 0, err
	}

	start := time.Now()
	// #nosec G204 -- ping path is from LookPath
	cmd := cmdexec.Command(ping, "-c", "1", "-W", "2", host)
	err = cmd.Run()
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
