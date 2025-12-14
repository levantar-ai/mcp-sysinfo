//go:build linux

package netconfig

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getDNSServers retrieves DNS servers from /etc/resolv.conf and systemd-resolved.
func (c *Collector) getDNSServers() (*types.DNSServersResult, error) {
	var servers []types.DNSServer

	// Read /etc/resolv.conf
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

	// Try systemd-resolved if available
	resolvectl, err := cmdexec.LookPath("resolvectl")
	if err == nil {
		// #nosec G204 -- resolvectl path is from LookPath
		cmd := cmdexec.Command(resolvectl, "status", "--no-pager")
		output, err := cmd.Output()
		if err == nil {
			servers = append(servers, parseResolvectl(output)...)
		}
	}

	return &types.DNSServersResult{
		Servers:   servers,
		Count:     len(servers),
		Timestamp: time.Now(),
	}, nil
}

// parseResolvectl parses resolvectl status output.
func parseResolvectl(output []byte) []types.DNSServer {
	var servers []types.DNSServer
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentInterface string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Link ") || strings.Contains(line, "(") {
			// Extract interface name
			if idx := strings.Index(line, "("); idx > 0 {
				end := strings.Index(line, ")")
				if end > idx {
					currentInterface = line[idx+1 : end]
				}
			}
		} else if strings.Contains(line, "DNS Servers:") || strings.Contains(line, "Current DNS Server:") {
			fields := strings.Fields(line)
			for _, f := range fields {
				// Check if it looks like an IP address
				if strings.Contains(f, ".") || strings.Contains(f, ":") {
					if !strings.Contains(f, "DNS") && !strings.Contains(f, "Server") {
						servers = append(servers, types.DNSServer{
							Address:   f,
							Interface: currentInterface,
							Type:      "resolved",
						})
					}
				}
			}
		}
	}

	return servers
}

// getRoutes retrieves the routing table from /proc/net/route and ip route.
func (c *Collector) getRoutes() (*types.RoutesResult, error) {
	var routes []types.Route

	// Try ip route first
	ip, err := cmdexec.LookPath("ip")
	if err == nil {
		// #nosec G204 -- ip path is from LookPath
		cmd := cmdexec.Command(ip, "route", "show")
		output, err := cmd.Output()
		if err == nil {
			routes = parseIPRoute(output)
		}
	}

	// Fallback to /proc/net/route if ip route failed
	if len(routes) == 0 {
		// #nosec G304 -- reading from procfs
		content, err := os.ReadFile("/proc/net/route")
		if err == nil {
			routes = parseProcRoute(content)
		}
	}

	return &types.RoutesResult{
		Routes:    routes,
		Count:     len(routes),
		Timestamp: time.Now(),
	}, nil
}

// parseIPRoute parses ip route output.
func parseIPRoute(output []byte) []types.Route {
	var routes []types.Route
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		route := types.Route{
			Destination: fields[0],
		}

		for i := 1; i < len(fields)-1; i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					route.Gateway = fields[i+1]
				}
			case "dev":
				if i+1 < len(fields) {
					route.Interface = fields[i+1]
				}
			case "metric":
				if i+1 < len(fields) {
					if m, err := strconv.Atoi(fields[i+1]); err == nil {
						route.Metric = m
					}
				}
			}
		}

		routes = append(routes, route)
	}

	return routes
}

// parseProcRoute parses /proc/net/route.
func parseProcRoute(content []byte) []types.Route {
	var routes []types.Route
	scanner := bufio.NewScanner(bytes.NewReader(content))

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}

		// Convert hex addresses to dotted notation
		dest := hexToIP(fields[1])
		gateway := hexToIP(fields[2])
		mask := hexToIP(fields[7])

		metric, _ := strconv.Atoi(fields[6])

		routes = append(routes, types.Route{
			Destination: dest,
			Gateway:     gateway,
			Interface:   fields[0],
			Mask:        mask,
			Metric:      metric,
			Flags:       fields[3],
		})
	}

	return routes
}

// hexToIP converts a hex string to dotted IP notation.
func hexToIP(hex string) string {
	if len(hex) != 8 {
		return hex
	}
	var octets [4]uint64
	for i := 0; i < 4; i++ {
		octets[i], _ = strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
	}
	// Little-endian on x86
	return strconv.FormatUint(octets[3], 10) + "." +
		strconv.FormatUint(octets[2], 10) + "." +
		strconv.FormatUint(octets[1], 10) + "." +
		strconv.FormatUint(octets[0], 10)
}

// getFirewallRules retrieves firewall rules from iptables or nftables.
func (c *Collector) getFirewallRules() (*types.FirewallRulesResult, error) {
	var rules []types.FirewallRule
	source := "none"
	enabled := false

	// Try iptables first
	iptables, err := cmdexec.LookPath("iptables")
	if err == nil {
		// #nosec G204 -- iptables path is from LookPath
		cmd := cmdexec.Command(iptables, "-L", "-n", "-v")
		output, err := cmd.Output()
		if err == nil {
			rules = parseIptables(output)
			source = "iptables"
			enabled = len(rules) > 0
		}
	}

	// Try nftables if iptables not found or empty
	if len(rules) == 0 {
		nft, err := cmdexec.LookPath("nft")
		if err == nil {
			// #nosec G204 -- nft path is from LookPath
			cmd := cmdexec.Command(nft, "list", "ruleset")
			output, err := cmd.Output()
			if err == nil && len(output) > 0 {
				rules = parseNftables(output)
				source = "nftables"
				enabled = len(rules) > 0
			}
		}
	}

	return &types.FirewallRulesResult{
		Rules:     rules,
		Count:     len(rules),
		Source:    source,
		Enabled:   enabled,
		Timestamp: time.Now(),
	}, nil
}

// parseIptables parses iptables -L output.
func parseIptables(output []byte) []types.FirewallRule {
	var rules []types.FirewallRule
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentChain string
	for scanner.Scan() {
		line := scanner.Text()

		// Chain header
		if strings.HasPrefix(line, "Chain ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentChain = parts[1]
			}
			continue
		}

		// Skip headers and empty lines
		if strings.HasPrefix(line, " pkts") || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		rule := types.FirewallRule{
			Chain:   currentChain,
			Table:   "filter",
			Action:  fields[2],
			Enabled: true,
		}

		// Parse protocol
		if fields[3] != "--" && fields[3] != "all" {
			rule.Protocol = fields[3]
		}

		// Parse source and destination
		if len(fields) > 7 {
			if fields[7] != "0.0.0.0/0" && fields[7] != "anywhere" {
				rule.Source = fields[7]
			}
		}
		if len(fields) > 8 {
			if fields[8] != "0.0.0.0/0" && fields[8] != "anywhere" {
				rule.Destination = fields[8]
			}
		}

		// Look for port info
		for i := 9; i < len(fields); i++ {
			if strings.HasPrefix(fields[i], "dpt:") {
				rule.Port = strings.TrimPrefix(fields[i], "dpt:")
			}
		}

		rules = append(rules, rule)
	}

	return rules
}

// parseNftables parses nft list ruleset output.
func parseNftables(output []byte) []types.FirewallRule {
	var rules []types.FirewallRule
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentTable, currentChain string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "table ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				currentTable = parts[2]
			}
		} else if strings.HasPrefix(line, "chain ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentChain = parts[1]
			}
		} else if strings.Contains(line, "accept") || strings.Contains(line, "drop") || strings.Contains(line, "reject") {
			rule := types.FirewallRule{
				Table:   currentTable,
				Chain:   currentChain,
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

			rules = append(rules, rule)
		}
	}

	return rules
}

// getListeningPorts retrieves listening ports from /proc/net/tcp and /proc/net/udp.
func (c *Collector) getListeningPorts() (*types.ListeningPortsResult, error) {
	var ports []types.ListeningPort

	// Try ss command first (more reliable)
	ss, err := cmdexec.LookPath("ss")
	if err == nil {
		// #nosec G204 -- ss path is from LookPath
		cmd := cmdexec.Command(ss, "-tlnp")
		output, err := cmd.Output()
		if err == nil {
			ports = append(ports, parseSS(output, "tcp")...)
		}

		// #nosec G204 -- ss path is from LookPath
		cmdUDP := cmdexec.Command(ss, "-ulnp")
		outputUDP, err := cmdUDP.Output()
		if err == nil {
			ports = append(ports, parseSS(outputUDP, "udp")...)
		}
	}

	// Fallback to /proc/net
	if len(ports) == 0 {
		ports = append(ports, readProcNetTCP("/proc/net/tcp")...)
		ports = append(ports, readProcNetTCP("/proc/net/tcp6")...)
		ports = append(ports, readProcNetUDP("/proc/net/udp")...)
		ports = append(ports, readProcNetUDP("/proc/net/udp6")...)
	}

	return &types.ListeningPortsResult{
		Ports:     ports,
		Count:     len(ports),
		Timestamp: time.Now(),
	}, nil
}

// parseSS parses ss command output.
func parseSS(output []byte, protocol string) []types.ListeningPort {
	var ports []types.ListeningPort
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	// Pattern to extract PID and process name
	pidPattern := regexp.MustCompile(`pid=(\d+)`)
	procPattern := regexp.MustCompile(`"([^"]+)"`)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address:port
		local := fields[3]
		lastColon := strings.LastIndex(local, ":")
		if lastColon < 0 {
			continue
		}

		address := local[:lastColon]
		portStr := local[lastColon+1:]
		port, _ := strconv.ParseUint(portStr, 10, 16)

		lp := types.ListeningPort{
			Protocol: protocol,
			Address:  address,
			Port:     uint16(port),
			State:    "LISTEN",
		}

		// Try to extract PID and process name
		if len(fields) > 5 {
			rest := strings.Join(fields[5:], " ")
			if matches := pidPattern.FindStringSubmatch(rest); matches != nil {
				if pid, err := strconv.ParseInt(matches[1], 10, 32); err == nil {
					lp.PID = int32(pid)
				}
			}
			if matches := procPattern.FindStringSubmatch(rest); matches != nil {
				lp.ProcessName = matches[1]
			}
		}

		ports = append(ports, lp)
	}

	return ports
}

// readProcNetTCP reads listening ports from /proc/net/tcp.
func readProcNetTCP(path string) []types.ListeningPort {
	var ports []types.ListeningPort

	// #nosec G304 -- reading from procfs
	content, err := os.ReadFile(path)
	if err != nil {
		return ports
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		// Check state - 0A is LISTEN
		if fields[3] != "0A" {
			continue
		}

		// Parse local address
		localParts := strings.Split(fields[1], ":")
		if len(localParts) != 2 {
			continue
		}

		port, _ := strconv.ParseUint(localParts[1], 16, 16)
		address := hexToIP(localParts[0])

		ports = append(ports, types.ListeningPort{
			Protocol: "tcp",
			Address:  address,
			Port:     uint16(port),
			State:    "LISTEN",
		})
	}

	return ports
}

// readProcNetUDP reads listening ports from /proc/net/udp.
func readProcNetUDP(path string) []types.ListeningPort {
	var ports []types.ListeningPort

	// #nosec G304 -- reading from procfs
	content, err := os.ReadFile(path)
	if err != nil {
		return ports
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Scan() // skip header

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

		port, _ := strconv.ParseUint(localParts[1], 16, 16)
		address := hexToIP(localParts[0])

		ports = append(ports, types.ListeningPort{
			Protocol: "udp",
			Address:  address,
			Port:     uint16(port),
			State:    "UNCONN",
		})
	}

	return ports
}

// getARPTable retrieves the ARP table from /proc/net/arp.
func (c *Collector) getARPTable() (*types.ARPTableResult, error) {
	var entries []types.ARPEntry

	// #nosec G304 -- reading from procfs
	content, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return &types.ARPTableResult{
			Entries:   entries,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		entries = append(entries, types.ARPEntry{
			IPAddress:  fields[0],
			MACAddress: fields[3],
			Interface:  fields[5],
			Type:       "dynamic",
			State:      "reachable",
		})
	}

	return &types.ARPTableResult{
		Entries:   entries,
		Count:     len(entries),
		Timestamp: time.Now(),
	}, nil
}

// getNetworkStats retrieves network statistics from /proc/net/snmp.
func (c *Collector) getNetworkStats() (*types.NetworkStatsResult, error) {
	stats := types.NetworkStats{}

	// Read /proc/net/snmp for TCP stats
	// #nosec G304 -- reading from procfs
	content, err := os.ReadFile("/proc/net/snmp")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Tcp:") && !strings.Contains(line, "RtoAlgorithm") {
				fields := strings.Fields(line)
				if len(fields) >= 10 {
					stats.TCPConnections, _ = strconv.Atoi(fields[9])
				}
			}
		}
	}

	// Get connection counts from /proc/net/tcp
	// #nosec G304 -- reading from procfs
	tcpContent, err := os.ReadFile("/proc/net/tcp")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(tcpContent))
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				switch fields[3] {
				case "01": // ESTABLISHED
					stats.TCPEstablished++
				case "06": // TIME_WAIT
					stats.TCPTimeWait++
				case "08": // CLOSE_WAIT
					stats.TCPCloseWait++
				}
			}
		}
	}

	// Count UDP connections
	// #nosec G304 -- reading from procfs
	udpContent, err := os.ReadFile("/proc/net/udp")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(udpContent))
		scanner.Scan() // skip header
		for scanner.Scan() {
			stats.UDPConnections++
		}
	}

	// Get packet/byte stats from /proc/net/dev
	// #nosec G304 -- reading from procfs
	devContent, err := os.ReadFile("/proc/net/dev")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(devContent))
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, ":") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			fields := strings.Fields(parts[1])
			if len(fields) >= 16 {
				// Accumulate stats from all interfaces
				if recv, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
					stats.BytesReceived += recv
				}
				if recvPkt, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					stats.PacketsReceived += recvPkt
				}
				if recvErr, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
					stats.Errors += recvErr
				}
				if recvDrop, err := strconv.ParseUint(fields[3], 10, 64); err == nil {
					stats.Drops += recvDrop
				}
				if sent, err := strconv.ParseUint(fields[8], 10, 64); err == nil {
					stats.BytesSent += sent
				}
				if sentPkt, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
					stats.PacketsSent += sentPkt
				}
				if sentErr, err := strconv.ParseUint(fields[10], 10, 64); err == nil {
					stats.Errors += sentErr
				}
				if sentDrop, err := strconv.ParseUint(fields[11], 10, 64); err == nil {
					stats.Drops += sentDrop
				}
			}
		}
	}

	return &types.NetworkStatsResult{
		Stats:     stats,
		Timestamp: time.Now(),
	}, nil
}
