//go:build linux

package network

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yourusername/mcp-sysinfo/pkg/types"
)

// collect gathers network interface information on Linux.
func (c *Collector) collect() (*types.NetworkInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("getting interfaces: %w", err)
	}

	var ifaceInfos []types.InterfaceInfo

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var addrStrings []string
		for _, addr := range addrs {
			addrStrings = append(addrStrings, addr.String())
		}

		ifaceInfos = append(ifaceInfos, types.InterfaceInfo{
			Name:  iface.Name,
			MTU:   iface.MTU,
			Addrs: addrStrings,
			IsUp:  iface.Flags&net.FlagUp != 0,
			MAC:   iface.HardwareAddr.String(),
		})
	}

	return &types.NetworkInfo{
		Interfaces: ifaceInfos,
		Timestamp:  time.Now(),
	}, nil
}

// getIOCounters returns network I/O statistics from /proc/net/dev.
func (c *Collector) getIOCounters() (map[string]*types.NetworkIOCounters, error) {
	file, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]*types.NetworkIOCounters)
	scanner := bufio.NewScanner(file)

	// Skip header lines
	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 17 {
			continue
		}

		// Interface name ends with ':'
		name := strings.TrimSuffix(fields[0], ":")

		bytesRecv, _ := strconv.ParseUint(fields[1], 10, 64)
		packetsRecv, _ := strconv.ParseUint(fields[2], 10, 64)
		errsRecv, _ := strconv.ParseUint(fields[3], 10, 64)
		dropRecv, _ := strconv.ParseUint(fields[4], 10, 64)

		bytesSent, _ := strconv.ParseUint(fields[9], 10, 64)
		packetsSent, _ := strconv.ParseUint(fields[10], 10, 64)
		errsSent, _ := strconv.ParseUint(fields[11], 10, 64)
		dropSent, _ := strconv.ParseUint(fields[12], 10, 64)

		result[name] = &types.NetworkIOCounters{
			BytesSent:   bytesSent,
			BytesRecv:   bytesRecv,
			PacketsSent: packetsSent,
			PacketsRecv: packetsRecv,
			ErrIn:       errsRecv,
			ErrOut:      errsSent,
			DropIn:      dropRecv,
			DropOut:     dropSent,
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// getConnections returns active network connections from /proc/net/{tcp,udp}.
func (c *Collector) getConnections(kind string) ([]types.ConnectionInfo, error) {
	var connections []types.ConnectionInfo

	switch kind {
	case "tcp", "tcp4", "all":
		conns, err := parseProcNet("/proc/net/tcp", "tcp")
		if err == nil {
			connections = append(connections, conns...)
		}
	}

	switch kind {
	case "tcp6", "all":
		conns, err := parseProcNet("/proc/net/tcp6", "tcp6")
		if err == nil {
			connections = append(connections, conns...)
		}
	}

	switch kind {
	case "udp", "udp4", "all":
		conns, err := parseProcNet("/proc/net/udp", "udp")
		if err == nil {
			connections = append(connections, conns...)
		}
	}

	switch kind {
	case "udp6", "all":
		conns, err := parseProcNet("/proc/net/udp6", "udp6")
		if err == nil {
			connections = append(connections, conns...)
		}
	}

	return connections, nil
}

// parseProcNet parses /proc/net/{tcp,udp,tcp6,udp6} files.
func parseProcNet(path, connType string) ([]types.ConnectionInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var connections []types.ConnectionInfo
	scanner := bufio.NewScanner(file)

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		localAddr, localPort := parseHexAddr(fields[1])
		remoteAddr, remotePort := parseHexAddr(fields[2])
		state := parseState(fields[3])

		connections = append(connections, types.ConnectionInfo{
			Type:       connType,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			Status:     state,
		})
	}

	return connections, nil
}

// parseHexAddr parses hex address:port from /proc/net files.
func parseHexAddr(s string) (string, uint16) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0
	}

	// Parse hex IP (little-endian for IPv4)
	hexIP := parts[0]
	var ip string
	if len(hexIP) == 8 {
		// IPv4
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			val, _ := strconv.ParseUint(hexIP[i*2:i*2+2], 16, 8)
			b[3-i] = byte(val)
		}
		ip = net.IP(b).String()
	} else if len(hexIP) == 32 {
		// IPv6
		b := make([]byte, 16)
		for i := 0; i < 16; i++ {
			val, _ := strconv.ParseUint(hexIP[i*2:i*2+2], 16, 8)
			b[i] = byte(val)
		}
		ip = net.IP(b).String()
	}

	port, _ := strconv.ParseUint(parts[1], 16, 16)
	return ip, uint16(port)
}

// parseState converts hex state to string.
func parseState(hexState string) string {
	state, _ := strconv.ParseUint(hexState, 16, 8)
	states := map[uint64]string{
		1:  "ESTABLISHED",
		2:  "SYN_SENT",
		3:  "SYN_RECV",
		4:  "FIN_WAIT1",
		5:  "FIN_WAIT2",
		6:  "TIME_WAIT",
		7:  "CLOSE",
		8:  "CLOSE_WAIT",
		9:  "LAST_ACK",
		10: "LISTEN",
		11: "CLOSING",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return "UNKNOWN"
}
