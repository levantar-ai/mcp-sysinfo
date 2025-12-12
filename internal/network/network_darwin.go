//go:build darwin

package network

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers network interface information on macOS.
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

// getIOCounters returns network I/O statistics using netstat on macOS.
func (c *Collector) getIOCounters() (map[string]*types.NetworkIOCounters, error) {
	// Use netstat -ib for interface statistics
	out, err := exec.Command("netstat", "-ib").Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	result := make(map[string]*types.NetworkIOCounters)
	lines := strings.Split(string(out), "\n")

	// Skip header
	for i, line := range lines {
		if i == 0 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		name := fields[0]

		// Skip duplicate entries (link-level vs protocol-level)
		if _, exists := result[name]; exists {
			continue
		}

		// netstat -ib format:
		// Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
		packetsRecv, _ := strconv.ParseUint(fields[4], 10, 64)
		errsRecv, _ := strconv.ParseUint(fields[5], 10, 64)
		bytesRecv, _ := strconv.ParseUint(fields[6], 10, 64)
		packetsSent, _ := strconv.ParseUint(fields[7], 10, 64)
		errsSent, _ := strconv.ParseUint(fields[8], 10, 64)
		bytesSent, _ := strconv.ParseUint(fields[9], 10, 64)

		result[name] = &types.NetworkIOCounters{
			BytesSent:   bytesSent,
			BytesRecv:   bytesRecv,
			PacketsSent: packetsSent,
			PacketsRecv: packetsRecv,
			ErrIn:       errsRecv,
			ErrOut:      errsSent,
		}
	}

	return result, nil
}

// getConnections returns active network connections using netstat on macOS.
func (c *Collector) getConnections(kind string) ([]types.ConnectionInfo, error) {
	args := []string{"-an"}

	switch kind {
	case "tcp", "tcp4", "tcp6":
		args = append(args, "-p", "tcp")
	case "udp", "udp4", "udp6":
		args = append(args, "-p", "udp")
	}

	out, err := exec.Command("netstat", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var connections []types.ConnectionInfo
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := fields[0]
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}

		localAddr, localPort := parseNetstatAddr(fields[3])
		remoteAddr, remotePort := parseNetstatAddr(fields[4])

		var status string
		if len(fields) >= 6 {
			status = fields[5]
		}

		connections = append(connections, types.ConnectionInfo{
			Type:       proto,
			LocalAddr:  localAddr,
			LocalPort:  localPort,
			RemoteAddr: remoteAddr,
			RemotePort: remotePort,
			Status:     status,
		})
	}

	return connections, nil
}

// parseNetstatAddr parses address:port from netstat output.
func parseNetstatAddr(s string) (string, uint16) {
	lastDot := strings.LastIndex(s, ".")
	if lastDot == -1 {
		return s, 0
	}

	addr := s[:lastDot]
	port, _ := strconv.ParseUint(s[lastDot+1:], 10, 16)

	// Handle "*" as "0.0.0.0"
	if addr == "*" {
		addr = "0.0.0.0"
	}

	return addr, uint16(port)
}
