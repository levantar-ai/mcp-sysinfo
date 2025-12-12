//go:build windows

package network

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIfTable        = iphlpapi.NewProc("GetIfTable")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

// MIB_IFROW structure (simplified)
type mibIfRow struct {
	Name            [256]uint16
	Index           uint32
	Type            uint32
	Mtu             uint32
	Speed           uint32
	PhysAddrLen     uint32
	PhysAddr        [8]byte
	AdminStatus     uint32
	OperStatus      uint32
	LastChange      uint32
	InOctets        uint32
	InUcastPkts     uint32
	InNUcastPkts    uint32
	InDiscards      uint32
	InErrors        uint32
	InUnknownProtos uint32
	OutOctets       uint32
	OutUcastPkts    uint32
	OutNUcastPkts   uint32
	OutDiscards     uint32
	OutErrors       uint32
	OutQLen         uint32
	DescrLen        uint32
	Descr           [256]byte
}

// collect gathers network interface information on Windows.
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

// getIOCounters returns network I/O statistics using GetIfTable on Windows.
func (c *Collector) getIOCounters() (map[string]*types.NetworkIOCounters, error) {
	// Get required buffer size
	var size uint32
	procGetIfTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)

	if size == 0 {
		return nil, fmt.Errorf("GetIfTable failed to get size")
	}

	buf := make([]byte, size)
	ret, _, _ := procGetIfTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("GetIfTable failed: %d", ret)
	}

	// Parse the table
	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	result := make(map[string]*types.NetworkIOCounters)

	rowSize := unsafe.Sizeof(mibIfRow{})
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}

		row := (*mibIfRow)(unsafe.Pointer(&buf[offset]))
		name := windows.UTF16ToString(row.Name[:])

		if name == "" {
			name = string(row.Descr[:row.DescrLen])
		}

		result[name] = &types.NetworkIOCounters{
			BytesSent:   uint64(row.OutOctets),
			BytesRecv:   uint64(row.InOctets),
			PacketsSent: uint64(row.OutUcastPkts + row.OutNUcastPkts),
			PacketsRecv: uint64(row.InUcastPkts + row.InNUcastPkts),
			ErrIn:       uint64(row.InErrors),
			ErrOut:      uint64(row.OutErrors),
			DropIn:      uint64(row.InDiscards),
			DropOut:     uint64(row.OutDiscards),
		}
	}

	return result, nil
}

// getConnections returns active network connections using netstat on Windows.
func (c *Collector) getConnections(kind string) ([]types.ConnectionInfo, error) {
	args := []string{"-an"}

	switch kind {
	case "tcp", "tcp4", "tcp6":
		args = append(args, "-p", "TCP")
	case "udp", "udp4", "udp6":
		args = append(args, "-p", "UDP")
	}

	out, err := exec.Command("netstat", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("netstat failed: %w", err)
	}

	var connections []types.ConnectionInfo
	lines := strings.Split(string(out), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}

		localAddr, localPort := parseWindowsAddr(fields[1])
		remoteAddr, remotePort := parseWindowsAddr(fields[2])

		var status string
		if len(fields) >= 4 && proto == "tcp" {
			status = fields[3]
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

// parseWindowsAddr parses address:port from Windows netstat output.
func parseWindowsAddr(s string) (string, uint16) {
	lastColon := strings.LastIndex(s, ":")
	if lastColon == -1 {
		return s, 0
	}

	addr := s[:lastColon]
	port, _ := strconv.ParseUint(s[lastColon+1:], 10, 16)

	// Handle "0.0.0.0" and "[::]"
	if addr == "0.0.0.0" || addr == "[::]" || addr == "[::1]" {
		addr = strings.Trim(addr, "[]")
	}

	return addr, uint16(port)
}
