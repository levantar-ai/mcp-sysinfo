//go:build integration && linux

package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/network"
)

func TestNetworkInfo_Linux(t *testing.T) {
	c := network.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	t.Logf("Found %d interfaces", len(info.Interfaces))

	for _, iface := range info.Interfaces {
		t.Logf("Interface: %s (MTU=%d, Up=%v)", iface.Name, iface.MTU, iface.IsUp)
	}

	if len(info.Interfaces) == 0 {
		t.Error("No interfaces found")
	}
}

func TestNetworkInfo_Linux_Loopback(t *testing.T) {
	c := network.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	foundLo := false
	for _, iface := range info.Interfaces {
		if iface.Name == "lo" {
			foundLo = true
			if !iface.IsUp {
				t.Error("Loopback should be up")
			}
			t.Logf("Loopback: MTU=%d, Addrs=%v", iface.MTU, iface.Addrs)
			break
		}
	}

	if !foundLo {
		t.Error("Loopback interface 'lo' not found")
	}
}

func TestNetworkIOCounters_Linux(t *testing.T) {
	c := network.NewCollector()

	counters, err := c.GetIOCounters()
	if err != nil {
		t.Fatalf("GetIOCounters failed: %v", err)
	}

	t.Logf("Found I/O counters for %d interfaces", len(counters))

	for name, counter := range counters {
		t.Logf("  %s: Sent=%d bytes, Recv=%d bytes", name, counter.BytesSent, counter.BytesRecv)
	}
}

func TestNetworkIOCounters_Linux_ProcNetDev(t *testing.T) {
	// Verify /proc/net/dev is readable
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		t.Fatalf("Cannot read /proc/net/dev: %v", err)
	}

	if len(data) == 0 {
		t.Error("/proc/net/dev is empty")
	}

	// Count interfaces
	lines := strings.Split(string(data), "\n")
	ifaceCount := 0
	for _, line := range lines[2:] { // Skip header lines
		if strings.TrimSpace(line) != "" {
			ifaceCount++
		}
	}

	t.Logf("Found %d interfaces in /proc/net/dev", ifaceCount)

	// Our collector should return similar count
	c := network.NewCollector()
	counters, err := c.GetIOCounters()
	if err != nil {
		t.Fatalf("GetIOCounters failed: %v", err)
	}

	if len(counters) != ifaceCount {
		t.Logf("Interface count mismatch: collector=%d, /proc/net/dev=%d",
			len(counters), ifaceCount)
	}
}

func TestNetworkConnections_Linux(t *testing.T) {
	c := network.NewCollector()

	conns, err := c.GetConnections("tcp")
	if err != nil {
		t.Fatalf("GetConnections failed: %v", err)
	}

	t.Logf("Found %d TCP connections", len(conns))

	// Count by state
	states := make(map[string]int)
	for _, conn := range conns {
		states[conn.Status]++
	}

	for state, count := range states {
		t.Logf("  %s: %d", state, count)
	}
}

func TestNetworkConnections_Linux_ProcNet(t *testing.T) {
	// Verify /proc/net/tcp is readable
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		t.Fatalf("Cannot read /proc/net/tcp: %v", err)
	}

	if len(data) == 0 {
		t.Error("/proc/net/tcp is empty")
	}

	t.Logf("/proc/net/tcp has %d bytes", len(data))
}

func TestNetworkInfo_Linux_Consistency(t *testing.T) {
	c := network.NewCollector()

	var lastCount int
	for i := 0; i < 5; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}

		if lastCount == 0 {
			lastCount = len(info.Interfaces)
		} else if len(info.Interfaces) != lastCount {
			t.Errorf("Interface count changed: %d -> %d", lastCount, len(info.Interfaces))
		}
	}
}

func TestNetworkInfo_Linux_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	c := network.NewCollector()

	for i := 0; i < 100; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if len(info.Interfaces) == 0 {
			t.Errorf("Iteration %d: No interfaces found", i)
		}
	}
}
