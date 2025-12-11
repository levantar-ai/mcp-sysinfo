package network

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Error("NewCollector returned nil")
	}
}

func TestCollector_Collect(t *testing.T) {
	c := NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if info == nil {
		t.Fatal("Collect returned nil")
	}

	// Should have at least loopback interface
	if len(info.Interfaces) == 0 {
		t.Error("No interfaces found")
	}

	foundLoopback := false
	for _, iface := range info.Interfaces {
		if iface.Name == "lo" || iface.Name == "lo0" || iface.Name == "Loopback Pseudo-Interface 1" {
			foundLoopback = true
		}
		t.Logf("Interface: %s (MTU=%d, Up=%v, MAC=%s, Addrs=%v)",
			iface.Name, iface.MTU, iface.IsUp, iface.MAC, iface.Addrs)
	}

	if !foundLoopback {
		t.Log("Warning: loopback interface not found by name (may have different name)")
	}

	if info.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestCollector_GetIOCounters(t *testing.T) {
	c := NewCollector()

	counters, err := c.GetIOCounters()
	if err != nil {
		t.Fatalf("GetIOCounters failed: %v", err)
	}

	if counters == nil {
		t.Fatal("GetIOCounters returned nil")
	}

	for name, counter := range counters {
		t.Logf("Interface %s: Sent=%d bytes (%d pkts), Recv=%d bytes (%d pkts)",
			name, counter.BytesSent, counter.PacketsSent,
			counter.BytesRecv, counter.PacketsRecv)
	}
}

func TestCollector_GetConnections(t *testing.T) {
	c := NewCollector()

	// Test TCP connections
	conns, err := c.GetConnections("tcp")
	if err != nil {
		t.Fatalf("GetConnections failed: %v", err)
	}

	t.Logf("Found %d TCP connections", len(conns))

	// Log first few connections
	for i, conn := range conns {
		if i >= 5 {
			t.Logf("... and %d more", len(conns)-5)
			break
		}
		t.Logf("  %s %s:%d -> %s:%d (%s)",
			conn.Type, conn.LocalAddr, conn.LocalPort,
			conn.RemoteAddr, conn.RemotePort, conn.Status)
	}
}

func TestCollector_GetConnections_All(t *testing.T) {
	c := NewCollector()

	conns, err := c.GetConnections("all")
	if err != nil {
		t.Fatalf("GetConnections(all) failed: %v", err)
	}

	t.Logf("Found %d total connections", len(conns))
}

func TestCollector_Collect_MultipleRuns(t *testing.T) {
	c := NewCollector()

	for i := 0; i < 5; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if len(info.Interfaces) == 0 {
			t.Errorf("Iteration %d: No interfaces found", i)
		}
	}
}

// Benchmark tests
func BenchmarkCollector_Collect(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Collect()
	}
}

func BenchmarkCollector_GetIOCounters(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.GetIOCounters()
	}
}

func BenchmarkCollector_GetConnections(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.GetConnections("tcp")
	}
}
