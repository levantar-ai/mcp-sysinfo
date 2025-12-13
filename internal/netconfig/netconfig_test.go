package netconfig

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetDNSServers(t *testing.T) {
	c := NewCollector()
	result, err := c.GetDNSServers()
	if err != nil {
		t.Fatalf("GetDNSServers failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetDNSServers returned nil")
	}
	if result.Count != len(result.Servers) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Servers))
	}
}

func TestGetRoutes(t *testing.T) {
	c := NewCollector()
	result, err := c.GetRoutes()
	if err != nil {
		t.Fatalf("GetRoutes failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetRoutes returned nil")
	}
	if result.Count != len(result.Routes) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Routes))
	}
}

func TestGetFirewallRules(t *testing.T) {
	c := NewCollector()
	result, err := c.GetFirewallRules()
	if err != nil {
		t.Fatalf("GetFirewallRules failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetFirewallRules returned nil")
	}
	if result.Count != len(result.Rules) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Rules))
	}
}

func TestGetListeningPorts(t *testing.T) {
	c := NewCollector()
	result, err := c.GetListeningPorts()
	if err != nil {
		t.Fatalf("GetListeningPorts failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetListeningPorts returned nil")
	}
	if result.Count != len(result.Ports) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Ports))
	}
}

func TestGetARPTable(t *testing.T) {
	c := NewCollector()
	result, err := c.GetARPTable()
	if err != nil {
		t.Fatalf("GetARPTable failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetARPTable returned nil")
	}
	if result.Count != len(result.Entries) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Entries))
	}
}

func TestGetNetworkStats(t *testing.T) {
	c := NewCollector()
	result, err := c.GetNetworkStats()
	if err != nil {
		t.Fatalf("GetNetworkStats failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetNetworkStats returned nil")
	}
}

// Benchmark tests
func BenchmarkGetDNSServers(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetDNSServers()
	}
}

func BenchmarkGetRoutes(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetRoutes()
	}
}

func BenchmarkGetListeningPorts(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetListeningPorts()
	}
}

func BenchmarkGetARPTable(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetARPTable()
	}
}

func BenchmarkGetNetworkStats(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetNetworkStats()
	}
}
