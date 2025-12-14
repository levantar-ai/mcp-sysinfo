package state

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetVMInfo(t *testing.T) {
	c := NewCollector()
	result, err := c.GetVMInfo()
	if err != nil {
		t.Fatalf("GetVMInfo failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetVMInfo returned nil")
	}
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestGetTimezone(t *testing.T) {
	c := NewCollector()
	result, err := c.GetTimezone()
	if err != nil {
		t.Fatalf("GetTimezone failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetTimezone returned nil")
	}
	if result.LocalTime.IsZero() {
		t.Error("LocalTime should not be zero")
	}
}

func TestGetNTPStatus(t *testing.T) {
	c := NewCollector()
	result, err := c.GetNTPStatus()
	if err != nil {
		t.Fatalf("GetNTPStatus failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetNTPStatus returned nil")
	}
}

func TestGetCoreDumps(t *testing.T) {
	c := NewCollector()
	result, err := c.GetCoreDumps()
	if err != nil {
		t.Fatalf("GetCoreDumps failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetCoreDumps returned nil")
	}
	if result.Count != len(result.CoreDumps) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.CoreDumps))
	}
}

func TestGetPowerState(t *testing.T) {
	c := NewCollector()
	result, err := c.GetPowerState()
	if err != nil {
		t.Fatalf("GetPowerState failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetPowerState returned nil")
	}
}

func TestGetNUMATopology(t *testing.T) {
	c := NewCollector()
	result, err := c.GetNUMATopology()
	if err != nil {
		t.Fatalf("GetNUMATopology failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetNUMATopology returned nil")
	}
	if result.Count != len(result.Nodes) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Nodes))
	}
}

// Benchmark tests
func BenchmarkGetVMInfo(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetVMInfo()
	}
}

func BenchmarkGetTimezone(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetTimezone()
	}
}

func BenchmarkGetPowerState(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetPowerState()
	}
}
