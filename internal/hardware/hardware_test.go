package hardware

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetHardwareInfo(t *testing.T) {
	c := NewCollector()
	result, err := c.GetHardwareInfo()
	if err != nil {
		t.Fatalf("GetHardwareInfo failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetHardwareInfo returned nil")
	}
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestGetUSBDevices(t *testing.T) {
	c := NewCollector()
	result, err := c.GetUSBDevices()
	if err != nil {
		t.Fatalf("GetUSBDevices failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetUSBDevices returned nil")
	}
	if result.Count != len(result.Devices) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Devices))
	}
}

func TestGetPCIDevices(t *testing.T) {
	c := NewCollector()
	result, err := c.GetPCIDevices()
	if err != nil {
		t.Fatalf("GetPCIDevices failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetPCIDevices returned nil")
	}
	if result.Count != len(result.Devices) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Devices))
	}
}

func TestGetBlockDevices(t *testing.T) {
	c := NewCollector()
	result, err := c.GetBlockDevices()
	if err != nil {
		t.Fatalf("GetBlockDevices failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetBlockDevices returned nil")
	}
	if result.Count != len(result.Devices) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Devices))
	}
}

// Benchmark tests
func BenchmarkGetHardwareInfo(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetHardwareInfo()
	}
}

func BenchmarkGetUSBDevices(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetUSBDevices()
	}
}

func BenchmarkGetPCIDevices(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetPCIDevices()
	}
}

func BenchmarkGetBlockDevices(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetBlockDevices()
	}
}
