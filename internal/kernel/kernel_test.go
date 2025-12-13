package kernel

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetKernelModules(t *testing.T) {
	c := NewCollector()
	result, err := c.GetKernelModules()
	if err != nil {
		t.Fatalf("GetKernelModules failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetKernelModules returned nil")
	}
	if result.Count != len(result.Modules) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Modules))
	}
}

func TestGetLoadedDrivers(t *testing.T) {
	c := NewCollector()
	result, err := c.GetLoadedDrivers()
	if err != nil {
		t.Fatalf("GetLoadedDrivers failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetLoadedDrivers returned nil")
	}
	if result.Count != len(result.Drivers) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Drivers))
	}
}

// Benchmark tests
func BenchmarkGetKernelModules(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetKernelModules()
	}
}

func BenchmarkGetLoadedDrivers(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetLoadedDrivers()
	}
}
