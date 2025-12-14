package resources

import (
	"os"
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetProcessEnviron(t *testing.T) {
	c := NewCollector()
	// Get environ for current process
	pid := int32(os.Getpid())
	result, err := c.GetProcessEnviron(pid)
	if err != nil {
		t.Fatalf("GetProcessEnviron failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetProcessEnviron returned nil")
	}
	if result.PID != pid {
		t.Errorf("PID mismatch: got %d, expected %d", result.PID, pid)
	}
}

func TestGetIPCResources(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIPCResources()
	if err != nil {
		t.Fatalf("GetIPCResources failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetIPCResources returned nil")
	}
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestGetNamespaces(t *testing.T) {
	c := NewCollector()
	result, err := c.GetNamespaces()
	if err != nil {
		t.Fatalf("GetNamespaces failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetNamespaces returned nil")
	}
	if result.Count != len(result.Namespaces) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Namespaces))
	}
}

func TestGetCgroups(t *testing.T) {
	c := NewCollector()
	result, err := c.GetCgroups()
	if err != nil {
		t.Fatalf("GetCgroups failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetCgroups returned nil")
	}
}

func TestGetCapabilities(t *testing.T) {
	c := NewCollector()
	// Get capabilities for current process
	pid := int32(os.Getpid())
	result, err := c.GetCapabilities(pid)
	if err != nil {
		t.Fatalf("GetCapabilities failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetCapabilities returned nil")
	}
	if result.PID != pid {
		t.Errorf("PID mismatch: got %d, expected %d", result.PID, pid)
	}
}

// Benchmark tests
func BenchmarkGetIPCResources(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetIPCResources()
	}
}

func BenchmarkGetNamespaces(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetNamespaces()
	}
}

func BenchmarkGetCgroups(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetCgroups()
	}
}
