package filesystem

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetMounts(t *testing.T) {
	c := NewCollector()
	result, err := c.GetMounts()
	if err != nil {
		t.Fatalf("GetMounts failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetMounts returned nil")
	}
	if result.Count != len(result.Mounts) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Mounts))
	}
}

func TestGetDiskIO(t *testing.T) {
	c := NewCollector()
	result, err := c.GetDiskIO()
	if err != nil {
		t.Fatalf("GetDiskIO failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetDiskIO returned nil")
	}
	if result.Count != len(result.Devices) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Devices))
	}
}

func TestGetOpenFiles(t *testing.T) {
	c := NewCollector()
	result, err := c.GetOpenFiles()
	if err != nil {
		t.Fatalf("GetOpenFiles failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetOpenFiles returned nil")
	}
	if result.Count != len(result.Files) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Files))
	}
}

func TestGetInodeUsage(t *testing.T) {
	c := NewCollector()
	result, err := c.GetInodeUsage()
	if err != nil {
		t.Fatalf("GetInodeUsage failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetInodeUsage returned nil")
	}
	if result.Count != len(result.Filesystems) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Filesystems))
	}
}

// Benchmark tests
func BenchmarkGetMounts(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetMounts()
	}
}

func BenchmarkGetDiskIO(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetDiskIO()
	}
}

func BenchmarkGetOpenFiles(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetOpenFiles()
	}
}

func BenchmarkGetInodeUsage(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetInodeUsage()
	}
}
