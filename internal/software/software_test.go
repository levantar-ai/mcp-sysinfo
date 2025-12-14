package software

import (
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
)

// TestHelperProcess is required for cmdexec mocking.
func TestHelperProcess(t *testing.T) {
	cmdexec.HelperProcess()
}

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetPathExecutables(t *testing.T) {
	c := NewCollector()
	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("GetPathExecutables failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetPathExecutables returned nil")
	}
	if result.Count != len(result.Executables) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Executables))
	}
	if len(result.PathDirs) == 0 {
		t.Error("expected non-empty PathDirs")
	}
}

func TestGetSystemPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("GetSystemPackages failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetSystemPackages returned nil")
	}
	if result.Count != len(result.Packages) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Packages))
	}
}

// Benchmark tests
func BenchmarkGetPathExecutables(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetPathExecutables()
	}
}

func BenchmarkGetSystemPackages(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetSystemPackages()
	}
}
