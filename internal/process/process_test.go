package process

import (
	"os"
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

	list, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if list == nil {
		t.Fatal("Collect returned nil")
	}

	if list.Total == 0 {
		t.Error("No processes found")
	}

	if len(list.Processes) != list.Total {
		t.Errorf("Process count mismatch: len=%d, Total=%d", len(list.Processes), list.Total)
	}

	t.Logf("Found %d processes", list.Total)

	// Log first few processes
	for i, proc := range list.Processes {
		if i >= 5 {
			break
		}
		t.Logf("  PID=%d Name=%s User=%s Mem=%.1f%%",
			proc.PID, proc.Name, proc.Username, proc.MemPercent)
	}

	if list.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestCollector_GetProcess(t *testing.T) {
	c := NewCollector()

	// Get our own process
	pid := int32(os.Getpid())

	proc, err := c.GetProcess(pid)
	if err != nil {
		t.Fatalf("GetProcess failed: %v", err)
	}

	if proc.PID != pid {
		t.Errorf("PID mismatch: expected %d, got %d", pid, proc.PID)
	}

	if proc.Name == "" {
		t.Error("Process name should not be empty")
	}

	t.Logf("Current process: PID=%d Name=%s User=%s Mem=%.1f%% Status=%s",
		proc.PID, proc.Name, proc.Username, proc.MemPercent, proc.Status)
}

func TestCollector_GetProcess_Init(t *testing.T) {
	c := NewCollector()

	// Get init/systemd (PID 1)
	proc, err := c.GetProcess(1)
	if err != nil {
		t.Logf("GetProcess(1) failed (may need privileges): %v", err)
		return
	}

	if proc.PID != 1 {
		t.Errorf("PID mismatch: expected 1, got %d", proc.PID)
	}

	t.Logf("Init process: PID=%d Name=%s", proc.PID, proc.Name)
}

func TestCollector_GetProcess_NotFound(t *testing.T) {
	c := NewCollector()

	// Try to get a non-existent process
	_, err := c.GetProcess(999999999)
	if err == nil {
		t.Error("Expected error for non-existent process")
	}
}

func TestCollector_GetTopProcesses_Memory(t *testing.T) {
	c := NewCollector()

	procs, err := c.GetTopProcesses(10, "memory")
	if err != nil {
		t.Fatalf("GetTopProcesses failed: %v", err)
	}

	if len(procs) == 0 {
		t.Error("No processes returned")
	}

	t.Logf("Top 10 processes by memory:")
	for i, proc := range procs {
		t.Logf("  %d. PID=%d Name=%s Mem=%d KB (%.1f%%)",
			i+1, proc.PID, proc.Name, proc.MemRSS/1024, proc.MemPercent)
	}

	// Verify sorted descending by memory
	for i := 1; i < len(procs); i++ {
		if procs[i].MemRSS > procs[i-1].MemRSS {
			t.Errorf("Not sorted by memory: %d > %d", procs[i].MemRSS, procs[i-1].MemRSS)
		}
	}
}

func TestCollector_GetTopProcesses_CPU(t *testing.T) {
	c := NewCollector()

	procs, err := c.GetTopProcesses(10, "cpu")
	if err != nil {
		t.Fatalf("GetTopProcesses failed: %v", err)
	}

	if len(procs) == 0 {
		t.Error("No processes returned")
	}

	t.Logf("Top 10 processes by CPU:")
	for i, proc := range procs {
		t.Logf("  %d. PID=%d Name=%s CPU=%.1f%%",
			i+1, proc.PID, proc.Name, proc.CPUPercent)
	}
}

func TestCollector_Collect_MultipleRuns(t *testing.T) {
	c := NewCollector()

	for i := 0; i < 5; i++ {
		list, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if list.Total == 0 {
			t.Errorf("Iteration %d: No processes found", i)
		}
	}
}

// Benchmark tests
func BenchmarkCollector_Collect(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Collect()
	}
}

func BenchmarkCollector_GetProcess(b *testing.B) {
	c := NewCollector()
	pid := int32(os.Getpid())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetProcess(pid)
	}
}

func BenchmarkCollector_GetTopProcesses(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetTopProcesses(10, "memory")
	}
}
