package scheduled

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetScheduledTasks(t *testing.T) {
	c := NewCollector()
	result, err := c.GetScheduledTasks()
	if err != nil {
		t.Fatalf("GetScheduledTasks failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetScheduledTasks returned nil")
	}
	if result.Source == "" {
		t.Error("expected non-empty source")
	}
	// Count should match length of tasks
	if result.Count != len(result.Tasks) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Tasks))
	}
}

func TestGetCronJobs(t *testing.T) {
	c := NewCollector()
	result, err := c.GetCronJobs()
	if err != nil {
		t.Fatalf("GetCronJobs failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetCronJobs returned nil")
	}
	// Count should match length of jobs
	if result.Count != len(result.Jobs) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Jobs))
	}
}

func TestGetStartupItems(t *testing.T) {
	c := NewCollector()
	result, err := c.GetStartupItems()
	if err != nil {
		t.Fatalf("GetStartupItems failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetStartupItems returned nil")
	}
	// Count should match length of items
	if result.Count != len(result.Items) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Items))
	}
}

func TestGetSystemdServices(t *testing.T) {
	c := NewCollector()
	result, err := c.GetSystemdServices()
	if err != nil {
		t.Fatalf("GetSystemdServices failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetSystemdServices returned nil")
	}
	// Count should match length of services
	if result.Count != len(result.Services) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Services))
	}
}

// Benchmark tests
func BenchmarkGetScheduledTasks(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetScheduledTasks()
	}
}

func BenchmarkGetCronJobs(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetCronJobs()
	}
}

func BenchmarkGetStartupItems(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetStartupItems()
	}
}

func BenchmarkGetSystemdServices(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetSystemdServices()
	}
}
