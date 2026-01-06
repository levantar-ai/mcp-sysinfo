package report

import (
	"context"
	"testing"
	"time"
)

func TestReportGenerator_GenerateSystemReport(t *testing.T) {
	rg := NewReportGenerator(30 * time.Second)

	start := time.Now()
	report, err := rg.GenerateSystemReport(context.Background(), nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("GenerateSystemReport returned error: %v", err)
	}

	if report == nil {
		t.Fatal("GenerateSystemReport returned nil report")
	}

	if report.Generated.IsZero() {
		t.Error("Generated timestamp should not be zero")
	}

	if report.Errors == nil {
		t.Error("Errors map should not be nil")
	}

	t.Logf("System report generated in %v", elapsed)
	t.Logf("Hostname: %s", report.Hostname)
	t.Logf("Errors: %d", len(report.Errors))

	// Check that at least some sections were collected
	sectionsCollected := 0
	if report.OS != nil {
		sectionsCollected++
	}
	if report.CPU != nil {
		sectionsCollected++
	}
	if report.Memory != nil {
		sectionsCollected++
	}
	if report.Disks != nil {
		sectionsCollected++
	}
	if report.Network != nil {
		sectionsCollected++
	}
	if report.Uptime != nil {
		sectionsCollected++
	}

	t.Logf("Sections collected: %d", sectionsCollected)

	if sectionsCollected == 0 && len(report.Errors) == 0 {
		t.Error("Expected at least some sections to be collected or errors to be reported")
	}
}

func TestReportGenerator_WithSections(t *testing.T) {
	rg := NewReportGenerator(30 * time.Second)

	// Only request cpu and memory
	sections := []string{"cpu", "memory"}

	report, err := rg.GenerateSystemReport(context.Background(), sections)
	if err != nil {
		t.Fatalf("GenerateSystemReport returned error: %v", err)
	}

	if report == nil {
		t.Fatal("GenerateSystemReport returned nil report")
	}

	// CPU and memory should be collected
	t.Logf("CPU collected: %v", report.CPU != nil || report.Errors["cpu"] != "")
	t.Logf("Memory collected: %v", report.Memory != nil || report.Errors["memory"] != "")
}

func TestReportGenerator_ParallelPerformance(t *testing.T) {
	rg := NewReportGenerator(30 * time.Second)

	// Request multiple sections to test parallel execution
	sections := []string{"cpu", "memory", "disks", "network", "uptime"}

	start := time.Now()
	_, err := rg.GenerateSystemReport(context.Background(), sections)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("GenerateSystemReport returned error: %v", err)
	}

	// Parallel execution should be much faster than serial
	// 5 collectors, if serial would take ~5x longer than single collector
	// With parallel, should complete in similar time to slowest collector
	if elapsed > 10*time.Second {
		t.Errorf("Report generation took too long: %v (expected < 10s for parallel execution)", elapsed)
	}

	t.Logf("Parallel system report (5 sections) completed in %v", elapsed)
}

func TestNewReportGenerator_DefaultTimeout(t *testing.T) {
	// Zero timeout should use default
	rg := NewReportGenerator(0)
	if rg.timeout != 30*time.Second {
		t.Errorf("Expected default timeout of 30s, got %v", rg.timeout)
	}
}
