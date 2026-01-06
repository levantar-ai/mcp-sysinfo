//go:build windows

package report

import (
	"context"
	"testing"
	"time"
)

func TestIISReportGenerator_GenerateIISReport(t *testing.T) {
	rg := NewIISReportGenerator(30 * time.Second)

	start := time.Now()
	report, err := rg.GenerateIISReport(context.Background(), nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("GenerateIISReport returned error: %v", err)
	}

	if report == nil {
		t.Fatal("GenerateIISReport returned nil report")
	}

	if report.Generated.IsZero() {
		t.Error("Generated timestamp should not be zero")
	}

	if report.Errors == nil {
		t.Error("Errors map should not be nil")
	}

	if report.Summary == nil {
		t.Error("Summary should not be nil")
	}

	t.Logf("IIS report generated in %v", elapsed)
	t.Logf("Summary: %d sites, %d app pools, %d bindings, %d SSL certs",
		report.Summary.TotalSites,
		report.Summary.TotalAppPools,
		report.Summary.TotalBindings,
		report.Summary.SSLCertificates)

	if len(report.Errors) > 0 {
		t.Logf("Errors encountered: %v", report.Errors)
	}
}

func TestIISReportGenerator_WithSections(t *testing.T) {
	rg := NewIISReportGenerator(30 * time.Second)

	// Only request sites and app_pools
	sections := []string{"sites", "app_pools"}

	report, err := rg.GenerateIISReport(context.Background(), sections)
	if err != nil {
		t.Fatalf("GenerateIISReport returned error: %v", err)
	}

	if report == nil {
		t.Fatal("GenerateIISReport returned nil report")
	}

	// Sites and app pools should be collected
	// Other sections should be nil
	t.Logf("Sites collected: %v", report.Sites != nil)
	t.Logf("AppPools collected: %v", report.AppPools != nil)
	t.Logf("Bindings collected: %v", report.Bindings != nil)
	t.Logf("Handlers collected: %v", report.Handlers != nil)
}

func TestIISReportGenerator_Timeout(t *testing.T) {
	// Very short timeout
	rg := NewIISReportGenerator(100 * time.Millisecond)

	start := time.Now()
	_, err := rg.GenerateIISReport(context.Background(), nil)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("GenerateIISReport returned error: %v", err)
	}

	// Should complete within reasonable time even with short timeout
	if elapsed > 5*time.Second {
		t.Errorf("Report generation took too long: %v", elapsed)
	}

	t.Logf("Report with short timeout completed in %v", elapsed)
}

func TestNewIISReportGenerator_DefaultTimeout(t *testing.T) {
	// Zero timeout should use default
	rg := NewIISReportGenerator(0)
	if rg.timeout != 30*time.Second {
		t.Errorf("Expected default timeout of 30s, got %v", rg.timeout)
	}
}
