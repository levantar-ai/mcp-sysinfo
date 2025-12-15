package software

import (
	"strings"
	"testing"
)

func TestGetSBOMCycloneDX(t *testing.T) {
	c := NewCollector()
	result, err := c.GetSBOMCycloneDX()

	if err != nil {
		t.Fatalf("GetSBOMCycloneDX returned error: %v", err)
	}

	if result == nil {
		t.Fatal("GetSBOMCycloneDX returned nil result")
	}

	if result.Format != "CycloneDX" {
		t.Errorf("expected format 'CycloneDX', got '%s'", result.Format)
	}

	if result.Version != "1.4" {
		t.Errorf("expected version '1.4', got '%s'", result.Version)
	}

	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	if result.Count != len(result.Components) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Components))
	}

	// Raw should contain valid CycloneDX JSON structure
	if !strings.Contains(result.Raw, "bomFormat") {
		t.Error("Raw output should contain 'bomFormat'")
	}

	if !strings.Contains(result.Raw, "CycloneDX") {
		t.Error("Raw output should contain 'CycloneDX'")
	}
}

func TestGetSBOMSPDX(t *testing.T) {
	c := NewCollector()
	result, err := c.GetSBOMSPDX()

	if err != nil {
		t.Fatalf("GetSBOMSPDX returned error: %v", err)
	}

	if result == nil {
		t.Fatal("GetSBOMSPDX returned nil result")
	}

	if result.Format != "SPDX" {
		t.Errorf("expected format 'SPDX', got '%s'", result.Format)
	}

	if result.Version != "2.3" {
		t.Errorf("expected version '2.3', got '%s'", result.Version)
	}

	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	if result.Count != len(result.Components) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Components))
	}

	// Raw should contain valid SPDX JSON structure
	if !strings.Contains(result.Raw, "spdxVersion") {
		t.Error("Raw output should contain 'spdxVersion'")
	}

	if !strings.Contains(result.Raw, "SPDX-2.3") {
		t.Error("Raw output should contain 'SPDX-2.3'")
	}
}

func TestGeneratePURL(t *testing.T) {
	tests := []struct {
		pkgManager string
		name       string
		version    string
		arch       string
		expected   string
	}{
		{"dpkg", "curl", "7.88.1", "amd64", "pkg:deb/debian/curl@7.88.1?arch=amd64"},
		{"dpkg", "curl", "7.88.1", "", "pkg:deb/debian/curl@7.88.1"},
		{"rpm", "curl", "7.88.1", "x86_64", "pkg:rpm/fedora/curl@7.88.1?arch=x86_64"},
		{"apk", "curl", "7.88.1", "", "pkg:apk/alpine/curl@7.88.1"},
		{"pacman", "curl", "7.88.1", "", "pkg:pacman/arch/curl@7.88.1"},
		{"brew", "curl", "7.88.1", "", "pkg:brew/curl@7.88.1"},
		{"homebrew", "curl", "7.88.1", "", "pkg:brew/curl@7.88.1"},
		{"chocolatey", "curl", "7.88.1", "", "pkg:chocolatey/curl@7.88.1"},
		{"choco", "curl", "7.88.1", "", "pkg:chocolatey/curl@7.88.1"},
		{"winget", "Microsoft.WindowsTerminal", "1.18.3181.0", "", "pkg:winget/Microsoft.WindowsTerminal@1.18.3181.0"},
		{"unknown", "mypackage", "1.0.0", "", "pkg:generic/mypackage@1.0.0"},
	}

	for _, tc := range tests {
		result := generatePURL(tc.pkgManager, tc.name, tc.version, tc.arch)
		if result != tc.expected {
			t.Errorf("generatePURL(%q, %q, %q, %q) = %q, expected %q",
				tc.pkgManager, tc.name, tc.version, tc.arch, result, tc.expected)
		}
	}
}

func TestCollectAllComponents(t *testing.T) {
	c := NewCollector()
	components := c.collectAllComponents()

	// Should return at least some components on most systems
	// On a bare system this could be empty, so we just verify it doesn't panic
	if components == nil {
		t.Fatal("collectAllComponents returned nil")
	}

	// Verify each component has required fields
	for i, comp := range components {
		if comp.Name == "" {
			t.Errorf("Component %d has empty name", i)
		}
		if comp.Type == "" {
			t.Errorf("Component %d (%s) has empty type", i, comp.Name)
		}
	}
}

// Benchmark tests
func BenchmarkGetSBOMCycloneDX(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetSBOMCycloneDX()
	}
}

func BenchmarkGetSBOMSPDX(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetSBOMSPDX()
	}
}
