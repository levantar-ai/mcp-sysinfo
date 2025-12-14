//go:build integration && darwin

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/software"
)

func TestGetPathExecutables_Darwin(t *testing.T) {
	c := software.NewCollector()

	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("GetPathExecutables failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetPathExecutables returned nil")
	}

	if result.Count != len(result.Executables) {
		t.Errorf("Count mismatch: got %d, expected %d", result.Count, len(result.Executables))
	}

	// Verify PATH directories are populated
	if len(result.PathDirs) == 0 {
		t.Error("PathDirs should not be empty")
	}

	t.Logf("Found %d executables in PATH", result.Count)
	t.Logf("PATH directories: %v", result.PathDirs)

	// Verify some common macOS executables exist
	commonExecs := []string{"bash", "sh", "ls", "cat"}
	foundCount := 0
	for _, exe := range result.Executables {
		for _, common := range commonExecs {
			if exe.Name == common {
				foundCount++
				t.Logf("Found %s at %s (size: %d)", exe.Name, exe.Path, exe.Size)
			}
		}
	}

	if foundCount < 2 {
		t.Errorf("Expected to find at least 2 common executables, found %d", foundCount)
	}
}

func TestGetPathExecutables_Darwin_MatchesWhich(t *testing.T) {
	c := software.NewCollector()

	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("GetPathExecutables failed: %v", err)
	}

	// Verify against which command for common binaries
	testBinaries := []string{"bash", "ls", "cat"}

	for _, bin := range testBinaries {
		whichOutput, err := exec.Command("which", bin).Output()
		if err != nil {
			t.Logf("which %s failed: %v", bin, err)
			continue
		}

		expectedPath := strings.TrimSpace(string(whichOutput))

		// Find in our results
		found := false
		for _, exe := range result.Executables {
			if exe.Name == bin {
				if exe.Path != expectedPath {
					t.Logf("Path differs for %s: got %s, which says %s", bin, exe.Path, expectedPath)
				}
				found = true
				break
			}
		}

		if !found {
			t.Errorf("Failed to find %s (expected at %s)", bin, expectedPath)
		}
	}
}

func TestGetSystemPackages_Darwin_Brew(t *testing.T) {
	// Check if brew is available
	if _, err := exec.LookPath("brew"); err != nil {
		t.Skip("brew not available, skipping")
	}

	c := software.NewCollector()

	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("GetSystemPackages failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetSystemPackages returned nil")
	}

	if result.PackageManager != "brew" {
		t.Logf("Package manager: %s (expected brew)", result.PackageManager)
	}

	t.Logf("Found %d packages via %s", result.Count, result.PackageManager)

	// Verify against brew list
	brewOutput, err := exec.Command("brew", "list", "--versions").Output()
	if err != nil {
		t.Logf("brew list failed: %v", err)
		return
	}

	// Count packages from brew list
	lines := strings.Split(strings.TrimSpace(string(brewOutput)), "\n")
	brewCount := 0
	for _, line := range lines {
		if line != "" {
			brewCount++
		}
	}

	// Allow some tolerance
	if result.Count > 0 && brewCount > 0 {
		ratio := float64(result.Count) / float64(brewCount)
		if ratio < 0.8 || ratio > 1.2 {
			t.Logf("Package count differs: got %d, brew shows %d", result.Count, brewCount)
		}
	}
}

func TestGetSystemPackages_Darwin_Pkgutil(t *testing.T) {
	// Skip if brew is primary
	if _, err := exec.LookPath("brew"); err == nil {
		t.Skip("brew is available, skipping pkgutil test")
	}

	c := software.NewCollector()

	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("GetSystemPackages failed: %v", err)
	}

	if result.PackageManager != "pkgutil" {
		t.Errorf("Expected pkgutil package manager, got %s", result.PackageManager)
	}

	t.Logf("Found %d packages via pkgutil", result.Count)

	// Verify some Apple packages exist
	foundApple := false
	for _, pkg := range result.Packages {
		if strings.HasPrefix(pkg.Name, "com.apple.") {
			foundApple = true
			t.Logf("Found Apple package: %s", pkg.Name)
			break
		}
	}

	if !foundApple && result.Count > 0 {
		t.Log("Warning: No Apple packages found")
	}
}

func TestGetPathExecutables_Darwin_CustomPath(t *testing.T) {
	// Test with custom PATH
	originalPath := os.Getenv("PATH")
	defer os.Setenv("PATH", originalPath)

	os.Setenv("PATH", "/bin:/usr/bin")

	c := software.NewCollector()
	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("GetPathExecutables failed: %v", err)
	}

	if len(result.PathDirs) != 2 {
		t.Errorf("Expected 2 PATH dirs, got %d: %v", len(result.PathDirs), result.PathDirs)
	}

	// Should still find basic executables
	foundLs := false
	for _, exe := range result.Executables {
		if exe.Name == "ls" {
			foundLs = true
			break
		}
	}

	if !foundLs {
		t.Error("Failed to find 'ls' in /bin:/usr/bin")
	}
}
