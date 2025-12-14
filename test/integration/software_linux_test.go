//go:build integration && linux

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/software"
)

func TestGetPathExecutables_Linux(t *testing.T) {
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

	// Verify some common executables exist
	commonExecs := []string{"bash", "sh", "ls", "cat"}
	foundCount := 0
	for _, exec := range result.Executables {
		for _, common := range commonExecs {
			if exec.Name == common {
				foundCount++
				t.Logf("Found %s at %s (size: %d)", exec.Name, exec.Path, exec.Size)
			}
		}
	}

	if foundCount < 2 {
		t.Errorf("Expected to find at least 2 common executables, found %d", foundCount)
	}
}

func TestGetPathExecutables_Linux_MatchesWhich(t *testing.T) {
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

func TestGetSystemPackages_Linux_Dpkg(t *testing.T) {
	// Check if dpkg is available
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		t.Skip("dpkg-query not available, skipping")
	}

	c := software.NewCollector()

	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("GetSystemPackages failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetSystemPackages returned nil")
	}

	if result.PackageManager != "dpkg" {
		t.Logf("Package manager: %s (expected dpkg)", result.PackageManager)
	}

	t.Logf("Found %d packages via %s", result.Count, result.PackageManager)

	// Verify against dpkg -l
	dpkgOutput, err := exec.Command("dpkg", "-l").Output()
	if err != nil {
		t.Logf("dpkg -l failed: %v", err)
		return
	}

	// Count installed packages from dpkg -l
	lines := strings.Split(string(dpkgOutput), "\n")
	dpkgCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "ii ") {
			dpkgCount++
		}
	}

	// Allow some tolerance
	if result.Count > 0 && dpkgCount > 0 {
		ratio := float64(result.Count) / float64(dpkgCount)
		if ratio < 0.8 || ratio > 1.2 {
			t.Logf("Package count differs significantly: got %d, dpkg -l shows %d", result.Count, dpkgCount)
		}
	}

	// Verify some common packages exist
	if result.PackageManager == "dpkg" && result.Count > 0 {
		foundCoreutils := false
		for _, pkg := range result.Packages {
			if pkg.Name == "coreutils" || pkg.Name == "bash" {
				foundCoreutils = true
				t.Logf("Found %s version %s", pkg.Name, pkg.Version)
				break
			}
		}
		if !foundCoreutils {
			t.Log("Warning: Could not find coreutils or bash package")
		}
	}
}

func TestGetSystemPackages_Linux_Rpm(t *testing.T) {
	// Check if rpm is available
	if _, err := exec.LookPath("rpm"); err != nil {
		t.Skip("rpm not available, skipping")
	}

	// Also skip if dpkg is primary (Debian-based systems)
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		t.Skip("dpkg is primary package manager, skipping rpm test")
	}

	c := software.NewCollector()

	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("GetSystemPackages failed: %v", err)
	}

	if result.PackageManager != "rpm" {
		t.Errorf("Expected rpm package manager, got %s", result.PackageManager)
	}

	t.Logf("Found %d packages via rpm", result.Count)
}

func TestGetPathExecutables_Linux_SymlinkHandling(t *testing.T) {
	c := software.NewCollector()

	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("GetPathExecutables failed: %v", err)
	}

	// Count symlinks
	symlinkCount := 0
	for _, exe := range result.Executables {
		if exe.IsSymlink {
			symlinkCount++
			t.Logf("Symlink: %s -> %s", exe.Path, exe.Target)
			if symlinkCount >= 5 {
				break
			}
		}
	}

	t.Logf("Found %d symlinks among executables", symlinkCount)
}

func TestGetPathExecutables_Linux_CustomPath(t *testing.T) {
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
