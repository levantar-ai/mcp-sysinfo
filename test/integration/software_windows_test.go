//go:build integration && windows

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/software"
)

func TestGetPathExecutables_Windows(t *testing.T) {
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

	// Verify some common Windows executables exist
	commonExecs := []string{"cmd.exe", "powershell.exe", "notepad.exe"}
	foundCount := 0
	for _, exe := range result.Executables {
		nameLower := strings.ToLower(exe.Name)
		for _, common := range commonExecs {
			if nameLower == common {
				foundCount++
				t.Logf("Found %s at %s (size: %d)", exe.Name, exe.Path, exe.Size)
			}
		}
	}

	if foundCount < 1 {
		t.Errorf("Expected to find at least 1 common executable, found %d", foundCount)
	}
}

func TestGetPathExecutables_Windows_MatchesWhere(t *testing.T) {
	c := software.NewCollector()

	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("GetPathExecutables failed: %v", err)
	}

	// Verify against where command for common binaries
	testBinaries := []string{"cmd.exe", "notepad.exe"}

	for _, bin := range testBinaries {
		whereOutput, err := exec.Command("where", bin).Output()
		if err != nil {
			t.Logf("where %s failed: %v", bin, err)
			continue
		}

		// where returns multiple paths, get first one
		paths := strings.Split(strings.TrimSpace(string(whereOutput)), "\n")
		if len(paths) == 0 {
			continue
		}
		expectedPath := strings.TrimSpace(paths[0])

		// Find in our results
		found := false
		binLower := strings.ToLower(bin)
		for _, exe := range result.Executables {
			if strings.ToLower(exe.Name) == binLower {
				found = true
				if !strings.EqualFold(exe.Path, expectedPath) {
					t.Logf("Path differs for %s: got %s, where says %s", bin, exe.Path, expectedPath)
				}
				break
			}
		}

		if !found {
			t.Errorf("Failed to find %s (expected at %s)", bin, expectedPath)
		}
	}
}

func TestGetSystemPackages_Windows_Chocolatey(t *testing.T) {
	// Check if choco is available
	if _, err := exec.LookPath("choco"); err != nil {
		t.Skip("chocolatey not available, skipping")
	}

	c := software.NewCollector()

	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("GetSystemPackages failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetSystemPackages returned nil")
	}

	if result.PackageManager != "chocolatey" {
		t.Logf("Package manager: %s (expected chocolatey)", result.PackageManager)
	}

	t.Logf("Found %d packages via %s", result.Count, result.PackageManager)

	// Verify against choco list
	chocoOutput, err := exec.Command("choco", "list", "--local-only", "--limit-output").Output()
	if err != nil {
		t.Logf("choco list failed: %v", err)
		return
	}

	// Count packages from choco list
	lines := strings.Split(strings.TrimSpace(string(chocoOutput)), "\n")
	chocoCount := 0
	for _, line := range lines {
		if strings.Contains(line, "|") {
			chocoCount++
		}
	}

	// Allow some tolerance
	if result.Count > 0 && chocoCount > 0 {
		ratio := float64(result.Count) / float64(chocoCount)
		if ratio < 0.8 || ratio > 1.2 {
			t.Logf("Package count differs: got %d, choco shows %d", result.Count, chocoCount)
		}
	}
}

func TestGetSystemPackages_Windows_Winget(t *testing.T) {
	// Check if winget is available
	if _, err := exec.LookPath("winget"); err != nil {
		t.Skip("winget not available, skipping")
	}

	// Skip if chocolatey is primary
	if _, err := exec.LookPath("choco"); err == nil {
		t.Skip("chocolatey is available, skipping winget test")
	}

	c := software.NewCollector()

	result, err := c.GetSystemPackages()
	if err != nil {
		t.Fatalf("GetSystemPackages failed: %v", err)
	}

	if result.PackageManager != "winget" {
		t.Errorf("Expected winget package manager, got %s", result.PackageManager)
	}

	t.Logf("Found %d packages via winget", result.Count)
}

func TestGetPathExecutables_Windows_ExtensionFiltering(t *testing.T) {
	c := software.NewCollector()

	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("GetPathExecutables failed: %v", err)
	}

	// Verify only executable extensions are included
	validExts := map[string]bool{
		".exe": true,
		".cmd": true,
		".bat": true,
		".com": true,
		".ps1": true,
	}

	invalidCount := 0
	for _, exe := range result.Executables {
		ext := strings.ToLower(exe.Name[strings.LastIndex(exe.Name, "."):])
		if !validExts[ext] {
			invalidCount++
			t.Logf("Unexpected extension: %s (%s)", exe.Name, ext)
			if invalidCount > 5 {
				break
			}
		}
	}

	if invalidCount > 0 {
		t.Errorf("Found %d executables with unexpected extensions", invalidCount)
	}
}

func TestGetPathExecutables_Windows_CustomPath(t *testing.T) {
	// Test with custom PATH
	originalPath := os.Getenv("PATH")
	defer os.Setenv("PATH", originalPath)

	os.Setenv("PATH", `C:\Windows\system32;C:\Windows`)

	c := software.NewCollector()
	result, err := c.GetPathExecutables()
	if err != nil {
		t.Fatalf("GetPathExecutables failed: %v", err)
	}

	if len(result.PathDirs) != 2 {
		t.Errorf("Expected 2 PATH dirs, got %d: %v", len(result.PathDirs), result.PathDirs)
	}

	// Should still find cmd.exe
	foundCmd := false
	for _, exe := range result.Executables {
		if strings.EqualFold(exe.Name, "cmd.exe") {
			foundCmd = true
			break
		}
	}

	if !foundCmd {
		t.Error("Failed to find 'cmd.exe' in Windows system directories")
	}
}
