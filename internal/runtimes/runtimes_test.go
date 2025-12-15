package runtimes

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetLanguageRuntimes(t *testing.T) {
	c := NewCollector()
	result, err := c.GetLanguageRuntimes()
	if err != nil {
		t.Fatalf("GetLanguageRuntimes failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetLanguageRuntimes returned nil result")
	}

	// Count should match runtimes length
	if result.Count != len(result.Runtimes) {
		t.Errorf("Count mismatch: %d != %d", result.Count, len(result.Runtimes))
	}

	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Validate each runtime
	validRuntimes := []string{"python", "node", "go", "ruby", "java", "php", "rust", "dotnet", "perl"}
	for _, rt := range result.Runtimes {
		if rt.Name == "" {
			t.Error("Runtime name should not be empty")
		}

		found := false
		for _, valid := range validRuntimes {
			if rt.Name == valid {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Unknown runtime name: %s", rt.Name)
		}

		if rt.Path == "" {
			t.Errorf("Runtime %s path should not be empty", rt.Name)
		}

		// Version should be set for most runtimes
		// (some might fail version detection)
		if rt.Version == "" {
			t.Logf("Warning: Runtime %s has no version detected", rt.Name)
		}
	}
}

func TestDetectPython(t *testing.T) {
	c := NewCollector()
	runtime := c.detectPython()

	// Python might not be installed, which is fine
	if runtime == nil {
		t.Log("Python not detected (might not be installed)")
		return
	}

	if runtime.Name != "python" {
		t.Errorf("Expected name 'python', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error("Python path should not be empty")
	}
}

func TestDetectNode(t *testing.T) {
	c := NewCollector()
	runtime := c.detectNode()

	// Node might not be installed, which is fine
	if runtime == nil {
		t.Log("Node.js not detected (might not be installed)")
		return
	}

	if runtime.Name != "node" {
		t.Errorf("Expected name 'node', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error("Node.js path should not be empty")
	}

	// If node is installed, npm usually is too
	if runtime.Manager != "npm" {
		t.Log("npm not detected as package manager")
	}
}

func TestDetectGo(t *testing.T) {
	c := NewCollector()
	runtime := c.detectGo()

	// Go might not be installed, which is fine
	if runtime == nil {
		t.Log("Go not detected (might not be installed)")
		return
	}

	if runtime.Name != "go" {
		t.Errorf("Expected name 'go', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error("Go path should not be empty")
	}

	// Go should have "go mod" as manager
	if runtime.Manager != "go mod" {
		t.Errorf("Expected manager 'go mod', got '%s'", runtime.Manager)
	}
}

func TestDetectRuby(t *testing.T) {
	c := NewCollector()
	runtime := c.detectRuby()

	// Ruby might not be installed, which is fine
	if runtime == nil {
		t.Log("Ruby not detected (might not be installed)")
		return
	}

	if runtime.Name != "ruby" {
		t.Errorf("Expected name 'ruby', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error("Ruby path should not be empty")
	}
}

func TestDetectJava(t *testing.T) {
	c := NewCollector()
	runtime := c.detectJava()

	// Java might not be installed, which is fine
	if runtime == nil {
		t.Log("Java not detected (might not be installed)")
		return
	}

	if runtime.Name != "java" {
		t.Errorf("Expected name 'java', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error("Java path should not be empty")
	}
}

func TestDetectPHP(t *testing.T) {
	c := NewCollector()
	runtime := c.detectPHP()

	// PHP might not be installed, which is fine
	if runtime == nil {
		t.Log("PHP not detected (might not be installed)")
		return
	}

	if runtime.Name != "php" {
		t.Errorf("Expected name 'php', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error("PHP path should not be empty")
	}
}

func TestDetectRust(t *testing.T) {
	c := NewCollector()
	runtime := c.detectRust()

	// Rust might not be installed, which is fine
	if runtime == nil {
		t.Log("Rust not detected (might not be installed)")
		return
	}

	if runtime.Name != "rust" {
		t.Errorf("Expected name 'rust', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error("Rust path should not be empty")
	}
}

func TestDetectDotNet(t *testing.T) {
	c := NewCollector()
	runtime := c.detectDotNet()

	// .NET might not be installed, which is fine
	if runtime == nil {
		t.Log(".NET not detected (might not be installed)")
		return
	}

	if runtime.Name != "dotnet" {
		t.Errorf("Expected name 'dotnet', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error(".NET path should not be empty")
	}
}

func TestDetectPerl(t *testing.T) {
	c := NewCollector()
	runtime := c.detectPerl()

	// Perl might not be installed, which is fine
	if runtime == nil {
		t.Log("Perl not detected (might not be installed)")
		return
	}

	if runtime.Name != "perl" {
		t.Errorf("Expected name 'perl', got '%s'", runtime.Name)
	}

	if runtime.Path == "" {
		t.Error("Perl path should not be empty")
	}
}
