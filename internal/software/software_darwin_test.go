//go:build darwin

package software

import (
	"testing"
)

func TestParseBrewOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid brew output",
			input: `git 2.39.1
node 18.14.0 19.5.0
python@3.11 3.11.1
`,
			expected: 3,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name: "single field lines",
			input: `incomplete
git 2.39.1
`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBrewOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestParseBrewOutputFields(t *testing.T) {
	input := `git 2.39.1`
	result := parseBrewOutput([]byte(input))

	if len(result) != 1 {
		t.Fatalf("expected 1 package, got %d", len(result))
	}

	pkg := result[0]
	if pkg.Name != "git" {
		t.Errorf("expected name 'git', got '%s'", pkg.Name)
	}
	if pkg.Version != "2.39.1" {
		t.Errorf("expected version '2.39.1', got '%s'", pkg.Version)
	}
	if pkg.Source != "homebrew" {
		t.Errorf("expected source 'homebrew', got '%s'", pkg.Source)
	}
}

func TestParseBrewOutputMultipleVersions(t *testing.T) {
	// Brew can show multiple versions, we take the first
	input := `node 18.14.0 19.5.0`
	result := parseBrewOutput([]byte(input))

	if len(result) != 1 {
		t.Fatalf("expected 1 package, got %d", len(result))
	}

	pkg := result[0]
	if pkg.Name != "node" {
		t.Errorf("expected name 'node', got '%s'", pkg.Name)
	}
	if pkg.Version != "18.14.0" {
		t.Errorf("expected version '18.14.0', got '%s'", pkg.Version)
	}
}

func TestParsePkgutilOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid pkgutil output",
			input: `com.apple.pkg.CoreTypes
com.apple.pkg.Berkeley
com.apple.pkg.Files
`,
			expected: 3,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name: "with empty lines",
			input: `com.apple.pkg.CoreTypes

com.apple.pkg.Berkeley
`,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePkgutilOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestParsePkgutilOutputFields(t *testing.T) {
	input := `com.apple.pkg.CoreTypes`
	result := parsePkgutilOutput([]byte(input))

	if len(result) != 1 {
		t.Fatalf("expected 1 package, got %d", len(result))
	}

	pkg := result[0]
	if pkg.Name != "com.apple.pkg.CoreTypes" {
		t.Errorf("expected name 'com.apple.pkg.CoreTypes', got '%s'", pkg.Name)
	}
	if pkg.Source != "pkgutil" {
		t.Errorf("expected source 'pkgutil', got '%s'", pkg.Source)
	}
}
