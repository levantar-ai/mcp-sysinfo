//go:build windows

package software

import (
	"testing"
)

func TestParseChocoOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid choco output",
			input: `git|2.39.1
nodejs|18.14.0
python|3.11.1
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
git|2.39.1
`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseChocoOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestParseChocoOutputFields(t *testing.T) {
	input := `git|2.39.1`
	result := parseChocoOutput([]byte(input))

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
	if pkg.Source != "chocolatey" {
		t.Errorf("expected source 'chocolatey', got '%s'", pkg.Source)
	}
}

func TestParseWingetOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid winget output",
			input: `Name                            Id                          Version
-----------------------------------------------------------
Git                             Git.Git                     2.39.1
Node.js                         OpenJS.NodeJS               18.14.0
`,
			expected: 2,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name: "only header",
			input: `Name                            Id                          Version
-----------------------------------------------------------
`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseWingetOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestParseWmicOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid wmic output",
			input: `Node,Name,Version
DESKTOP-ABC,Microsoft Visual C++ 2019,14.28.29914
DESKTOP-ABC,Git,2.39.1
`,
			expected: 2,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name: "only header",
			input: `Node,Name,Version
`,
			expected: 0,
		},
		{
			name: "with empty name",
			input: `Node,Name,Version
DESKTOP-ABC,,1.0.0
DESKTOP-ABC,Git,2.39.1
`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseWmicOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestParseWmicOutputFields(t *testing.T) {
	input := `Node,Name,Version
DESKTOP-ABC,Git,2.39.1`
	result := parseWmicOutput([]byte(input))

	if len(result) != 1 {
		t.Fatalf("expected 1 package, got %d", len(result))
	}

	pkg := result[0]
	if pkg.Name != "Git" {
		t.Errorf("expected name 'Git', got '%s'", pkg.Name)
	}
	if pkg.Version != "2.39.1" {
		t.Errorf("expected version '2.39.1', got '%s'", pkg.Version)
	}
	if pkg.Source != "wmic" {
		t.Errorf("expected source 'wmic', got '%s'", pkg.Source)
	}
}
