//go:build linux

package software

import (
	"testing"
)

func TestParseDpkgOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid dpkg output",
			input: `bash	5.1-6	amd64	1234	install ok installed	GNU Bourne Again SHell
coreutils	8.32-4	amd64	5678	install ok installed	GNU core utilities
git	2.34.1	amd64	9012	install ok installed	fast distributed version control
`,
			expected: 3,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name: "partial fields",
			input: `bash	5.1-6	amd64
incomplete
`,
			expected: 0,
		},
		{
			name: "mixed valid and invalid",
			input: `bash	5.1-6	amd64	1234	install ok installed	GNU Bourne Again SHell
incomplete
coreutils	8.32-4	amd64	5678	install ok installed	GNU core utilities
`,
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDpkgOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestParseDpkgOutputFields(t *testing.T) {
	input := `bash	5.1-6	amd64	1234	install ok installed	GNU Bourne Again SHell`
	result := parseDpkgOutput([]byte(input))

	if len(result) != 1 {
		t.Fatalf("expected 1 package, got %d", len(result))
	}

	pkg := result[0]
	if pkg.Name != "bash" {
		t.Errorf("expected name 'bash', got '%s'", pkg.Name)
	}
	if pkg.Version != "5.1-6" {
		t.Errorf("expected version '5.1-6', got '%s'", pkg.Version)
	}
	if pkg.Architecture != "amd64" {
		t.Errorf("expected arch 'amd64', got '%s'", pkg.Architecture)
	}
	if pkg.Size != 1234*1024 {
		t.Errorf("expected size %d, got %d", 1234*1024, pkg.Size)
	}
	if pkg.Status != "install ok installed" {
		t.Errorf("expected status 'install ok installed', got '%s'", pkg.Status)
	}
	if pkg.Description != "GNU Bourne Again SHell" {
		t.Errorf("expected description 'GNU Bourne Again SHell', got '%s'", pkg.Description)
	}
}

func TestParseRpmOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid rpm output",
			input: `bash	5.1.8-4.el9	x86_64	1234567	1699123456	GNU Bourne Again Shell
coreutils	8.32-34.el9	x86_64	2345678	1699123457	GNU Core Utilities
`,
			expected: 2,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRpmOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestParseApkOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid apk output",
			input: `alpine-baselayout-3.4.0-r0
busybox-1.35.0-r29
musl-1.2.3-r4
`,
			expected: 3,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseApkOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestParseApkOutputParsesVersion(t *testing.T) {
	input := `busybox-1.35.0-r29`
	result := parseApkOutput([]byte(input))

	if len(result) != 1 {
		t.Fatalf("expected 1 package, got %d", len(result))
	}

	pkg := result[0]
	if pkg.Name != "busybox" {
		t.Errorf("expected name 'busybox', got '%s'", pkg.Name)
	}
	if pkg.Version != "1.35.0-r29" {
		t.Errorf("expected version '1.35.0-r29', got '%s'", pkg.Version)
	}
}

func TestParsePacmanOutput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name: "valid pacman output",
			input: `bash 5.1.016-1
coreutils 9.1-1
git 2.39.1-1
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
bash 5.1.016-1
`,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parsePacmanOutput([]byte(tt.input))
			if len(result) != tt.expected {
				t.Errorf("expected %d packages, got %d", tt.expected, len(result))
			}
		})
	}
}
