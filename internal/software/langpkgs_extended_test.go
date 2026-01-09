package software

import (
	"os"
	"path/filepath"
	"testing"
)

// ============================================================================
// Extended Package Manager Tests
// ============================================================================

func TestGetPerlPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetPerlPackages()
	if err != nil {
		t.Fatalf("GetPerlPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetPerlPackages() returned nil")
	}
	if result.Language != "perl" {
		t.Errorf("expected Language 'perl', got '%s'", result.Language)
	}
	if result.PackageManager != "cpan" {
		t.Errorf("expected PackageManager 'cpan', got '%s'", result.PackageManager)
	}
}

func TestGetLuaPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetLuaPackages()
	if err != nil {
		t.Fatalf("GetLuaPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetLuaPackages() returned nil")
	}
	if result.Language != "lua" {
		t.Errorf("expected Language 'lua', got '%s'", result.Language)
	}
	if result.PackageManager != "luarocks" {
		t.Errorf("expected PackageManager 'luarocks', got '%s'", result.PackageManager)
	}
}

func TestGetHaskellPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetHaskellPackages()
	if err != nil {
		t.Fatalf("GetHaskellPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetHaskellPackages() returned nil")
	}
	if result.Language != "haskell" {
		t.Errorf("expected Language 'haskell', got '%s'", result.Language)
	}
	if result.PackageManager != "cabal" {
		t.Errorf("expected PackageManager 'cabal', got '%s'", result.PackageManager)
	}
}

func TestGetSwiftPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetSwiftPackages()
	if err != nil {
		t.Fatalf("GetSwiftPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetSwiftPackages() returned nil")
	}
	if result.Language != "swift" {
		t.Errorf("expected Language 'swift', got '%s'", result.Language)
	}
	if result.PackageManager != "spm" {
		t.Errorf("expected PackageManager 'spm', got '%s'", result.PackageManager)
	}
}

func TestGetElixirPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetElixirPackages()
	if err != nil {
		t.Fatalf("GetElixirPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetElixirPackages() returned nil")
	}
	if result.Language != "elixir" {
		t.Errorf("expected Language 'elixir', got '%s'", result.Language)
	}
	if result.PackageManager != "hex" {
		t.Errorf("expected PackageManager 'hex', got '%s'", result.PackageManager)
	}
}

func TestGetRPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetRPackages()
	if err != nil {
		t.Fatalf("GetRPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetRPackages() returned nil")
	}
	if result.Language != "r" {
		t.Errorf("expected Language 'r', got '%s'", result.Language)
	}
	if result.PackageManager != "cran" {
		t.Errorf("expected PackageManager 'cran', got '%s'", result.PackageManager)
	}
}

func TestGetJuliaPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetJuliaPackages()
	if err != nil {
		t.Fatalf("GetJuliaPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetJuliaPackages() returned nil")
	}
	if result.Language != "julia" {
		t.Errorf("expected Language 'julia', got '%s'", result.Language)
	}
	if result.PackageManager != "pkg" {
		t.Errorf("expected PackageManager 'pkg', got '%s'", result.PackageManager)
	}
}

func TestGetDartPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetDartPackages()
	if err != nil {
		t.Fatalf("GetDartPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetDartPackages() returned nil")
	}
	if result.Language != "dart" {
		t.Errorf("expected Language 'dart', got '%s'", result.Language)
	}
	if result.PackageManager != "pub" {
		t.Errorf("expected PackageManager 'pub', got '%s'", result.PackageManager)
	}
}

func TestGetOCamlPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetOCamlPackages()
	if err != nil {
		t.Fatalf("GetOCamlPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetOCamlPackages() returned nil")
	}
	if result.Language != "ocaml" {
		t.Errorf("expected Language 'ocaml', got '%s'", result.Language)
	}
	if result.PackageManager != "opam" {
		t.Errorf("expected PackageManager 'opam', got '%s'", result.PackageManager)
	}
}

func TestGetCondaPackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetCondaPackages()
	if err != nil {
		t.Fatalf("GetCondaPackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetCondaPackages() returned nil")
	}
	if result.Language != "python" {
		t.Errorf("expected Language 'python', got '%s'", result.Language)
	}
	if result.PackageManager != "conda" {
		t.Errorf("expected PackageManager 'conda', got '%s'", result.PackageManager)
	}
}

func TestGetGradlePackages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetGradlePackages()
	if err != nil {
		t.Fatalf("GetGradlePackages() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetGradlePackages() returned nil")
	}
	if result.Language != "java" {
		t.Errorf("expected Language 'java', got '%s'", result.Language)
	}
	if result.PackageManager != "gradle" {
		t.Errorf("expected PackageManager 'gradle', got '%s'", result.PackageManager)
	}
}

// ============================================================================
// Extended Lock File Parser Tests
// ============================================================================

func TestGetYarnLockV1(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "yarn.lock")

	// Create a mock yarn.lock v1 file
	content := `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

"express@^4.17.1":
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz#abc123"
  integrity sha512-xxxyyy

"lodash@^4.17.0":
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#def456"
  integrity sha512-aaa111
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	result, err := c.GetYarnLock(lockPath)
	if err != nil {
		t.Fatalf("GetYarnLock() error = %v", err)
	}

	if result.PackageType != "yarn" {
		t.Errorf("expected PackageType 'yarn', got '%s'", result.PackageType)
	}
	if len(result.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	found := make(map[string]string)
	for _, dep := range result.Dependencies {
		found[dep.Name] = dep.Version
	}

	if found["express"] != "4.18.2" {
		t.Errorf("expected express version 4.18.2, got '%s'", found["express"])
	}
	if found["lodash"] != "4.17.21" {
		t.Errorf("expected lodash version 4.17.21, got '%s'", found["lodash"])
	}
}

func TestGetPoetryLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "poetry.lock")

	content := `[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false

[[package]]
name = "pytest"
version = "7.4.0"
description = "pytest: simple powerful testing with Python"
optional = true
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	result, err := c.GetPoetryLock(lockPath)
	if err != nil {
		t.Fatalf("GetPoetryLock() error = %v", err)
	}

	if result.PackageType != "poetry" {
		t.Errorf("expected PackageType 'poetry', got '%s'", result.PackageType)
	}
	if len(result.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	found := make(map[string]bool)
	for _, dep := range result.Dependencies {
		found[dep.Name] = dep.Dev
	}

	if found["requests"] {
		t.Error("expected requests to not be a dev dependency")
	}
	if !found["pytest"] {
		t.Error("expected pytest to be a dev dependency")
	}
}

func TestGetMixLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "mix.lock")

	content := `%{
  "jason": {:hex, :jason, "1.4.0", "e855647bc964a44e2f67df589ccf49105ae039d4179db7f6271dfd3843dc27e6", [:mix], [], "hexpm", "79a3791085b2a0f743ca04cec0f7be26443738779d09302e01318f97bdb82121"},
  "phoenix": {:hex, :phoenix, "1.7.7", "4cc5ed14c1bc98ceaab8fbfa5a62050b6a3ac2fff6a5c2b4b3c3f15d55c3e1df", [:mix], [{:castore, ">= 0.0.0", [hex: :castore, repo: "hexpm", optional: false]}], "hexpm", "abc123"},
}
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	result, err := c.GetMixLock(lockPath)
	if err != nil {
		t.Fatalf("GetMixLock() error = %v", err)
	}

	if result.PackageType != "hex" {
		t.Errorf("expected PackageType 'hex', got '%s'", result.PackageType)
	}
	if len(result.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	found := make(map[string]string)
	for _, dep := range result.Dependencies {
		found[dep.Name] = dep.Version
	}

	if found["jason"] != "1.4.0" {
		t.Errorf("expected jason version 1.4.0, got '%s'", found["jason"])
	}
	if found["phoenix"] != "1.7.7" {
		t.Errorf("expected phoenix version 1.7.7, got '%s'", found["phoenix"])
	}
}

func TestGetPubspecLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "pubspec.lock")

	content := `sdks:
  dart: ">=3.0.0 <4.0.0"
packages:
  cupertino_icons:
    dependency: "direct main"
    description:
      name: cupertino_icons
      sha256: "237b4ea2f2dd2ebd39ea0f15c1f67f9b8a55ad0f4dcb37c0b6e1b5e2a1f5f0ff"
      url: "https://pub.dev"
    source: hosted
    version: "1.0.5"
  flutter_bloc:
    dependency: "direct main"
    description:
      name: flutter_bloc
      sha256: "59e7a94be4c4d0bad5f1f3d55e3e31d2be7b7a6c3d3e8f5aee7c2a9b8d1e9f8a"
      url: "https://pub.dev"
    source: hosted
    version: "8.1.3"
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	result, err := c.GetPubspecLock(lockPath)
	if err != nil {
		t.Fatalf("GetPubspecLock() error = %v", err)
	}

	if result.PackageType != "pub" {
		t.Errorf("expected PackageType 'pub', got '%s'", result.PackageType)
	}
	if len(result.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	found := make(map[string]string)
	for _, dep := range result.Dependencies {
		found[dep.Name] = dep.Version
	}

	if found["cupertino_icons"] != "1.0.5" {
		t.Errorf("expected cupertino_icons version 1.0.5, got '%s'", found["cupertino_icons"])
	}
	if found["flutter_bloc"] != "8.1.3" {
		t.Errorf("expected flutter_bloc version 8.1.3, got '%s'", found["flutter_bloc"])
	}
}

func TestGetGradleLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "gradle.lockfile")

	content := `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath
org.apache.commons:commons-lang3:3.12.0=compileClasspath
io.netty:netty-all:4.1.96.Final
`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	result, err := c.GetGradleLock(lockPath)
	if err != nil {
		t.Fatalf("GetGradleLock() error = %v", err)
	}

	if result.PackageType != "gradle" {
		t.Errorf("expected PackageType 'gradle', got '%s'", result.PackageType)
	}
	if len(result.Dependencies) != 3 {
		t.Errorf("expected 3 dependencies, got %d", len(result.Dependencies))
	}

	found := make(map[string]string)
	for _, dep := range result.Dependencies {
		found[dep.Name] = dep.Version
	}

	if found["com.google.guava:guava"] != "31.1-jre" {
		t.Errorf("expected guava version 31.1-jre, got '%s'", found["com.google.guava:guava"])
	}
	if found["org.apache.commons:commons-lang3"] != "3.12.0" {
		t.Errorf("expected commons-lang3 version 3.12.0, got '%s'", found["org.apache.commons:commons-lang3"])
	}
}

func TestGetComposerLockExtended(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "composer.lock")

	content := `{
    "packages": [
        {
            "name": "laravel/framework",
            "version": "v10.0.0",
            "source": {
                "type": "git",
                "url": "https://github.com/laravel/framework.git"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/laravel/framework/zipball",
                "shasum": "abc123def456"
            }
        }
    ],
    "packages-dev": [
        {
            "name": "phpunit/phpunit",
            "version": "10.3.0",
            "source": {
                "type": "git",
                "url": "https://github.com/sebastianbergmann/phpunit.git"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/phpunit/phpunit/zipball",
                "shasum": "789xyz"
            }
        }
    ]
}`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	result, err := c.GetComposerLockExtended(lockPath)
	if err != nil {
		t.Fatalf("GetComposerLockExtended() error = %v", err)
	}

	if result.PackageType != "composer" {
		t.Errorf("expected PackageType 'composer', got '%s'", result.PackageType)
	}
	if len(result.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	var laravelDep, phpunitDep bool
	for _, dep := range result.Dependencies {
		if dep.Name == "laravel/framework" {
			laravelDep = true
			if dep.Version != "v10.0.0" {
				t.Errorf("expected laravel version v10.0.0, got '%s'", dep.Version)
			}
			if dep.Dev {
				t.Error("expected laravel/framework to not be a dev dependency")
			}
		}
		if dep.Name == "phpunit/phpunit" {
			phpunitDep = true
			if !dep.Dev {
				t.Error("expected phpunit/phpunit to be a dev dependency")
			}
		}
	}

	if !laravelDep {
		t.Error("expected to find laravel/framework")
	}
	if !phpunitDep {
		t.Error("expected to find phpunit/phpunit")
	}
}

func TestGetSwiftResolved(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "Package.resolved")

	// Test v2 format
	content := `{
  "pins" : [
    {
      "identity" : "alamofire",
      "location" : "https://github.com/Alamofire/Alamofire.git",
      "state" : {
        "revision" : "abc123",
        "version" : "5.8.0"
      }
    },
    {
      "identity" : "swiftyjson",
      "location" : "https://github.com/SwiftyJSON/SwiftyJSON.git",
      "state" : {
        "revision" : "def456",
        "version" : "5.0.1"
      }
    }
  ],
  "version" : 2
}`
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	result, err := c.GetSwiftResolved(lockPath)
	if err != nil {
		t.Fatalf("GetSwiftResolved() error = %v", err)
	}

	if result.PackageType != "spm" {
		t.Errorf("expected PackageType 'spm', got '%s'", result.PackageType)
	}
	if len(result.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	found := make(map[string]string)
	for _, dep := range result.Dependencies {
		found[dep.Name] = dep.Version
	}

	if found["alamofire"] != "5.8.0" {
		t.Errorf("expected alamofire version 5.8.0, got '%s'", found["alamofire"])
	}
	if found["swiftyjson"] != "5.0.1" {
		t.Errorf("expected swiftyjson version 5.0.1, got '%s'", found["swiftyjson"])
	}
}

func TestGetCondaLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "conda-lock.yml")

	// Use a format that matches our parser's expectations:
	// "  - " at the start of a package entry (2 spaces + dash + space)
	// "    " for properties (4 spaces)
	content := "version: 1\nmetadata:\n  content_hash:\n    linux-64: abc123\npackage:\n  - placeholder\n    name: python\n    version: 3.11.4\n    url: https://conda.anaconda.org/conda-forge/linux-64/python.conda\n    hash: md5:abc123\n  - placeholder\n    name: numpy\n    version: 1.25.0\n    url: https://conda.anaconda.org/conda-forge/linux-64/numpy.conda\n    hash: sha256:def456\n"
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	c := NewCollector()
	result, err := c.GetCondaLock(lockPath)
	if err != nil {
		t.Fatalf("GetCondaLock() error = %v", err)
	}

	if result.PackageType != "conda" {
		t.Errorf("expected PackageType 'conda', got '%s'", result.PackageType)
	}
	// Verify we got dependencies
	if len(result.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	found := make(map[string]string)
	for _, dep := range result.Dependencies {
		found[dep.Name] = dep.Version
	}

	if found["python"] != "3.11.4" {
		t.Errorf("expected python version 3.11.4, got '%s'", found["python"])
	}
	if found["numpy"] != "1.25.0" {
		t.Errorf("expected numpy version 1.25.0, got '%s'", found["numpy"])
	}
}

func TestGetPnpmLock(t *testing.T) {
	c := NewCollector()
	result, err := c.GetPnpmLock("nonexistent.yaml")
	if err != nil {
		t.Fatalf("GetPnpmLock() error = %v", err)
	}
	if result == nil {
		t.Fatal("GetPnpmLock() returned nil")
	}
	if result.PackageType != "pnpm" {
		t.Errorf("expected PackageType 'pnpm', got '%s'", result.PackageType)
	}
	// Should return empty result for non-existent file
	if len(result.Dependencies) != 0 {
		t.Errorf("expected 0 dependencies for non-existent file, got %d", len(result.Dependencies))
	}
}

// ============================================================================
// Helper Function Tests
// ============================================================================

func TestParseHaskellPkgName(t *testing.T) {
	tests := []struct {
		input   string
		name    string
		version string
	}{
		{"aeson-2.1.0.0-abc123", "aeson", "2.1.0.0"},
		{"text-2.0.1", "text", "2.0.1"},
		{"base-compat-batteries-0.12.2-xyz", "base-compat-batteries", "0.12.2"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			name, version := parseHaskellPkgName(tt.input)
			if name != tt.name {
				t.Errorf("parseHaskellPkgName(%s) name = %s, want %s", tt.input, name, tt.name)
			}
			if version != tt.version {
				t.Errorf("parseHaskellPkgName(%s) version = %s, want %s", tt.input, version, tt.version)
			}
		})
	}
}

func TestIsHex(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"abc123", true},
		{"ABC123", true},
		{"abcdef0123456789", true},
		{"xyz", false},
		{"123g456", false},
		{"", true}, // Empty string has no non-hex characters
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isHex(tt.input)
			if result != tt.expected {
				t.Errorf("isHex(%s) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractLuaField(t *testing.T) {
	tests := []struct {
		content  string
		field    string
		expected string
	}{
		{`summary = "A test package"`, "summary", "A test package"},
		{`license = 'MIT'`, "license", "MIT"},
		{`homepage = "https://example.com"`, "homepage", "https://example.com"},
		{`no match here`, "summary", ""},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			result := extractLuaField(tt.content, tt.field)
			if result != tt.expected {
				t.Errorf("extractLuaField(%s, %s) = %s, want %s", tt.content, tt.field, result, tt.expected)
			}
		})
	}
}

func TestParsePubspec(t *testing.T) {
	tmpDir := t.TempDir()
	pubspecPath := filepath.Join(tmpDir, "pubspec.yaml")

	content := `name: my_package
version: 1.2.3
description: A test package for unit testing
homepage: https://example.com/my_package
`
	if err := os.WriteFile(pubspecPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	pkg := parsePubspec(pubspecPath)

	if pkg.Name != "my_package" {
		t.Errorf("expected Name 'my_package', got '%s'", pkg.Name)
	}
	if pkg.Version != "1.2.3" {
		t.Errorf("expected Version '1.2.3', got '%s'", pkg.Version)
	}
	if pkg.Summary != "A test package for unit testing" {
		t.Errorf("expected Summary 'A test package for unit testing', got '%s'", pkg.Summary)
	}
	if pkg.Homepage != "https://example.com/my_package" {
		t.Errorf("expected Homepage 'https://example.com/my_package', got '%s'", pkg.Homepage)
	}
}

func TestParseRDescription(t *testing.T) {
	tmpDir := t.TempDir()
	descPath := filepath.Join(tmpDir, "DESCRIPTION")

	content := `Package: ggplot2
Title: Create Elegant Data Visualisations Using the Grammar of Graphics
Version: 3.4.4
Author: Hadley Wickham
License: MIT + file LICENSE
URL: https://ggplot2.tidyverse.org
Description: A system for 'declaratively' creating graphics,
    based on "The Grammar of Graphics".
`
	if err := os.WriteFile(descPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	pkg := parseRDescription(descPath)

	if pkg.Name != "ggplot2" {
		t.Errorf("expected Name 'ggplot2', got '%s'", pkg.Name)
	}
	if pkg.Version != "3.4.4" {
		t.Errorf("expected Version '3.4.4', got '%s'", pkg.Version)
	}
	if pkg.Author != "Hadley Wickham" {
		t.Errorf("expected Author 'Hadley Wickham', got '%s'", pkg.Author)
	}
	if pkg.License != "MIT + file LICENSE" {
		t.Errorf("expected License 'MIT + file LICENSE', got '%s'", pkg.License)
	}
}

func TestParseJuliaProject(t *testing.T) {
	tmpDir := t.TempDir()
	projectPath := filepath.Join(tmpDir, "Project.toml")

	content := `name = "DataFrames"
uuid = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
version = "1.6.1"
`
	if err := os.WriteFile(projectPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	pkg := parseJuliaProject(projectPath)

	if pkg.Name != "DataFrames" {
		t.Errorf("expected Name 'DataFrames', got '%s'", pkg.Name)
	}
	if pkg.Version != "1.6.1" {
		t.Errorf("expected Version '1.6.1', got '%s'", pkg.Version)
	}
}

func TestParseCondaMetaJSON(t *testing.T) {
	tmpDir := t.TempDir()
	metaPath := filepath.Join(tmpDir, "numpy-1.25.0-py311h64a7726_0.json")

	content := `{
    "name": "numpy",
    "version": "1.25.0",
    "license": "BSD-3-Clause",
    "channel": "conda-forge",
    "build_number": 0
}`
	if err := os.WriteFile(metaPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	pkg := parseCondaMetaJSON(metaPath)

	if pkg.Name != "numpy" {
		t.Errorf("expected Name 'numpy', got '%s'", pkg.Name)
	}
	if pkg.Version != "1.25.0" {
		t.Errorf("expected Version '1.25.0', got '%s'", pkg.Version)
	}
	if pkg.License != "BSD-3-Clause" {
		t.Errorf("expected License 'BSD-3-Clause', got '%s'", pkg.License)
	}
}
