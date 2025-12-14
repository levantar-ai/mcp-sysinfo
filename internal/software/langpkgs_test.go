package software

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePythonPackageInfo(t *testing.T) {
	// Create a temporary directory with a mock METADATA file
	tmpDir := t.TempDir()
	distInfoDir := filepath.Join(tmpDir, "requests-2.31.0.dist-info")
	if err := os.Mkdir(distInfoDir, 0755); err != nil {
		t.Fatal(err)
	}

	metadataContent := `Metadata-Version: 2.1
Name: requests
Version: 2.31.0
Summary: Python HTTP for Humans.
Home-page: https://requests.readthedocs.io
Author: Kenneth Reitz
License: Apache 2.0

Requests is a simple HTTP library.
`
	if err := os.WriteFile(filepath.Join(distInfoDir, "METADATA"), []byte(metadataContent), 0644); err != nil {
		t.Fatal(err)
	}

	pkg := parsePythonPackageInfo(distInfoDir)

	if pkg.Name != "requests" {
		t.Errorf("expected Name 'requests', got '%s'", pkg.Name)
	}
	if pkg.Version != "2.31.0" {
		t.Errorf("expected Version '2.31.0', got '%s'", pkg.Version)
	}
	if pkg.Summary != "Python HTTP for Humans." {
		t.Errorf("expected Summary 'Python HTTP for Humans.', got '%s'", pkg.Summary)
	}
	if pkg.Author != "Kenneth Reitz" {
		t.Errorf("expected Author 'Kenneth Reitz', got '%s'", pkg.Author)
	}
	if pkg.License != "Apache 2.0" {
		t.Errorf("expected License 'Apache 2.0', got '%s'", pkg.License)
	}
	if pkg.Homepage != "https://requests.readthedocs.io" {
		t.Errorf("expected Homepage 'https://requests.readthedocs.io', got '%s'", pkg.Homepage)
	}
}

func TestParsePythonPKGInfo(t *testing.T) {
	// Test PKG-INFO format (egg)
	tmpDir := t.TempDir()
	eggInfoDir := filepath.Join(tmpDir, "flask-2.0.0.egg-info")
	if err := os.Mkdir(eggInfoDir, 0755); err != nil {
		t.Fatal(err)
	}

	pkgInfoContent := `Metadata-Version: 1.0
Name: Flask
Version: 2.0.0
Summary: A simple framework for building web applications.
Author: Armin Ronacher
`
	if err := os.WriteFile(filepath.Join(eggInfoDir, "PKG-INFO"), []byte(pkgInfoContent), 0644); err != nil {
		t.Fatal(err)
	}

	pkg := parsePythonPackageInfo(eggInfoDir)

	if pkg.Name != "Flask" {
		t.Errorf("expected Name 'Flask', got '%s'", pkg.Name)
	}
	if pkg.Version != "2.0.0" {
		t.Errorf("expected Version '2.0.0', got '%s'", pkg.Version)
	}
}

func TestParseNodePackageJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with string author
	packageJSON := `{
  "name": "express",
  "version": "4.18.2",
  "description": "Fast, unopinionated, minimalist web framework",
  "license": "MIT",
  "author": "TJ Holowaychuk",
  "homepage": "http://expressjs.com/"
}`
	packageJSONPath := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(packageJSONPath, []byte(packageJSON), 0644); err != nil {
		t.Fatal(err)
	}

	pkg := parseNodePackageJSON(packageJSONPath)

	if pkg.Name != "express" {
		t.Errorf("expected Name 'express', got '%s'", pkg.Name)
	}
	if pkg.Version != "4.18.2" {
		t.Errorf("expected Version '4.18.2', got '%s'", pkg.Version)
	}
	if pkg.Summary != "Fast, unopinionated, minimalist web framework" {
		t.Errorf("expected Summary mismatch, got '%s'", pkg.Summary)
	}
	if pkg.License != "MIT" {
		t.Errorf("expected License 'MIT', got '%s'", pkg.License)
	}
	if pkg.Author != "TJ Holowaychuk" {
		t.Errorf("expected Author 'TJ Holowaychuk', got '%s'", pkg.Author)
	}
}

func TestParseNodePackageJSONObjectAuthor(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with object author
	packageJSON := `{
  "name": "lodash",
  "version": "4.17.21",
  "description": "Lodash modular utilities.",
  "author": {"name": "John-David Dalton", "email": "john@example.com"}
}`
	packageJSONPath := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(packageJSONPath, []byte(packageJSON), 0644); err != nil {
		t.Fatal(err)
	}

	pkg := parseNodePackageJSON(packageJSONPath)

	if pkg.Name != "lodash" {
		t.Errorf("expected Name 'lodash', got '%s'", pkg.Name)
	}
	if pkg.Author != "John-David Dalton" {
		t.Errorf("expected Author 'John-David Dalton', got '%s'", pkg.Author)
	}
}

func TestDecodeGoModulePath(t *testing.T) {
	tests := []struct {
		encoded  string
		expected string
	}{
		{"github.com/gin-gonic/gin", "github.com/gin-gonic/gin"},
		{"github.com/!azure/azure-sdk-for-go", "github.com/Azure/azure-sdk-for-go"},
		{"github.com/!bishop!fox/smux", "github.com/BishopFox/smux"},
		{"golang.org/x/crypto", "golang.org/x/crypto"},
	}

	for _, tt := range tests {
		t.Run(tt.encoded, func(t *testing.T) {
			result := decodeGoModulePath(tt.encoded)
			if result != tt.expected {
				t.Errorf("decodeGoModulePath(%s) = %s, want %s", tt.encoded, result, tt.expected)
			}
		})
	}
}

func TestScanCargoRegistry(t *testing.T) {
	// Create a mock cargo registry structure
	tmpDir := t.TempDir()
	indexDir := filepath.Join(tmpDir, "github.com-1ecc6299db9ec823")
	if err := os.MkdirAll(indexDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create mock .crate files
	crateFiles := []string{
		"serde-1.0.188.crate",
		"tokio-1.32.0.crate",
		"clap-4.4.6.crate",
	}
	for _, cf := range crateFiles {
		path := filepath.Join(indexDir, cf)
		if err := os.WriteFile(path, []byte{}, 0644); err != nil {
			t.Fatal(err)
		}
	}

	packages := scanCargoRegistry(tmpDir)

	if len(packages) != 3 {
		t.Errorf("expected 3 packages, got %d", len(packages))
	}

	// Check that we found the expected packages
	found := make(map[string]bool)
	for _, pkg := range packages {
		found[pkg.Name+"@"+pkg.Version] = true
	}

	expected := []string{"serde@1.0.188", "tokio@1.32.0", "clap@4.4.6"}
	for _, exp := range expected {
		if !found[exp] {
			t.Errorf("expected to find package %s", exp)
		}
	}
}

func TestScanGemSpecs(t *testing.T) {
	// Create a mock gem specifications directory
	tmpDir := t.TempDir()

	// Create mock .gemspec files
	gemspecs := map[string]string{
		"rails-7.0.0.gemspec": `Gem::Specification.new do |s|
  s.name = "rails"
  s.version = "7.0.0"
  s.summary = "Full-stack web application framework."
  s.license = "MIT"
end`,
		"bundler-2.4.0.gemspec": `Gem::Specification.new do |s|
  s.name = "bundler"
  s.version = "2.4.0"
  s.summary = "The best way to manage your application's dependencies"
  s.homepage = "https://bundler.io"
end`,
	}

	for name, content := range gemspecs {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	packages := scanGemSpecs(tmpDir)

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	// Check that we found the expected packages
	found := make(map[string]string)
	for _, pkg := range packages {
		found[pkg.Name] = pkg.Version
	}

	if found["rails"] != "7.0.0" {
		t.Errorf("expected rails version 7.0.0, got %s", found["rails"])
	}
	if found["bundler"] != "2.4.0" {
		t.Errorf("expected bundler version 2.4.0, got %s", found["bundler"])
	}
}

func TestExtractRubyString(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{`s.summary = "A test summary"`, "A test summary"},
		{`s.license = 'MIT'`, "MIT"},
		{`  s.homepage = "https://example.com"  `, "https://example.com"},
		{`s.author = "John Doe"`, "John Doe"},
		{`no quotes here`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			result := extractRubyString(tt.line)
			if result != tt.expected {
				t.Errorf("extractRubyString(%s) = %s, want %s", tt.line, result, tt.expected)
			}
		})
	}
}

func TestScanPythonSitePackages(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mock dist-info directories
	distInfos := []struct {
		name    string
		content string
	}{
		{
			"requests-2.31.0.dist-info",
			"Name: requests\nVersion: 2.31.0\nSummary: HTTP library\n",
		},
		{
			"urllib3-2.0.0.dist-info",
			"Name: urllib3\nVersion: 2.0.0\nSummary: HTTP client\n",
		},
	}

	for _, di := range distInfos {
		dir := filepath.Join(tmpDir, di.name)
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "METADATA"), []byte(di.content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Also create a regular directory that should be ignored
	if err := os.Mkdir(filepath.Join(tmpDir, "some_package"), 0755); err != nil {
		t.Fatal(err)
	}

	packages, err := scanPythonSitePackages(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	found := make(map[string]bool)
	for _, pkg := range packages {
		found[pkg.Name] = true
	}

	if !found["requests"] {
		t.Error("expected to find 'requests' package")
	}
	if !found["urllib3"] {
		t.Error("expected to find 'urllib3' package")
	}
}

func TestScanNodeModules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create mock package directories
	packages := []struct {
		name    string
		version string
	}{
		{"express", "4.18.2"},
		{"lodash", "4.17.21"},
	}

	for _, pkg := range packages {
		pkgDir := filepath.Join(tmpDir, pkg.name)
		if err := os.MkdirAll(pkgDir, 0755); err != nil {
			t.Fatal(err)
		}
		packageJSON := `{"name": "` + pkg.name + `", "version": "` + pkg.version + `"}`
		if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(packageJSON), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create a scoped package
	scopedDir := filepath.Join(tmpDir, "@types", "node")
	if err := os.MkdirAll(scopedDir, 0755); err != nil {
		t.Fatal(err)
	}
	scopedJSON := `{"name": "@types/node", "version": "20.0.0"}`
	if err := os.WriteFile(filepath.Join(scopedDir, "package.json"), []byte(scopedJSON), 0644); err != nil {
		t.Fatal(err)
	}

	result, err := scanNodeModules(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 packages, got %d", len(result))
	}

	found := make(map[string]string)
	for _, pkg := range result {
		found[pkg.Name] = pkg.Version
	}

	if found["express"] != "4.18.2" {
		t.Errorf("expected express version 4.18.2, got %s", found["express"])
	}
	if found["@types/node"] != "20.0.0" {
		t.Errorf("expected @types/node version 20.0.0, got %s", found["@types/node"])
	}
}
