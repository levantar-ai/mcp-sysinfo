// Package software provides software inventory and SBOM functionality.
package software

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// GetPythonPackages returns installed Python packages by scanning site-packages.
func (c *Collector) GetPythonPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "python",
		PackageManager: "pip",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	// Find Python site-packages directories
	sitePackagesDirs := findPythonSitePackages()
	if len(sitePackagesDirs) == 0 {
		return result, nil
	}

	seen := make(map[string]bool)
	for _, dir := range sitePackagesDirs {
		packages, err := scanPythonSitePackages(dir)
		if err != nil {
			continue
		}
		for _, pkg := range packages {
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				result.Packages = append(result.Packages, pkg)
			}
		}
	}

	result.Count = len(result.Packages)
	if len(sitePackagesDirs) > 0 {
		result.Location = strings.Join(sitePackagesDirs, ", ")
	}

	return result, nil
}

func findPythonSitePackages() []string {
	var dirs []string
	home, _ := os.UserHomeDir()

	// Common Python site-packages locations
	patterns := []string{
		"/usr/lib/python*/site-packages",
		"/usr/lib/python*/dist-packages",
		"/usr/local/lib/python*/site-packages",
		"/usr/local/lib/python*/dist-packages",
	}

	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, ".local/lib/python*/site-packages"),
			filepath.Join(home, ".pyenv/versions/*/lib/python*/site-packages"),
		)
	}

	// macOS specific
	if runtime.GOOS == "darwin" {
		patterns = append(patterns,
			"/Library/Python/*/site-packages",
			"/opt/homebrew/lib/python*/site-packages",
			"/usr/local/Cellar/python*/*/Frameworks/Python.framework/Versions/*/lib/python*/site-packages",
		)
	}

	// Windows specific
	if runtime.GOOS == "windows" {
		if home != "" {
			patterns = append(patterns,
				filepath.Join(home, "AppData/Local/Programs/Python/Python*/Lib/site-packages"),
				filepath.Join(home, "AppData/Roaming/Python/Python*/site-packages"),
			)
		}
		patterns = append(patterns,
			"C:/Python*/Lib/site-packages",
			"C:/Program Files/Python*/Lib/site-packages",
		)
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err == nil {
			dirs = append(dirs, matches...)
		}
	}

	return dirs
}

func scanPythonSitePackages(sitePackagesDir string) ([]types.LanguagePackage, error) {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(sitePackagesDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Look for .dist-info or .egg-info directories
		name := entry.Name()
		if strings.HasSuffix(name, ".dist-info") || strings.HasSuffix(name, ".egg-info") {
			pkg := parsePythonPackageInfo(filepath.Join(sitePackagesDir, name))
			if pkg.Name != "" {
				pkg.Location = sitePackagesDir
				packages = append(packages, pkg)
			}
		}
	}

	return packages, nil
}

func parsePythonPackageInfo(infoDir string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	// Try METADATA file first (wheel format)
	metadataPath := filepath.Join(infoDir, "METADATA")
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		// Try PKG-INFO (egg format)
		metadataPath = filepath.Join(infoDir, "PKG-INFO")
	}

	file, err := os.Open(metadataPath) // #nosec G304 -- reading package metadata from site-packages
	if err != nil {
		return pkg
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // End of headers
		}

		if strings.HasPrefix(line, "Name: ") {
			pkg.Name = strings.TrimPrefix(line, "Name: ")
		} else if strings.HasPrefix(line, "Version: ") {
			pkg.Version = strings.TrimPrefix(line, "Version: ")
		} else if strings.HasPrefix(line, "Summary: ") {
			pkg.Summary = strings.TrimPrefix(line, "Summary: ")
		} else if strings.HasPrefix(line, "Author: ") {
			pkg.Author = strings.TrimPrefix(line, "Author: ")
		} else if strings.HasPrefix(line, "License: ") {
			pkg.License = strings.TrimPrefix(line, "License: ")
		} else if strings.HasPrefix(line, "Home-page: ") {
			pkg.Homepage = strings.TrimPrefix(line, "Home-page: ")
		}
	}

	return pkg
}

// GetNodePackages returns globally installed Node.js packages.
func (c *Collector) GetNodePackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "nodejs",
		PackageManager: "npm",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	// Find global node_modules directories
	nodeModulesDirs := findGlobalNodeModules()
	if len(nodeModulesDirs) == 0 {
		return result, nil
	}

	seen := make(map[string]bool)
	for _, dir := range nodeModulesDirs {
		packages, err := scanNodeModules(dir)
		if err != nil {
			continue
		}
		for _, pkg := range packages {
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				result.Packages = append(result.Packages, pkg)
			}
		}
	}

	result.Count = len(result.Packages)
	if len(nodeModulesDirs) > 0 {
		result.Location = strings.Join(nodeModulesDirs, ", ")
	}

	return result, nil
}

func findGlobalNodeModules() []string {
	var dirs []string
	home, _ := os.UserHomeDir()

	// Common global node_modules locations
	if runtime.GOOS == "windows" {
		if home != "" {
			dirs = append(dirs, filepath.Join(home, "AppData/Roaming/npm/node_modules"))
		}
		dirs = append(dirs, "C:/Program Files/nodejs/node_modules")
	} else {
		dirs = append(dirs,
			"/usr/lib/node_modules",
			"/usr/local/lib/node_modules",
		)
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, ".npm-global/lib/node_modules"),
				filepath.Join(home, ".nvm/versions/node"),
			)
		}
		if runtime.GOOS == "darwin" {
			dirs = append(dirs, "/opt/homebrew/lib/node_modules")
		}
	}

	// Filter to existing directories
	var existing []string
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			existing = append(existing, dir)
		}
	}

	return existing
}

func scanNodeModules(nodeModulesDir string) ([]types.LanguagePackage, error) {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(nodeModulesDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Skip hidden directories and special directories
		if strings.HasPrefix(name, ".") || name == "node_modules" {
			continue
		}

		// Handle scoped packages (@org/pkg)
		if strings.HasPrefix(name, "@") {
			scopedEntries, err := os.ReadDir(filepath.Join(nodeModulesDir, name))
			if err != nil {
				continue
			}
			for _, scopedEntry := range scopedEntries {
				if scopedEntry.IsDir() {
					pkgName := name + "/" + scopedEntry.Name()
					pkg := parseNodePackageJSON(filepath.Join(nodeModulesDir, name, scopedEntry.Name(), "package.json"))
					if pkg.Name == "" {
						pkg.Name = pkgName
					}
					pkg.Location = nodeModulesDir
					if pkg.Version != "" {
						packages = append(packages, pkg)
					}
				}
			}
		} else {
			pkg := parseNodePackageJSON(filepath.Join(nodeModulesDir, name, "package.json"))
			if pkg.Name == "" {
				pkg.Name = name
			}
			pkg.Location = nodeModulesDir
			if pkg.Version != "" {
				packages = append(packages, pkg)
			}
		}
	}

	return packages, nil
}

func parseNodePackageJSON(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading package.json from node_modules
	if err != nil {
		return pkg
	}

	var packageJSON struct {
		Name        string      `json:"name"`
		Version     string      `json:"version"`
		Description string      `json:"description"`
		License     string      `json:"license"`
		Author      interface{} `json:"author"` // Can be string or object
		Homepage    string      `json:"homepage"`
	}

	if err := json.Unmarshal(data, &packageJSON); err != nil {
		return pkg
	}

	pkg.Name = packageJSON.Name
	pkg.Version = packageJSON.Version
	pkg.Summary = packageJSON.Description
	pkg.License = packageJSON.License
	pkg.Homepage = packageJSON.Homepage

	// Handle author field (can be string or object)
	switch v := packageJSON.Author.(type) {
	case string:
		pkg.Author = v
	case map[string]interface{}:
		if name, ok := v["name"].(string); ok {
			pkg.Author = name
		}
	}

	return pkg
}

// GetGoModules returns Go modules from go.sum files in common locations.
func (c *Collector) GetGoModules() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "go",
		PackageManager: "go",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Scan Go module cache
	modCacheDir := filepath.Join(home, "go/pkg/mod/cache/download")
	if info, err := os.Stat(modCacheDir); err == nil && info.IsDir() {
		packages := scanGoModCache(modCacheDir)
		result.Packages = packages
		result.Location = modCacheDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanGoModCache(cacheDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage
	seen := make(map[string]bool)

	// Walk the cache directory looking for .info files
	_ = filepath.WalkDir(cacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if d.IsDir() {
			return nil
		}

		// Look for .info files which indicate downloaded modules
		if strings.HasSuffix(path, ".info") {
			// Parse module path and version from directory structure
			rel, _ := filepath.Rel(cacheDir, path)
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) >= 2 {
				// Join all but last two parts for module path
				version := strings.TrimSuffix(parts[len(parts)-1], ".info")
				modPath := strings.Join(parts[:len(parts)-2], "/")

				// Decode module path (capital letters are encoded as !)
				modPath = decodeGoModulePath(modPath)
				version = strings.TrimPrefix(version, "v")

				key := modPath + "@" + version
				if !seen[key] && modPath != "" && version != "" {
					seen[key] = true
					packages = append(packages, types.LanguagePackage{
						Name:    modPath,
						Version: version,
					})
				}
			}
		}
		return nil
	})

	return packages
}

func decodeGoModulePath(encoded string) string {
	// Go module paths encode capital letters as !lowercase
	var result strings.Builder
	i := 0
	for i < len(encoded) {
		if encoded[i] == '!' && i+1 < len(encoded) {
			result.WriteByte(encoded[i+1] - 'a' + 'A')
			i += 2
		} else {
			result.WriteByte(encoded[i])
			i++
		}
	}
	return result.String()
}

// GetRustPackages returns Rust crates from Cargo registry cache.
func (c *Collector) GetRustPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "rust",
		PackageManager: "cargo",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Cargo registry cache location
	registryDir := filepath.Join(home, ".cargo/registry/cache")
	if info, err := os.Stat(registryDir); err == nil && info.IsDir() {
		packages := scanCargoRegistry(registryDir)
		result.Packages = packages
		result.Location = registryDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanCargoRegistry(registryDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage
	seen := make(map[string]bool)

	// Walk registry directories (e.g., github.com-xxx)
	entries, err := os.ReadDir(registryDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		indexDir := filepath.Join(registryDir, entry.Name())
		crateFiles, err := os.ReadDir(indexDir)
		if err != nil {
			continue
		}

		for _, crateFile := range crateFiles {
			name := crateFile.Name()
			// Crate files are named: cratename-version.crate
			if strings.HasSuffix(name, ".crate") {
				name = strings.TrimSuffix(name, ".crate")
				lastDash := strings.LastIndex(name, "-")
				if lastDash > 0 {
					crateName := name[:lastDash]
					version := name[lastDash+1:]

					key := crateName + "@" + version
					if !seen[key] {
						seen[key] = true
						packages = append(packages, types.LanguagePackage{
							Name:    crateName,
							Version: version,
						})
					}
				}
			}
		}
	}

	return packages
}

// GetRubyGems returns installed Ruby gems.
func (c *Collector) GetRubyGems() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "ruby",
		PackageManager: "gem",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	// Find gem specification directories
	gemSpecDirs := findRubyGemSpecs()
	if len(gemSpecDirs) == 0 {
		return result, nil
	}

	seen := make(map[string]bool)
	for _, dir := range gemSpecDirs {
		packages := scanGemSpecs(dir)
		for _, pkg := range packages {
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				result.Packages = append(result.Packages, pkg)
			}
		}
	}

	result.Count = len(result.Packages)
	if len(gemSpecDirs) > 0 {
		result.Location = strings.Join(gemSpecDirs, ", ")
	}

	return result, nil
}

func findRubyGemSpecs() []string {
	var dirs []string
	home, _ := os.UserHomeDir()

	// Common gem specification locations
	patterns := []string{
		"/var/lib/gems/*/specifications",
		"/usr/lib/ruby/gems/*/specifications",
		"/usr/local/lib/ruby/gems/*/specifications",
	}

	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, ".gem/ruby/*/specifications"),
			filepath.Join(home, ".rbenv/versions/*/lib/ruby/gems/*/specifications"),
			filepath.Join(home, ".rvm/gems/*/specifications"),
		)
	}

	if runtime.GOOS == "darwin" {
		patterns = append(patterns,
			"/opt/homebrew/lib/ruby/gems/*/specifications",
			"/Library/Ruby/Gems/*/specifications",
		)
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err == nil {
			dirs = append(dirs, matches...)
		}
	}

	return dirs
}

func scanGemSpecs(specsDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(specsDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasSuffix(name, ".gemspec") {
			name = strings.TrimSuffix(name, ".gemspec")
			// Gemspec files are named: gemname-version.gemspec
			lastDash := strings.LastIndex(name, "-")
			if lastDash > 0 {
				gemName := name[:lastDash]
				version := name[lastDash+1:]

				pkg := types.LanguagePackage{
					Name:     gemName,
					Version:  version,
					Location: specsDir,
				}

				// Try to parse more details from the gemspec file
				parseGemspec(filepath.Join(specsDir, entry.Name()), &pkg)
				packages = append(packages, pkg)
			}
		}
	}

	return packages
}

func parseGemspec(path string, pkg *types.LanguagePackage) {
	data, err := os.ReadFile(path) // #nosec G304 -- reading gemspec from gem specifications dir
	if err != nil {
		return
	}

	content := string(data)

	// Simple extraction of common fields from gemspec
	// Gemspec is Ruby code, so we just look for common patterns
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.Contains(line, ".summary") && strings.Contains(line, "=") {
			pkg.Summary = extractRubyString(line)
		} else if strings.Contains(line, ".license") && strings.Contains(line, "=") {
			pkg.License = extractRubyString(line)
		} else if strings.Contains(line, ".homepage") && strings.Contains(line, "=") {
			pkg.Homepage = extractRubyString(line)
		} else if strings.Contains(line, ".author") && strings.Contains(line, "=") {
			pkg.Author = extractRubyString(line)
		}
	}
}

func extractRubyString(line string) string {
	// Extract string value from patterns like: s.summary = "description"
	// or s.summary = 'description'
	start := strings.Index(line, "\"")
	if start == -1 {
		start = strings.Index(line, "'")
	}
	if start == -1 {
		return ""
	}

	quote := line[start]
	end := strings.LastIndex(line, string(quote))
	if end > start {
		return line[start+1 : end]
	}
	return ""
}

// GetMavenPackages returns Java/Maven packages from ~/.m2/repository.
func (c *Collector) GetMavenPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "java",
		PackageManager: "maven",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Maven repository location
	m2RepoDir := filepath.Join(home, ".m2", "repository")
	if info, err := os.Stat(m2RepoDir); err == nil && info.IsDir() {
		packages := scanMavenRepository(m2RepoDir)
		result.Packages = packages
		result.Location = m2RepoDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanMavenRepository(repoDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage
	seen := make(map[string]bool)

	// Walk the repository looking for .pom files
	_ = filepath.WalkDir(repoDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		if d.IsDir() {
			return nil
		}

		// Look for .pom files which indicate downloaded artifacts
		if strings.HasSuffix(path, ".pom") {
			pkg := parseMavenPOM(repoDir, path)
			if pkg.Name != "" && pkg.Version != "" {
				key := pkg.Name + "@" + pkg.Version
				if !seen[key] {
					seen[key] = true
					packages = append(packages, pkg)
				}
			}
		}
		return nil
	})

	return packages
}

func parseMavenPOM(repoDir, pomPath string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	// Parse path to get groupId/artifactId/version
	rel, err := filepath.Rel(repoDir, pomPath)
	if err != nil {
		return pkg
	}

	// Path format: com/example/artifact/1.0.0/artifact-1.0.0.pom
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) < 4 {
		return pkg
	}

	// Version is second to last, artifactId is third to last
	version := parts[len(parts)-2]
	artifactId := parts[len(parts)-3]
	groupId := strings.Join(parts[:len(parts)-3], ".")

	pkg.Name = groupId + ":" + artifactId
	pkg.Version = version
	pkg.Location = filepath.Dir(pomPath)

	// Try to read basic info from POM file
	data, err := os.ReadFile(pomPath) // #nosec G304 -- reading pom from .m2/repository
	if err != nil {
		return pkg
	}

	content := string(data)

	// Extract description if available
	if desc := extractXMLTag(content, "description"); desc != "" {
		pkg.Summary = desc
	}
	if license := extractXMLTag(content, "name"); license != "" && pkg.Summary == "" {
		pkg.Summary = license
	}
	if url := extractXMLTag(content, "url"); url != "" {
		pkg.Homepage = url
	}

	return pkg
}

func extractXMLTag(content, tag string) string {
	start := strings.Index(content, "<"+tag+">")
	if start == -1 {
		return ""
	}
	start += len(tag) + 2
	end := strings.Index(content[start:], "</"+tag+">")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(content[start : start+end])
}

// GetPHPPackages returns PHP packages from composer.lock files.
func (c *Collector) GetPHPPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "php",
		PackageManager: "composer",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Check global composer directory
	composerDirs := []string{
		filepath.Join(home, ".composer"),
		filepath.Join(home, ".config", "composer"),
	}

	// Also check common Composer cache location
	if runtime.GOOS == "windows" {
		composerDirs = append(composerDirs, filepath.Join(home, "AppData", "Roaming", "Composer"))
	}

	seen := make(map[string]bool)
	var locations []string

	for _, dir := range composerDirs {
		lockFile := filepath.Join(dir, "composer.lock")
		if _, err := os.Stat(lockFile); err == nil {
			packages := parseComposerLock(lockFile)
			for _, pkg := range packages {
				key := pkg.Name + "@" + pkg.Version
				if !seen[key] {
					seen[key] = true
					result.Packages = append(result.Packages, pkg)
				}
			}
			locations = append(locations, dir)
		}

		// Also check vendor directory for installed packages
		vendorDir := filepath.Join(dir, "vendor")
		if info, err := os.Stat(vendorDir); err == nil && info.IsDir() {
			packages := scanComposerVendor(vendorDir)
			for _, pkg := range packages {
				key := pkg.Name + "@" + pkg.Version
				if !seen[key] {
					seen[key] = true
					result.Packages = append(result.Packages, pkg)
				}
			}
		}
	}

	result.Count = len(result.Packages)
	if len(locations) > 0 {
		result.Location = strings.Join(locations, ", ")
	}
	return result, nil
}

func parseComposerLock(lockFile string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	data, err := os.ReadFile(lockFile) // #nosec G304 -- reading composer.lock
	if err != nil {
		return packages
	}

	var lock struct {
		Packages    []composerPackage `json:"packages"`
		PackagesDev []composerPackage `json:"packages-dev"`
	}

	if err := json.Unmarshal(data, &lock); err != nil {
		return packages
	}

	for _, p := range lock.Packages {
		pkg := types.LanguagePackage{
			Name:     p.Name,
			Version:  p.Version,
			License:  strings.Join(p.License, ", "),
			Summary:  p.Description,
			Homepage: p.Homepage,
		}
		packages = append(packages, pkg)
	}

	for _, p := range lock.PackagesDev {
		pkg := types.LanguagePackage{
			Name:     p.Name,
			Version:  p.Version,
			License:  strings.Join(p.License, ", "),
			Summary:  p.Description,
			Homepage: p.Homepage,
			DevDep:   true,
		}
		packages = append(packages, pkg)
	}

	return packages
}

type composerPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	License     []string `json:"license"`
	Homepage    string   `json:"homepage"`
}

func scanComposerVendor(vendorDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(vendorDir)
	if err != nil {
		return packages
	}

	for _, vendor := range entries {
		if !vendor.IsDir() || strings.HasPrefix(vendor.Name(), ".") {
			continue
		}

		vendorPath := filepath.Join(vendorDir, vendor.Name())
		pkgEntries, err := os.ReadDir(vendorPath)
		if err != nil {
			continue
		}

		for _, pkgEntry := range pkgEntries {
			if !pkgEntry.IsDir() {
				continue
			}

			composerJSON := filepath.Join(vendorPath, pkgEntry.Name(), "composer.json")
			if pkg := parseComposerJSON(composerJSON); pkg.Name != "" {
				pkg.Location = filepath.Join(vendorPath, pkgEntry.Name())
				packages = append(packages, pkg)
			}
		}
	}

	return packages
}

func parseComposerJSON(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading composer.json from vendor
	if err != nil {
		return pkg
	}

	var composer struct {
		Name        string   `json:"name"`
		Version     string   `json:"version"`
		Description string   `json:"description"`
		License     []string `json:"license"`
		Homepage    string   `json:"homepage"`
	}

	if err := json.Unmarshal(data, &composer); err != nil {
		return pkg
	}

	pkg.Name = composer.Name
	pkg.Version = composer.Version
	pkg.Summary = composer.Description
	pkg.License = strings.Join(composer.License, ", ")
	pkg.Homepage = composer.Homepage

	return pkg
}

// GetDotnetPackages returns .NET/NuGet packages from the global package cache.
func (c *Collector) GetDotnetPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "dotnet",
		PackageManager: "nuget",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// NuGet global packages folder locations
	var nugetDirs []string
	if runtime.GOOS == "windows" {
		nugetDirs = []string{
			filepath.Join(home, ".nuget", "packages"),
			filepath.Join(os.Getenv("ProgramData"), "NuGet", "Packages"),
		}
	} else {
		nugetDirs = []string{
			filepath.Join(home, ".nuget", "packages"),
		}
	}

	seen := make(map[string]bool)
	var locations []string

	for _, dir := range nugetDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			packages := scanNuGetPackages(dir)
			for _, pkg := range packages {
				key := pkg.Name + "@" + pkg.Version
				if !seen[key] {
					seen[key] = true
					result.Packages = append(result.Packages, pkg)
				}
			}
			locations = append(locations, dir)
		}
	}

	result.Count = len(result.Packages)
	if len(locations) > 0 {
		result.Location = strings.Join(locations, ", ")
	}
	return result, nil
}

func scanNuGetPackages(packagesDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(packagesDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		pkgName := entry.Name()
		pkgPath := filepath.Join(packagesDir, pkgName)

		// List versions
		versionEntries, err := os.ReadDir(pkgPath)
		if err != nil {
			continue
		}

		for _, versionEntry := range versionEntries {
			if !versionEntry.IsDir() {
				continue
			}

			version := versionEntry.Name()
			nuspecPath := filepath.Join(pkgPath, version, pkgName+".nuspec")

			pkg := types.LanguagePackage{
				Name:     pkgName,
				Version:  version,
				Location: filepath.Join(pkgPath, version),
			}

			// Try to parse nuspec for more details
			if nuspecInfo := parseNuSpec(nuspecPath); nuspecInfo.Name != "" {
				pkg.Summary = nuspecInfo.Summary
				pkg.License = nuspecInfo.License
				pkg.Homepage = nuspecInfo.Homepage
				pkg.Author = nuspecInfo.Author
			}

			packages = append(packages, pkg)
		}
	}

	return packages
}

func parseNuSpec(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading nuspec from nuget packages
	if err != nil {
		return pkg
	}

	content := string(data)

	pkg.Name = extractXMLTag(content, "id")
	pkg.Version = extractXMLTag(content, "version")
	pkg.Summary = extractXMLTag(content, "description")
	pkg.Author = extractXMLTag(content, "authors")
	pkg.Homepage = extractXMLTag(content, "projectUrl")
	pkg.License = extractXMLTag(content, "license")
	if pkg.License == "" {
		pkg.License = extractXMLTag(content, "licenseUrl")
	}

	return pkg
}
