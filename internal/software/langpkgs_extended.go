// Package software provides software inventory and SBOM functionality.
// This file implements Phase 1.10: Extended Language Ecosystems.
package software

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// ============================================================================
// Extended Global Package Managers (11 new queries)
// ============================================================================

// GetPerlPackages returns installed Perl modules from CPAN/cpanm.
func (c *Collector) GetPerlPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "perl",
		PackageManager: "cpan",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	// Find Perl library directories
	perlLibDirs := findPerlLibDirs()
	if len(perlLibDirs) == 0 {
		return result, nil
	}

	seen := make(map[string]bool)
	for _, dir := range perlLibDirs {
		packages := scanPerlModules(dir)
		for _, pkg := range packages {
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				result.Packages = append(result.Packages, pkg)
			}
		}
	}

	result.Count = len(result.Packages)
	if len(perlLibDirs) > 0 {
		result.Location = strings.Join(perlLibDirs, ", ")
	}

	return result, nil
}

func findPerlLibDirs() []string {
	var dirs []string
	home, _ := os.UserHomeDir()

	patterns := []string{
		"/usr/share/perl5",
		"/usr/lib/perl5",
		"/usr/local/lib/perl5",
		"/usr/local/share/perl5",
	}

	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, "perl5/lib/perl5"),
			filepath.Join(home, ".cpanm"),
		)
	}

	if runtime.GOOS == "darwin" {
		patterns = append(patterns,
			"/opt/homebrew/lib/perl5",
			"/opt/homebrew/Cellar/perl/*/lib/perl5",
		)
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err == nil {
			for _, m := range matches {
				if info, err := os.Stat(m); err == nil && info.IsDir() {
					dirs = append(dirs, m)
				}
			}
		}
	}

	return dirs
}

func scanPerlModules(libDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	// Look for .packlist files which indicate installed modules
	_ = filepath.WalkDir(libDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.Name() == ".packlist" {
			// Extract module name from path
			rel, _ := filepath.Rel(libDir, filepath.Dir(path))
			moduleName := strings.ReplaceAll(rel, string(filepath.Separator), "::")
			moduleName = strings.TrimPrefix(moduleName, "auto::")

			if moduleName != "" && moduleName != "." {
				pkg := types.LanguagePackage{
					Name:     moduleName,
					Location: filepath.Dir(path),
				}
				// Try to get version from module
				pkg.Version = getPerlModuleVersion(libDir, moduleName)
				packages = append(packages, pkg)
			}
		}
		return nil
	})

	return packages
}

func getPerlModuleVersion(libDir, moduleName string) string {
	// Convert module name to file path
	modulePath := strings.ReplaceAll(moduleName, "::", string(filepath.Separator)) + ".pm"
	fullPath := filepath.Join(libDir, modulePath)

	data, err := os.ReadFile(fullPath) // #nosec G304 -- reading perl module
	if err != nil {
		return ""
	}

	// Look for VERSION or $VERSION in the file
	versionRe := regexp.MustCompile(`(?:our\s+)?\$VERSION\s*=\s*['"]?([0-9.]+)['"]?`)
	matches := versionRe.FindSubmatch(data)
	if len(matches) > 1 {
		return string(matches[1])
	}

	return ""
}

// GetLuaPackages returns installed LuaRocks packages.
func (c *Collector) GetLuaPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "lua",
		PackageManager: "luarocks",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	luarocksDirs := findLuaRocksDirs()
	if len(luarocksDirs) == 0 {
		return result, nil
	}

	seen := make(map[string]bool)
	for _, dir := range luarocksDirs {
		packages := scanLuaRocks(dir)
		for _, pkg := range packages {
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				result.Packages = append(result.Packages, pkg)
			}
		}
	}

	result.Count = len(result.Packages)
	if len(luarocksDirs) > 0 {
		result.Location = strings.Join(luarocksDirs, ", ")
	}

	return result, nil
}

func findLuaRocksDirs() []string {
	var dirs []string
	home, _ := os.UserHomeDir()

	patterns := []string{
		"/usr/local/lib/luarocks/rocks-*",
		"/usr/lib/luarocks/rocks-*",
		"/usr/share/lua/*/",
	}

	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, ".luarocks/lib/luarocks/rocks-*"),
		)
	}

	if runtime.GOOS == "darwin" {
		patterns = append(patterns,
			"/opt/homebrew/lib/luarocks/rocks-*",
		)
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err == nil {
			for _, m := range matches {
				if info, err := os.Stat(m); err == nil && info.IsDir() {
					dirs = append(dirs, m)
				}
			}
		}
	}

	return dirs
}

func scanLuaRocks(rocksDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(rocksDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		pkgName := entry.Name()
		pkgPath := filepath.Join(rocksDir, pkgName)

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
			pkg := types.LanguagePackage{
				Name:     pkgName,
				Version:  version,
				Location: filepath.Join(pkgPath, version),
			}

			// Try to read rockspec for more details
			rockspecPattern := filepath.Join(pkgPath, version, "*.rockspec")
			if rockspecs, _ := filepath.Glob(rockspecPattern); len(rockspecs) > 0 {
				parseLuaRockspec(rockspecs[0], &pkg)
			}

			packages = append(packages, pkg)
		}
	}

	return packages
}

func parseLuaRockspec(path string, pkg *types.LanguagePackage) {
	data, err := os.ReadFile(path) // #nosec G304 -- reading rockspec file
	if err != nil {
		return
	}

	content := string(data)

	// Extract fields from Lua table format
	if desc := extractLuaField(content, "summary"); desc != "" {
		pkg.Summary = desc
	}
	if license := extractLuaField(content, "license"); license != "" {
		pkg.License = license
	}
	if homepage := extractLuaField(content, "homepage"); homepage != "" {
		pkg.Homepage = homepage
	}
}

func extractLuaField(content, field string) string {
	// Match patterns like: field = "value" or field = 'value'
	pattern := regexp.MustCompile(field + `\s*=\s*["']([^"']+)["']`)
	matches := pattern.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// GetHaskellPackages returns installed Haskell packages from Cabal/Stack.
func (c *Collector) GetHaskellPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "haskell",
		PackageManager: "cabal",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Check Cabal store
	cabalStoreDir := filepath.Join(home, ".cabal/store")
	if info, err := os.Stat(cabalStoreDir); err == nil && info.IsDir() {
		packages := scanCabalStore(cabalStoreDir)
		result.Packages = append(result.Packages, packages...)
		result.Location = cabalStoreDir
	}

	// Also check Stack's global packages
	stackDir := filepath.Join(home, ".stack/snapshots")
	if info, err := os.Stat(stackDir); err == nil && info.IsDir() {
		packages := scanStackSnapshots(stackDir)
		result.Packages = append(result.Packages, packages...)
		if result.Location != "" {
			result.Location += ", " + stackDir
		} else {
			result.Location = stackDir
		}
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanCabalStore(storeDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage
	seen := make(map[string]bool)

	// Walk store looking for package directories
	entries, err := os.ReadDir(storeDir)
	if err != nil {
		return packages
	}

	for _, ghcEntry := range entries {
		if !ghcEntry.IsDir() {
			continue
		}

		ghcDir := filepath.Join(storeDir, ghcEntry.Name())
		pkgEntries, err := os.ReadDir(ghcDir)
		if err != nil {
			continue
		}

		for _, pkgEntry := range pkgEntries {
			if !pkgEntry.IsDir() {
				continue
			}

			// Package directories are named: pkgname-version-hash
			name := pkgEntry.Name()
			parts := strings.Split(name, "-")
			if len(parts) >= 2 {
				// Try to separate name and version
				pkgName, version := parseHaskellPkgName(name)
				if pkgName != "" {
					key := pkgName + "@" + version
					if !seen[key] {
						seen[key] = true
						packages = append(packages, types.LanguagePackage{
							Name:     pkgName,
							Version:  version,
							Location: filepath.Join(ghcDir, name),
						})
					}
				}
			}
		}
	}

	return packages
}

func parseHaskellPkgName(fullName string) (string, string) {
	// Format: pkgname-version-hash or pkgname-version
	parts := strings.Split(fullName, "-")
	if len(parts) < 2 {
		return "", ""
	}

	// Find the version (starts with digit)
	for i := len(parts) - 1; i > 0; i-- {
		if len(parts[i]) > 0 && parts[i][0] >= '0' && parts[i][0] <= '9' {
			// Check if it looks like a hash (long hex string)
			if len(parts[i]) > 20 && isHex(parts[i]) {
				continue
			}
			return strings.Join(parts[:i], "-"), parts[i]
		}
	}

	return strings.Join(parts[:len(parts)-1], "-"), parts[len(parts)-1]
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func scanStackSnapshots(stackDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage
	seen := make(map[string]bool)

	// Walk snapshots looking for installed packages
	_ = filepath.WalkDir(stackDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Look for package.conf files
		if strings.HasSuffix(path, ".conf") && strings.Contains(path, "pkgdb") {
			pkg := parseStackPkgConf(path)
			if pkg.Name != "" {
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

func parseStackPkgConf(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading stack package conf
	if err != nil {
		return pkg
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "name:") {
			pkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		} else if strings.HasPrefix(line, "version:") {
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "version:"))
		} else if strings.HasPrefix(line, "license:") {
			pkg.License = strings.TrimSpace(strings.TrimPrefix(line, "license:"))
		} else if strings.HasPrefix(line, "synopsis:") {
			pkg.Summary = strings.TrimSpace(strings.TrimPrefix(line, "synopsis:"))
		} else if strings.HasPrefix(line, "homepage:") {
			pkg.Homepage = strings.TrimSpace(strings.TrimPrefix(line, "homepage:"))
		}
	}

	return pkg
}

// GetSwiftPackages returns Swift Package Manager packages.
func (c *Collector) GetSwiftPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "swift",
		PackageManager: "spm",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	// Swift packages are stored in ~/.swiftpm/cache (macOS/Linux only)
	if runtime.GOOS == "windows" {
		return result, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Check Swift PM cache
	swiftCacheDir := filepath.Join(home, ".swiftpm/cache")
	if info, err := os.Stat(swiftCacheDir); err == nil && info.IsDir() {
		packages := scanSwiftCache(swiftCacheDir)
		result.Packages = packages
		result.Location = swiftCacheDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanSwiftCache(cacheDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage
	seen := make(map[string]bool)

	// Walk cache looking for Package.swift files
	_ = filepath.WalkDir(cacheDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if d.Name() == "Package.swift" {
			pkg := parseSwiftPackage(path)
			if pkg.Name != "" {
				key := pkg.Name
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

func parseSwiftPackage(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading Package.swift
	if err != nil {
		return pkg
	}

	content := string(data)

	// Extract package name from Package(name: "...")
	nameRe := regexp.MustCompile(`Package\s*\(\s*name:\s*"([^"]+)"`)
	if matches := nameRe.FindStringSubmatch(content); len(matches) > 1 {
		pkg.Name = matches[1]
	}

	pkg.Location = filepath.Dir(path)

	return pkg
}

// GetElixirPackages returns installed Hex packages for Elixir.
func (c *Collector) GetElixirPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "elixir",
		PackageManager: "hex",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Hex packages cache location
	hexCacheDir := filepath.Join(home, ".hex/packages/hexpm")
	if info, err := os.Stat(hexCacheDir); err == nil && info.IsDir() {
		packages := scanHexPackages(hexCacheDir)
		result.Packages = packages
		result.Location = hexCacheDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanHexPackages(hexDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(hexDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pkgName := entry.Name()
		pkgPath := filepath.Join(hexDir, pkgName)

		// List versions (tar.gz files)
		files, err := os.ReadDir(pkgPath)
		if err != nil {
			continue
		}

		for _, file := range files {
			name := file.Name()
			if strings.HasSuffix(name, ".tar") {
				version := strings.TrimSuffix(name, ".tar")
				packages = append(packages, types.LanguagePackage{
					Name:     pkgName,
					Version:  version,
					Location: pkgPath,
				})
			}
		}
	}

	return packages
}

// GetRPackages returns installed R packages from CRAN.
func (c *Collector) GetRPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "r",
		PackageManager: "cran",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	rLibDirs := findRLibraryDirs()
	if len(rLibDirs) == 0 {
		return result, nil
	}

	seen := make(map[string]bool)
	for _, dir := range rLibDirs {
		packages := scanRPackages(dir)
		for _, pkg := range packages {
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				result.Packages = append(result.Packages, pkg)
			}
		}
	}

	result.Count = len(result.Packages)
	if len(rLibDirs) > 0 {
		result.Location = strings.Join(rLibDirs, ", ")
	}

	return result, nil
}

func findRLibraryDirs() []string {
	var dirs []string
	home, _ := os.UserHomeDir()

	patterns := []string{
		"/usr/lib/R/library",
		"/usr/local/lib/R/library",
		"/usr/lib/R/site-library",
		"/usr/local/lib/R/site-library",
	}

	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, "R/*/library"),
		)
	}

	if runtime.GOOS == "darwin" {
		patterns = append(patterns,
			"/Library/Frameworks/R.framework/Versions/*/Resources/library",
			"/opt/homebrew/lib/R/*/library",
		)
	}

	if runtime.GOOS == "windows" {
		patterns = append(patterns,
			"C:/Program Files/R/R-*/library",
		)
		if home != "" {
			patterns = append(patterns,
				filepath.Join(home, "Documents/R/win-library/*"),
			)
		}
	}

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err == nil {
			for _, m := range matches {
				if info, err := os.Stat(m); err == nil && info.IsDir() {
					dirs = append(dirs, m)
				}
			}
		}
	}

	return dirs
}

func scanRPackages(libDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(libDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pkgName := entry.Name()
		descPath := filepath.Join(libDir, pkgName, "DESCRIPTION")

		pkg := parseRDescription(descPath)
		if pkg.Name == "" {
			pkg.Name = pkgName
		}
		pkg.Location = filepath.Join(libDir, pkgName)
		packages = append(packages, pkg)
	}

	return packages
}

func parseRDescription(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading R DESCRIPTION
	if err != nil {
		return pkg
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	currentField := ""
	currentValue := ""

	for scanner.Scan() {
		line := scanner.Text()

		// Check if this is a continuation line (starts with whitespace)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			currentValue += " " + strings.TrimSpace(line)
			continue
		}

		// Save previous field
		setRPackageField(&pkg, currentField, currentValue)

		// Parse new field
		if idx := strings.Index(line, ":"); idx > 0 {
			currentField = strings.TrimSpace(line[:idx])
			currentValue = strings.TrimSpace(line[idx+1:])
		}
	}

	// Save last field
	setRPackageField(&pkg, currentField, currentValue)

	return pkg
}

func setRPackageField(pkg *types.LanguagePackage, field, value string) {
	switch strings.ToLower(field) {
	case "package":
		pkg.Name = value
	case "version":
		pkg.Version = value
	case "title":
		pkg.Summary = value
	case "license":
		pkg.License = value
	case "author", "authors@r":
		if pkg.Author == "" {
			pkg.Author = value
		}
	case "url":
		pkg.Homepage = value
	}
}

// GetJuliaPackages returns installed Julia packages.
func (c *Collector) GetJuliaPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "julia",
		PackageManager: "pkg",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Julia packages location
	juliaDir := filepath.Join(home, ".julia/packages")
	if info, err := os.Stat(juliaDir); err == nil && info.IsDir() {
		packages := scanJuliaPackages(juliaDir)
		result.Packages = packages
		result.Location = juliaDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanJuliaPackages(pkgDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pkgName := entry.Name()
		pkgPath := filepath.Join(pkgDir, pkgName)

		// List version directories (hashed)
		versionEntries, err := os.ReadDir(pkgPath)
		if err != nil {
			continue
		}

		for _, versionEntry := range versionEntries {
			if !versionEntry.IsDir() {
				continue
			}

			projectPath := filepath.Join(pkgPath, versionEntry.Name(), "Project.toml")
			pkg := parseJuliaProject(projectPath)
			if pkg.Name == "" {
				pkg.Name = pkgName
			}
			pkg.Location = filepath.Join(pkgPath, versionEntry.Name())

			if pkg.Version != "" {
				packages = append(packages, pkg)
			}
		}
	}

	return packages
}

func parseJuliaProject(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading Project.toml
	if err != nil {
		return pkg
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "name = ") {
			pkg.Name = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
		} else if strings.HasPrefix(line, "version = ") {
			pkg.Version = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
		} else if strings.HasPrefix(line, "uuid = ") {
			// Skip UUID
		}
	}

	return pkg
}

// GetDartPackages returns Dart/Flutter pub cache packages.
func (c *Collector) GetDartPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "dart",
		PackageManager: "pub",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Pub cache location
	var pubCacheDir string
	if runtime.GOOS == "windows" {
		pubCacheDir = filepath.Join(home, "AppData/Local/Pub/Cache/hosted/pub.dev")
	} else {
		pubCacheDir = filepath.Join(home, ".pub-cache/hosted/pub.dev")
	}

	if info, err := os.Stat(pubCacheDir); err == nil && info.IsDir() {
		packages := scanPubCache(pubCacheDir)
		result.Packages = packages
		result.Location = pubCacheDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanPubCache(cacheDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Package directories are named: pkgname-version
		name := entry.Name()
		lastDash := strings.LastIndex(name, "-")
		if lastDash > 0 {
			pkgName := name[:lastDash]
			version := name[lastDash+1:]

			pubspecPath := filepath.Join(cacheDir, name, "pubspec.yaml")
			pkg := parsePubspec(pubspecPath)
			if pkg.Name == "" {
				pkg.Name = pkgName
			}
			if pkg.Version == "" {
				pkg.Version = version
			}
			pkg.Location = filepath.Join(cacheDir, name)

			packages = append(packages, pkg)
		}
	}

	return packages
}

func parsePubspec(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading pubspec.yaml
	if err != nil {
		return pkg
	}

	// Simple YAML parsing for common fields
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "name:") {
			pkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "name:"))
		} else if strings.HasPrefix(line, "version:") {
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "version:"))
		} else if strings.HasPrefix(line, "description:") {
			pkg.Summary = strings.TrimSpace(strings.TrimPrefix(line, "description:"))
		} else if strings.HasPrefix(line, "homepage:") {
			pkg.Homepage = strings.TrimSpace(strings.TrimPrefix(line, "homepage:"))
		}
	}

	return pkg
}

// GetOCamlPackages returns installed OPAM packages.
func (c *Collector) GetOCamlPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "ocaml",
		PackageManager: "opam",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	// OPAM is not available on Windows
	if runtime.GOOS == "windows" {
		return result, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// OPAM packages location
	opamDir := filepath.Join(home, ".opam")
	if info, err := os.Stat(opamDir); err == nil && info.IsDir() {
		packages := scanOpamPackages(opamDir)
		result.Packages = packages
		result.Location = opamDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanOpamPackages(opamDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage
	seen := make(map[string]bool)

	// Walk opam looking for installed packages in switch directories
	entries, err := os.ReadDir(opamDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		installedDir := filepath.Join(opamDir, entry.Name(), ".opam-switch/packages")
		if info, err := os.Stat(installedDir); err != nil || !info.IsDir() {
			continue
		}

		pkgEntries, err := os.ReadDir(installedDir)
		if err != nil {
			continue
		}

		for _, pkgEntry := range pkgEntries {
			if !pkgEntry.IsDir() {
				continue
			}

			// Package directories are named: pkgname.version
			name := pkgEntry.Name()
			if idx := strings.LastIndex(name, "."); idx > 0 {
				pkgName := name[:idx]
				version := name[idx+1:]

				key := pkgName + "@" + version
				if !seen[key] {
					seen[key] = true
					packages = append(packages, types.LanguagePackage{
						Name:     pkgName,
						Version:  version,
						Location: filepath.Join(installedDir, name),
					})
				}
			}
		}
	}

	return packages
}

// GetCondaPackages returns Conda environments and packages.
func (c *Collector) GetCondaPackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "python",
		PackageManager: "conda",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	condaDirs := findCondaDirs()
	if len(condaDirs) == 0 {
		return result, nil
	}

	seen := make(map[string]bool)
	for _, dir := range condaDirs {
		packages := scanCondaPackages(dir)
		for _, pkg := range packages {
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				result.Packages = append(result.Packages, pkg)
			}
		}
	}

	result.Count = len(result.Packages)
	if len(condaDirs) > 0 {
		result.Location = strings.Join(condaDirs, ", ")
	}

	return result, nil
}

func findCondaDirs() []string {
	var dirs []string
	home, _ := os.UserHomeDir()

	// Common conda installation locations
	patterns := []string{}

	if home != "" {
		patterns = append(patterns,
			filepath.Join(home, "miniconda3"),
			filepath.Join(home, "anaconda3"),
			filepath.Join(home, ".conda"),
			filepath.Join(home, "miniforge3"),
			filepath.Join(home, "mambaforge"),
		)
	}

	if runtime.GOOS == "darwin" {
		patterns = append(patterns,
			"/opt/homebrew/Caskroom/miniconda/base",
			"/opt/homebrew/Caskroom/anaconda/base",
		)
	}

	if runtime.GOOS == "windows" {
		if home != "" {
			patterns = append(patterns,
				filepath.Join(home, "Miniconda3"),
				filepath.Join(home, "Anaconda3"),
			)
		}
		patterns = append(patterns,
			"C:/ProgramData/Miniconda3",
			"C:/ProgramData/Anaconda3",
		)
	}

	for _, pattern := range patterns {
		if info, err := os.Stat(pattern); err == nil && info.IsDir() {
			dirs = append(dirs, pattern)
		}
	}

	return dirs
}

func scanCondaPackages(condaDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	// Look for conda-meta directory
	condaMetaDir := filepath.Join(condaDir, "conda-meta")
	if info, err := os.Stat(condaMetaDir); err == nil && info.IsDir() {
		packages = append(packages, scanCondaMeta(condaMetaDir)...)
	}

	// Also scan environments
	envsDir := filepath.Join(condaDir, "envs")
	if entries, err := os.ReadDir(envsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				envMetaDir := filepath.Join(envsDir, entry.Name(), "conda-meta")
				if info, err := os.Stat(envMetaDir); err == nil && info.IsDir() {
					packages = append(packages, scanCondaMeta(envMetaDir)...)
				}
			}
		}
	}

	return packages
}

func scanCondaMeta(metaDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage

	entries, err := os.ReadDir(metaDir)
	if err != nil {
		return packages
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		pkg := parseCondaMetaJSON(filepath.Join(metaDir, entry.Name()))
		if pkg.Name != "" {
			packages = append(packages, pkg)
		}
	}

	return packages
}

func parseCondaMetaJSON(path string) types.LanguagePackage {
	pkg := types.LanguagePackage{}

	data, err := os.ReadFile(path) // #nosec G304 -- reading conda meta json
	if err != nil {
		return pkg
	}

	var meta struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		License  string `json:"license"`
		Channel  string `json:"channel"`
		BuildNum int    `json:"build_number"`
	}

	if err := json.Unmarshal(data, &meta); err != nil {
		return pkg
	}

	pkg.Name = meta.Name
	pkg.Version = meta.Version
	pkg.License = meta.License
	pkg.Location = filepath.Dir(path)

	return pkg
}

// GetGradlePackages returns Gradle dependency cache packages.
func (c *Collector) GetGradlePackages() (*types.LanguagePackagesResult, error) {
	result := &types.LanguagePackagesResult{
		Language:       "java",
		PackageManager: "gradle",
		Packages:       []types.LanguagePackage{},
		Timestamp:      time.Now(),
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return result, nil
	}

	// Gradle cache location
	gradleCacheDir := filepath.Join(home, ".gradle/caches/modules-2/files-2.1")
	if info, err := os.Stat(gradleCacheDir); err == nil && info.IsDir() {
		packages := scanGradleCache(gradleCacheDir)
		result.Packages = packages
		result.Location = gradleCacheDir
	}

	result.Count = len(result.Packages)
	return result, nil
}

func scanGradleCache(cacheDir string) []types.LanguagePackage {
	var packages []types.LanguagePackage
	seen := make(map[string]bool)

	// Walk cache: groupId/artifactId/version/hash/artifact.jar
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return packages
	}

	for _, groupEntry := range entries {
		if !groupEntry.IsDir() {
			continue
		}

		groupId := groupEntry.Name()
		groupPath := filepath.Join(cacheDir, groupId)

		artifactEntries, err := os.ReadDir(groupPath)
		if err != nil {
			continue
		}

		for _, artifactEntry := range artifactEntries {
			if !artifactEntry.IsDir() {
				continue
			}

			artifactId := artifactEntry.Name()
			artifactPath := filepath.Join(groupPath, artifactId)

			versionEntries, err := os.ReadDir(artifactPath)
			if err != nil {
				continue
			}

			for _, versionEntry := range versionEntries {
				if !versionEntry.IsDir() {
					continue
				}

				version := versionEntry.Name()
				key := groupId + ":" + artifactId + "@" + version

				if !seen[key] {
					seen[key] = true
					packages = append(packages, types.LanguagePackage{
						Name:     groupId + ":" + artifactId,
						Version:  version,
						Location: filepath.Join(artifactPath, version),
					})
				}
			}
		}
	}

	return packages
}

// ============================================================================
// Extended Lock File Parsers (10 new queries)
// ============================================================================

// GetYarnLock parses yarn.lock (Yarn v1 and v2+ formats).
func (c *Collector) GetYarnLock(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "yarn.lock",
		PackageType:  "yarn",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	if lockPath == "" {
		lockPath = "yarn.lock"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	content := string(data)

	// Detect format: v1 starts with comments, v2+ starts with __metadata
	if strings.Contains(content, "__metadata:") {
		// Yarn v2+ (berry) format
		return parseYarnBerryLock(content, result)
	}

	// Yarn v1 format
	return parseYarnV1Lock(content, result)
}

func parseYarnV1Lock(content string, result *types.LockFileResult) (*types.LockFileResult, error) {
	// Yarn v1 format:
	// "pkg@version":
	//   version "resolved_version"
	//   resolved "url"
	//   integrity sha512-xxx

	lines := strings.Split(content, "\n")
	var currentPkg string
	var currentDep types.LockDependency
	inPackage := false

	pkgRe := regexp.MustCompile(`^"?(@?[^@"]+)@[^"]+`)

	for _, line := range lines {
		// Skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}

		// New package entry (not indented)
		if len(line) > 0 && line[0] != ' ' && strings.Contains(line, "@") {
			// Save previous package
			if inPackage && currentDep.Name != "" {
				result.Dependencies = append(result.Dependencies, currentDep)
			}

			// Parse package name
			matches := pkgRe.FindStringSubmatch(line)
			if len(matches) > 1 {
				currentPkg = matches[1]
				currentDep = types.LockDependency{Name: currentPkg}
				inPackage = true
			}
			continue
		}

		// Package properties (indented)
		if inPackage {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "version ") {
				version := strings.TrimPrefix(line, "version ")
				version = strings.Trim(version, "\"")
				currentDep.Version = version
			} else if strings.HasPrefix(line, "resolved ") {
				resolved := strings.TrimPrefix(line, "resolved ")
				resolved = strings.Trim(resolved, "\"")
				currentDep.Resolved = resolved
			} else if strings.HasPrefix(line, "integrity ") {
				integrity := strings.TrimPrefix(line, "integrity ")
				currentDep.Integrity = integrity
			}
		}
	}

	// Save last package
	if inPackage && currentDep.Name != "" {
		result.Dependencies = append(result.Dependencies, currentDep)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var deduped []types.LockDependency
	for _, dep := range result.Dependencies {
		key := dep.Name + "@" + dep.Version
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, dep)
		}
	}
	result.Dependencies = deduped

	result.Count = len(result.Dependencies)
	return result, nil
}

func parseYarnBerryLock(content string, result *types.LockFileResult) (*types.LockFileResult, error) {
	// Yarn v2+ (Berry) uses YAML format
	// Parse simple YAML-like structure

	lines := strings.Split(content, "\n")
	var currentPkg string
	var currentDep types.LockDependency
	inPackage := false

	// Pattern: "pkg@npm:version":
	pkgRe := regexp.MustCompile(`^"?(@?[^@"]+)@(?:npm:)?([^"]+)`)

	for _, line := range lines {
		// Skip metadata
		if strings.HasPrefix(line, "__metadata:") || strings.HasPrefix(line, "  version:") {
			continue
		}

		// New package entry (not indented, ends with :)
		if len(line) > 0 && line[0] != ' ' && strings.HasSuffix(strings.TrimSpace(line), ":") {
			// Save previous package
			if inPackage && currentDep.Name != "" && currentDep.Version != "" {
				result.Dependencies = append(result.Dependencies, currentDep)
			}

			// Parse package name
			matches := pkgRe.FindStringSubmatch(line)
			if len(matches) > 1 {
				currentPkg = matches[1]
				currentDep = types.LockDependency{Name: currentPkg}
				inPackage = true
			}
			continue
		}

		// Package properties (indented)
		if inPackage {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "version:") {
				version := strings.TrimPrefix(line, "version:")
				version = strings.TrimSpace(version)
				version = strings.Trim(version, "\"")
				currentDep.Version = version
			} else if strings.HasPrefix(line, "resolution:") {
				resolved := strings.TrimPrefix(line, "resolution:")
				resolved = strings.TrimSpace(resolved)
				resolved = strings.Trim(resolved, "\"")
				currentDep.Resolved = resolved
			} else if strings.HasPrefix(line, "checksum:") {
				integrity := strings.TrimPrefix(line, "checksum:")
				integrity = strings.TrimSpace(integrity)
				currentDep.Integrity = integrity
			}
		}
	}

	// Save last package
	if inPackage && currentDep.Name != "" && currentDep.Version != "" {
		result.Dependencies = append(result.Dependencies, currentDep)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var deduped []types.LockDependency
	for _, dep := range result.Dependencies {
		key := dep.Name + "@" + dep.Version
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, dep)
		}
	}
	result.Dependencies = deduped

	result.Count = len(result.Dependencies)
	return result, nil
}

// GetPnpmLock parses pnpm-lock.yaml.
func (c *Collector) GetPnpmLock(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "pnpm-lock.yaml",
		PackageType:  "pnpm",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	if lockPath == "" {
		lockPath = "pnpm-lock.yaml"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	// Simple YAML parsing for pnpm-lock.yaml
	// Format varies by version but packages are under "packages:" key
	content := string(data)
	lines := strings.Split(content, "\n")

	inPackages := false
	var currentPkg string
	var currentDep types.LockDependency

	// Pattern for package entries: /pkgname@version: or /@scope/pkgname@version:
	pkgRe := regexp.MustCompile(`^\s{2}/(@?[^@]+)@([^:]+):`)

	for _, line := range lines {
		if strings.TrimSpace(line) == "packages:" {
			inPackages = true
			continue
		}

		if !inPackages {
			continue
		}

		// End of packages section
		if len(line) > 0 && line[0] != ' ' && line[0] != '/' {
			break
		}

		// Package entry
		if matches := pkgRe.FindStringSubmatch(line); len(matches) > 2 {
			// Save previous
			if currentDep.Name != "" {
				result.Dependencies = append(result.Dependencies, currentDep)
			}

			currentPkg = matches[1]
			currentDep = types.LockDependency{
				Name:    currentPkg,
				Version: matches[2],
			}
			continue
		}

		// Package properties
		if currentPkg != "" {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "resolution:") {
				// Parse resolution object
				resolved := strings.TrimPrefix(line, "resolution:")
				resolved = strings.TrimSpace(resolved)
				if strings.HasPrefix(resolved, "{") {
					// Inline object, extract integrity
					if idx := strings.Index(resolved, "integrity:"); idx > 0 {
						integrity := resolved[idx+10:]
						if endIdx := strings.Index(integrity, ","); endIdx > 0 {
							integrity = integrity[:endIdx]
						}
						if endIdx := strings.Index(integrity, "}"); endIdx > 0 {
							integrity = integrity[:endIdx]
						}
						currentDep.Integrity = strings.TrimSpace(integrity)
					}
				}
			} else if strings.HasPrefix(line, "integrity:") {
				integrity := strings.TrimPrefix(line, "integrity:")
				currentDep.Integrity = strings.TrimSpace(integrity)
			}
		}
	}

	// Save last package
	if currentDep.Name != "" {
		result.Dependencies = append(result.Dependencies, currentDep)
	}

	result.Count = len(result.Dependencies)
	return result, nil
}

// GetPoetryLock parses poetry.lock (Python Poetry).
func (c *Collector) GetPoetryLock(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "poetry.lock",
		PackageType:  "poetry",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	if lockPath == "" {
		lockPath = "poetry.lock"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	// Poetry.lock is TOML format
	// [[package]] sections
	content := string(data)
	sections := strings.Split(content, "[[package]]")

	for _, section := range sections[1:] { // Skip first empty section
		dep := types.LockDependency{}
		lines := strings.Split(section, "\n")

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "name = ") {
				dep.Name = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
			} else if strings.HasPrefix(line, "version = ") {
				dep.Version = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
			} else if strings.HasPrefix(line, "optional = true") {
				dep.Dev = true
			}
		}

		if dep.Name != "" && dep.Version != "" {
			result.Dependencies = append(result.Dependencies, dep)
		}
	}

	result.Count = len(result.Dependencies)
	return result, nil
}

// GetComposerLockExtended parses composer.lock with extended information.
// This is similar to the existing one in langpkgs.go but exposed as a lock file parser.
func (c *Collector) GetComposerLockExtended(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "composer.lock",
		PackageType:  "composer",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	if lockPath == "" {
		lockPath = "composer.lock"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	var lock struct {
		Packages    []composerLockPackage `json:"packages"`
		PackagesDev []composerLockPackage `json:"packages-dev"`
	}

	if err := json.Unmarshal(data, &lock); err != nil {
		return result, nil
	}

	for _, p := range lock.Packages {
		dep := types.LockDependency{
			Name:     p.Name,
			Version:  p.Version,
			Resolved: p.Source.URL,
		}
		if p.Dist.Shasum != "" {
			dep.Integrity = "sha1:" + p.Dist.Shasum
		}
		result.Dependencies = append(result.Dependencies, dep)
	}

	for _, p := range lock.PackagesDev {
		dep := types.LockDependency{
			Name:     p.Name,
			Version:  p.Version,
			Resolved: p.Source.URL,
			Dev:      true,
		}
		if p.Dist.Shasum != "" {
			dep.Integrity = "sha1:" + p.Dist.Shasum
		}
		result.Dependencies = append(result.Dependencies, dep)
	}

	result.Count = len(result.Dependencies)
	return result, nil
}

type composerLockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"source"`
	Dist struct {
		Type   string `json:"type"`
		URL    string `json:"url"`
		Shasum string `json:"shasum"`
	} `json:"dist"`
}

// GetMixLock parses mix.lock (Elixir).
func (c *Collector) GetMixLock(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "mix.lock",
		PackageType:  "hex",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	if lockPath == "" {
		lockPath = "mix.lock"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	// mix.lock format (Elixir map format):
	// %{
	//   "pkg_name": {:hex, :pkg_name, "version", "sha256", [:mix], ...},
	// }

	content := string(data)

	// Pattern: "pkg_name": {:hex, :pkg_name, "version", "sha256", ...
	pkgRe := regexp.MustCompile(`"([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)",\s*"([^"]+)"`)

	matches := pkgRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 4 {
			dep := types.LockDependency{
				Name:      match[1],
				Version:   match[2],
				Integrity: "sha256:" + match[3],
			}
			result.Dependencies = append(result.Dependencies, dep)
		}
	}

	result.Count = len(result.Dependencies)
	return result, nil
}

// GetPubspecLock parses pubspec.lock (Dart/Flutter).
func (c *Collector) GetPubspecLock(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "pubspec.lock",
		PackageType:  "pub",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	if lockPath == "" {
		lockPath = "pubspec.lock"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	// pubspec.lock is YAML format
	content := string(data)
	lines := strings.Split(content, "\n")

	inPackages := false
	var currentPkg string
	var currentDep types.LockDependency
	indentLevel := 0

	for _, line := range lines {
		if strings.TrimSpace(line) == "packages:" {
			inPackages = true
			continue
		}

		if !inPackages {
			continue
		}

		// End of packages section
		if len(line) > 0 && line[0] != ' ' {
			break
		}

		// Count indentation
		trimmed := strings.TrimLeft(line, " ")
		currentIndent := len(line) - len(trimmed)

		// Package name (2 spaces indent)
		if currentIndent == 2 && strings.HasSuffix(trimmed, ":") {
			// Save previous
			if currentDep.Name != "" {
				result.Dependencies = append(result.Dependencies, currentDep)
			}

			currentPkg = strings.TrimSuffix(trimmed, ":")
			currentDep = types.LockDependency{Name: currentPkg}
			indentLevel = 2
			continue
		}

		// Package properties (4+ spaces indent)
		if currentPkg != "" && currentIndent >= 4 {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "version:") {
				version := strings.TrimPrefix(line, "version:")
				version = strings.TrimSpace(version)
				version = strings.Trim(version, "\"")
				currentDep.Version = version
			} else if strings.HasPrefix(line, "sha256:") {
				sha := strings.TrimPrefix(line, "sha256:")
				sha = strings.TrimSpace(sha)
				sha = strings.Trim(sha, "\"")
				currentDep.Integrity = "sha256:" + sha
			} else if strings.HasPrefix(line, "url:") {
				url := strings.TrimPrefix(line, "url:")
				url = strings.TrimSpace(url)
				url = strings.Trim(url, "\"")
				currentDep.Resolved = url
			}
		}
	}

	// Save last package
	if currentDep.Name != "" {
		result.Dependencies = append(result.Dependencies, currentDep)
	}

	// Filter out empty entries
	var filtered []types.LockDependency
	for _, dep := range result.Dependencies {
		if dep.Version != "" {
			filtered = append(filtered, dep)
		}
	}
	result.Dependencies = filtered

	_ = indentLevel // Suppress unused variable warning

	result.Count = len(result.Dependencies)
	return result, nil
}

// GetSwiftResolved parses Package.resolved (Swift Package Manager).
func (c *Collector) GetSwiftResolved(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "Package.resolved",
		PackageType:  "spm",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	// Swift PM is not available on Windows
	if runtime.GOOS == "windows" {
		return result, nil
	}

	if lockPath == "" {
		lockPath = "Package.resolved"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	// Package.resolved is JSON (v1 or v2 format)
	var resolvedV2 struct {
		Pins []struct {
			Identity string `json:"identity"`
			Location string `json:"location"`
			State    struct {
				Revision string `json:"revision"`
				Version  string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
		Version int `json:"version"`
	}

	var resolvedV1 struct {
		Object struct {
			Pins []struct {
				Package    string `json:"package"`
				Repository string `json:"repositoryURL"`
				State      struct {
					Revision string `json:"revision"`
					Version  string `json:"version"`
				} `json:"state"`
			} `json:"pins"`
		} `json:"object"`
		Version int `json:"version"`
	}

	// Try v2 format first
	if err := json.Unmarshal(data, &resolvedV2); err == nil && resolvedV2.Version == 2 {
		for _, pin := range resolvedV2.Pins {
			dep := types.LockDependency{
				Name:      pin.Identity,
				Version:   pin.State.Version,
				Resolved:  pin.Location,
				Integrity: pin.State.Revision,
			}
			result.Dependencies = append(result.Dependencies, dep)
		}
	} else if err := json.Unmarshal(data, &resolvedV1); err == nil {
		// v1 format
		for _, pin := range resolvedV1.Object.Pins {
			dep := types.LockDependency{
				Name:      pin.Package,
				Version:   pin.State.Version,
				Resolved:  pin.Repository,
				Integrity: pin.State.Revision,
			}
			result.Dependencies = append(result.Dependencies, dep)
		}
	}

	result.Count = len(result.Dependencies)
	return result, nil
}

// GetPodfileLock parses Podfile.lock (CocoaPods for iOS/macOS).
func (c *Collector) GetPodfileLock(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "Podfile.lock",
		PackageType:  "cocoapods",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	// CocoaPods is macOS only
	if runtime.GOOS != "darwin" {
		return result, nil
	}

	if lockPath == "" {
		lockPath = "Podfile.lock"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	// Podfile.lock is YAML format
	// PODS:
	//   - PodName (version)
	// SPEC CHECKSUMS:
	//   PodName: checksum

	content := string(data)
	lines := strings.Split(content, "\n")

	inPods := false
	inChecksums := false
	checksums := make(map[string]string)

	// Pattern for pod entries: - PodName (version)
	podRe := regexp.MustCompile(`^\s+-\s+([^(/\s]+)(?:/[^(]+)?\s*\(([^)]+)\)`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if trimmed == "PODS:" {
			inPods = true
			inChecksums = false
			continue
		}

		if trimmed == "SPEC CHECKSUMS:" {
			inPods = false
			inChecksums = true
			continue
		}

		if trimmed == "DEPENDENCIES:" || trimmed == "SPEC REPOS:" || trimmed == "EXTERNAL SOURCES:" {
			inPods = false
			inChecksums = false
			continue
		}

		if inPods {
			if matches := podRe.FindStringSubmatch(line); len(matches) > 2 {
				dep := types.LockDependency{
					Name:    matches[1],
					Version: matches[2],
				}
				result.Dependencies = append(result.Dependencies, dep)
			}
		}

		if inChecksums {
			// Format: PodName: checksum
			if idx := strings.Index(line, ":"); idx > 0 {
				name := strings.TrimSpace(line[:idx])
				checksum := strings.TrimSpace(line[idx+1:])
				checksums[name] = checksum
			}
		}
	}

	// Add checksums to dependencies
	for i := range result.Dependencies {
		if checksum, ok := checksums[result.Dependencies[i].Name]; ok {
			result.Dependencies[i].Integrity = checksum
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var deduped []types.LockDependency
	for _, dep := range result.Dependencies {
		key := dep.Name + "@" + dep.Version
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, dep)
		}
	}
	result.Dependencies = deduped

	result.Count = len(result.Dependencies)
	return result, nil
}

// GetGradleLock parses gradle.lockfile.
func (c *Collector) GetGradleLock(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "gradle.lockfile",
		PackageType:  "gradle",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	if lockPath == "" {
		lockPath = "gradle.lockfile"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	// gradle.lockfile format:
	// # Comment
	// group:artifact:version=configuration1,configuration2
	// or
	// group:artifact:version

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Remove configuration suffix if present
		if idx := strings.Index(line, "="); idx > 0 {
			line = line[:idx]
		}

		// Parse group:artifact:version
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			groupId := parts[0]
			artifactId := parts[1]
			version := parts[2]

			key := groupId + ":" + artifactId + "@" + version
			if !seen[key] {
				seen[key] = true
				dep := types.LockDependency{
					Name:    groupId + ":" + artifactId,
					Version: version,
				}
				result.Dependencies = append(result.Dependencies, dep)
			}
		}
	}

	result.Count = len(result.Dependencies)
	return result, nil
}

// GetCondaLock parses conda-lock.yml.
func (c *Collector) GetCondaLock(lockPath string) (*types.LockFileResult, error) {
	result := &types.LockFileResult{
		LockFile:     "conda-lock.yml",
		PackageType:  "conda",
		Dependencies: []types.LockDependency{},
		Timestamp:    time.Now(),
	}

	if lockPath == "" {
		lockPath = "conda-lock.yml"
	}

	result.LockFile = lockPath

	data, err := os.ReadFile(lockPath) // #nosec G304 -- user-specified lock file path
	if err != nil {
		return result, nil
	}

	// conda-lock.yml is YAML format with package entries
	content := string(data)
	lines := strings.Split(content, "\n")

	inPackage := false
	var currentDep types.LockDependency

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// New package entry
		if strings.HasPrefix(line, "  - ") && !strings.HasPrefix(line, "    ") {
			// Save previous
			if currentDep.Name != "" {
				result.Dependencies = append(result.Dependencies, currentDep)
			}
			currentDep = types.LockDependency{}
			inPackage = true
			continue
		}

		if inPackage && strings.HasPrefix(line, "    ") {
			if strings.HasPrefix(trimmed, "name:") {
				currentDep.Name = strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
			} else if strings.HasPrefix(trimmed, "version:") {
				currentDep.Version = strings.TrimSpace(strings.TrimPrefix(trimmed, "version:"))
			} else if strings.HasPrefix(trimmed, "url:") {
				currentDep.Resolved = strings.TrimSpace(strings.TrimPrefix(trimmed, "url:"))
			} else if strings.HasPrefix(trimmed, "hash:") {
				hash := strings.TrimSpace(strings.TrimPrefix(trimmed, "hash:"))
				// conda-lock uses md5:xxx or sha256:xxx format
				currentDep.Integrity = hash
			}
		}
	}

	// Save last package
	if currentDep.Name != "" {
		result.Dependencies = append(result.Dependencies, currentDep)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var deduped []types.LockDependency
	for _, dep := range result.Dependencies {
		key := dep.Name + "@" + dep.Version
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, dep)
		}
	}
	result.Dependencies = deduped

	result.Count = len(result.Dependencies)
	return result, nil
}
