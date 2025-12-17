//go:build darwin

package software

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// GetPathExecutables returns executables found in PATH directories.
func (c *Collector) GetPathExecutables() (*types.PathExecutablesResult, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	}

	pathDirs := strings.Split(pathEnv, ":")
	var executables []types.PathExecutable
	seen := make(map[string]bool)

	for _, dir := range pathDirs {
		if dir == "" {
			continue
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			if seen[name] {
				continue
			}

			fullPath := filepath.Join(dir, name)
			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Check if executable
			mode := info.Mode()
			if mode&0111 == 0 {
				continue
			}

			exec := types.PathExecutable{
				Name:    name,
				Path:    fullPath,
				Size:    info.Size(),
				Mode:    mode.String(),
				ModTime: info.ModTime(),
			}

			// Check if symlink
			if mode&os.ModeSymlink != 0 {
				exec.IsSymlink = true
				if target, err := os.Readlink(fullPath); err == nil {
					exec.Target = target
				}
			}

			executables = append(executables, exec)
			seen[name] = true
		}
	}

	return &types.PathExecutablesResult{
		Executables: executables,
		Count:       len(executables),
		PathDirs:    pathDirs,
		Timestamp:   time.Now(),
	}, nil
}

// GetSystemPackages returns installed system packages using Homebrew or pkgutil.
func (c *Collector) GetSystemPackages() (*types.SystemPackagesResult, error) {
	// Try Homebrew first (most common on macOS)
	if brew, err := cmdexec.LookPath("brew"); err == nil {
		return c.getBrewPackages(brew)
	}

	// Fall back to pkgutil (system packages)
	if pkgutil, err := cmdexec.LookPath("pkgutil"); err == nil {
		return c.getPkgutilPackages(pkgutil)
	}

	return &types.SystemPackagesResult{
		PackageManager: "unknown",
		Packages:       []types.SystemPackage{},
		Count:          0,
		Timestamp:      time.Now(),
	}, nil
}

// getBrewPackages retrieves packages using Homebrew.
func (c *Collector) getBrewPackages(brew string) (*types.SystemPackagesResult, error) {
	// #nosec G204 -- brew path is from LookPath
	cmd := cmdexec.Command(brew, "list", "--versions")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "brew",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parseBrewOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "brew",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parseBrewOutput parses Homebrew list output.
func parseBrewOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: package-name version [version2 ...]
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		packages = append(packages, types.SystemPackage{
			Name:    fields[0],
			Version: fields[1], // Use first (latest) version
			Source:  "homebrew",
		})
	}

	return packages
}

// getPkgutilPackages retrieves system packages using pkgutil.
func (c *Collector) getPkgutilPackages(pkgutil string) (*types.SystemPackagesResult, error) {
	// #nosec G204 -- pkgutil path is from LookPath
	cmd := cmdexec.Command(pkgutil, "--pkgs")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "pkgutil",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parsePkgutilOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "pkgutil",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parsePkgutilOutput parses pkgutil output.
func parsePkgutilOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Package IDs are like com.apple.pkg.CoreTypes
		packages = append(packages, types.SystemPackage{
			Name:   line,
			Source: "pkgutil",
		})
	}

	return packages
}

// WindowsHotfix represents a Windows hotfix/update (stub for Darwin).
type WindowsHotfix struct {
	HotfixID    string `json:"hotfix_id"`
	Description string `json:"description,omitempty"`
	InstalledBy string `json:"installed_by,omitempty"`
	InstalledOn string `json:"installed_on,omitempty"`
	Source      string `json:"source,omitempty"`
	Caption     string `json:"caption,omitempty"`
}

// WindowsHotfixesResult represents Windows hotfixes query results (stub for Darwin).
type WindowsHotfixesResult struct {
	Hotfixes  []WindowsHotfix `json:"hotfixes"`
	Count     int             `json:"count"`
	Timestamp time.Time       `json:"timestamp"`
}

// GetWindowsHotfixes returns empty result on Darwin (Windows only).
func (c *Collector) GetWindowsHotfixes() (*WindowsHotfixesResult, error) {
	return &WindowsHotfixesResult{
		Hotfixes:  []WindowsHotfix{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// MacOSApplication represents a macOS application from /Applications.
type MacOSApplication struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	BundleID     string `json:"bundle_id,omitempty"`
	Version      string `json:"version,omitempty"`
	ShortVersion string `json:"short_version,omitempty"`
	Executable   string `json:"executable,omitempty"`
	Category     string `json:"category,omitempty"`
	Copyright    string `json:"copyright,omitempty"`
}

// MacOSApplicationsResult represents macOS applications query results.
type MacOSApplicationsResult struct {
	Applications []MacOSApplication `json:"applications"`
	Count        int                `json:"count"`
	Timestamp    time.Time          `json:"timestamp"`
}

// GetMacOSApplications returns installed macOS applications from /Applications.
func (c *Collector) GetMacOSApplications() (*MacOSApplicationsResult, error) {
	result := &MacOSApplicationsResult{
		Applications: []MacOSApplication{},
		Timestamp:    time.Now(),
	}

	// Scan /Applications and ~/Applications
	appDirs := []string{"/Applications"}
	if home, err := os.UserHomeDir(); err == nil {
		appDirs = append(appDirs, filepath.Join(home, "Applications"))
	}

	seen := make(map[string]bool)
	for _, appDir := range appDirs {
		apps := scanApplicationsDir(appDir)
		for _, app := range apps {
			if !seen[app.Path] {
				seen[app.Path] = true
				result.Applications = append(result.Applications, app)
			}
		}
	}

	result.Count = len(result.Applications)
	return result, nil
}

func scanApplicationsDir(appDir string) []MacOSApplication {
	var apps []MacOSApplication

	entries, err := os.ReadDir(appDir)
	if err != nil {
		return apps
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasSuffix(name, ".app") {
			continue
		}

		appPath := filepath.Join(appDir, name)
		app := parseMacOSApp(appPath)
		if app.Name != "" {
			apps = append(apps, app)
		}
	}

	return apps
}

func parseMacOSApp(appPath string) MacOSApplication {
	app := MacOSApplication{
		Path: appPath,
		Name: strings.TrimSuffix(filepath.Base(appPath), ".app"),
	}

	infoPlistPath := filepath.Join(appPath, "Contents", "Info.plist")

	// Use plutil to convert plist to JSON for parsing
	// #nosec G204 -- plutil is a system utility
	cmd := cmdexec.Command("plutil", "-convert", "json", "-o", "-", infoPlistPath)
	output, err := cmd.Output()
	if err != nil {
		return app
	}

	var plistData map[string]interface{}
	if err := json.Unmarshal(output, &plistData); err != nil {
		return app
	}

	// Extract fields from Info.plist
	if bundleID, ok := plistData["CFBundleIdentifier"].(string); ok {
		app.BundleID = bundleID
	}
	if version, ok := plistData["CFBundleVersion"].(string); ok {
		app.Version = version
	}
	if shortVersion, ok := plistData["CFBundleShortVersionString"].(string); ok {
		app.ShortVersion = shortVersion
	}
	if executable, ok := plistData["CFBundleExecutable"].(string); ok {
		app.Executable = executable
	}
	if category, ok := plistData["LSApplicationCategoryType"].(string); ok {
		app.Category = category
	}
	if copyright, ok := plistData["NSHumanReadableCopyright"].(string); ok {
		app.Copyright = copyright
	}
	if name, ok := plistData["CFBundleDisplayName"].(string); ok && name != "" {
		app.Name = name
	} else if name, ok := plistData["CFBundleName"].(string); ok && name != "" {
		app.Name = name
	}

	return app
}

// GetSnapPackages returns empty on macOS (Linux only).
func (c *Collector) GetSnapPackages() (*types.SnapPackagesResult, error) {
	return &types.SnapPackagesResult{
		Packages:  []types.SnapPackage{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetFlatpakPackages returns empty on macOS (Linux only).
func (c *Collector) GetFlatpakPackages() (*types.FlatpakPackagesResult, error) {
	return &types.FlatpakPackagesResult{
		Packages:  []types.FlatpakPackage{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetHomebrewCasks returns installed Homebrew Casks (macOS GUI apps).
func (c *Collector) GetHomebrewCasks() (*types.HomebrewCasksResult, error) {
	brew, err := cmdexec.LookPath("brew")
	if err != nil {
		return &types.HomebrewCasksResult{
			Casks:     []types.HomebrewCask{},
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// #nosec G204 -- brew path is from LookPath
	cmd := cmdexec.Command(brew, "list", "--cask", "--versions")
	output, err := cmd.Output()
	if err != nil {
		return &types.HomebrewCasksResult{
			Casks:     []types.HomebrewCask{},
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	casks := parseBrewCasksOutput(output)
	return &types.HomebrewCasksResult{
		Casks:     casks,
		Count:     len(casks),
		Timestamp: time.Now(),
	}, nil
}

// parseBrewCasksOutput parses Homebrew cask list output.
func parseBrewCasksOutput(output []byte) []types.HomebrewCask {
	var casks []types.HomebrewCask
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: cask-name version
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}

		cask := types.HomebrewCask{
			Name: fields[0],
		}
		if len(fields) > 1 {
			cask.Version = fields[1]
		}

		casks = append(casks, cask)
	}

	return casks
}

// GetScoopPackages returns empty on macOS (Windows only).
func (c *Collector) GetScoopPackages() (*types.ScoopPackagesResult, error) {
	return &types.ScoopPackagesResult{
		Packages:  []types.ScoopPackage{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetWindowsPrograms returns empty on macOS (Windows only).
func (c *Collector) GetWindowsPrograms() (*types.WindowsProgramsResult, error) {
	return &types.WindowsProgramsResult{
		Programs:  []types.WindowsProgram{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetWindowsFeatures returns empty on macOS (Windows only).
func (c *Collector) GetWindowsFeatures() (*types.WindowsFeaturesResult, error) {
	return &types.WindowsFeaturesResult{
		Features:  []types.WindowsFeature{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}
