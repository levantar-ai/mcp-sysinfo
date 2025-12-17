//go:build windows

package software

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// MacOSApplication represents a macOS application (stub for Windows).
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

// MacOSApplicationsResult represents macOS applications query results (stub for Windows).
type MacOSApplicationsResult struct {
	Applications []MacOSApplication `json:"applications"`
	Count        int                `json:"count"`
	Timestamp    time.Time          `json:"timestamp"`
}

// GetMacOSApplications returns empty result on Windows (macOS only).
func (c *Collector) GetMacOSApplications() (*MacOSApplicationsResult, error) {
	return &MacOSApplicationsResult{
		Applications: []MacOSApplication{},
		Count:        0,
		Timestamp:    time.Now(),
	}, nil
}

// WindowsHotfix represents a Windows hotfix/update.
type WindowsHotfix struct {
	HotfixID    string `json:"hotfix_id"`
	Description string `json:"description,omitempty"`
	InstalledBy string `json:"installed_by,omitempty"`
	InstalledOn string `json:"installed_on,omitempty"`
	Source      string `json:"source,omitempty"`
	Caption     string `json:"caption,omitempty"`
}

// WindowsHotfixesResult represents Windows hotfixes query results.
type WindowsHotfixesResult struct {
	Hotfixes  []WindowsHotfix `json:"hotfixes"`
	Count     int             `json:"count"`
	Timestamp time.Time       `json:"timestamp"`
}

// GetWindowsHotfixes returns Windows hotfixes/updates using Get-HotFix.
func (c *Collector) GetWindowsHotfixes() (*WindowsHotfixesResult, error) {
	result := &WindowsHotfixesResult{
		Hotfixes:  []WindowsHotfix{},
		Timestamp: time.Now(),
	}

	// Use PowerShell Get-HotFix to get Windows updates
	// #nosec G204 -- powershell is a system utility
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command",
		"Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn,Caption | ConvertTo-Csv -NoTypeInformation")
	output, err := cmd.Output()
	if err != nil {
		// Try wmic as fallback
		return c.getHotfixesWmic()
	}

	hotfixes := parseHotfixCSV(output)
	result.Hotfixes = hotfixes
	result.Count = len(hotfixes)
	return result, nil
}

func parseHotfixCSV(output []byte) []WindowsHotfix {
	var hotfixes []WindowsHotfix

	reader := csv.NewReader(bytes.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return hotfixes
	}

	// First row is header
	header := records[0]
	idxMap := make(map[string]int)
	for i, h := range header {
		idxMap[strings.ToLower(strings.Trim(h, "\""))] = i
	}

	for _, record := range records[1:] {
		if len(record) == 0 {
			continue
		}

		hotfix := WindowsHotfix{Source: "Get-HotFix"}

		if idx, ok := idxMap["hotfixid"]; ok && idx < len(record) {
			hotfix.HotfixID = strings.Trim(record[idx], "\"")
		}
		if idx, ok := idxMap["description"]; ok && idx < len(record) {
			hotfix.Description = strings.Trim(record[idx], "\"")
		}
		if idx, ok := idxMap["installedby"]; ok && idx < len(record) {
			hotfix.InstalledBy = strings.Trim(record[idx], "\"")
		}
		if idx, ok := idxMap["installedon"]; ok && idx < len(record) {
			hotfix.InstalledOn = strings.Trim(record[idx], "\"")
		}
		if idx, ok := idxMap["caption"]; ok && idx < len(record) {
			hotfix.Caption = strings.Trim(record[idx], "\"")
		}

		if hotfix.HotfixID != "" {
			hotfixes = append(hotfixes, hotfix)
		}
	}

	return hotfixes
}

func (c *Collector) getHotfixesWmic() (*WindowsHotfixesResult, error) {
	result := &WindowsHotfixesResult{
		Hotfixes:  []WindowsHotfix{},
		Timestamp: time.Now(),
	}

	// #nosec G204 -- wmic is a system utility
	cmd := cmdexec.Command("wmic", "qfe", "get", "HotFixID,Description,InstalledBy,InstalledOn", "/format:csv")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	hotfixes := parseWmicHotfixes(output)
	result.Hotfixes = hotfixes
	result.Count = len(hotfixes)
	return result, nil
}

func parseWmicHotfixes(output []byte) []WindowsHotfix {
	var hotfixes []WindowsHotfix
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// CSV format: Node,Description,HotFixID,InstalledBy,InstalledOn
		parts := strings.Split(line, ",")
		if len(parts) < 4 {
			continue
		}

		hotfix := WindowsHotfix{
			Description: parts[1],
			HotfixID:    parts[2],
			InstalledBy: parts[3],
			Source:      "wmic",
		}

		if len(parts) > 4 {
			hotfix.InstalledOn = parts[4]
		}

		if hotfix.HotfixID != "" {
			hotfixes = append(hotfixes, hotfix)
		}
	}

	return hotfixes
}

// GetPathExecutables returns executables found in PATH directories.
func (c *Collector) GetPathExecutables() (*types.PathExecutablesResult, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = `C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem`
	}

	pathDirs := strings.Split(pathEnv, ";")
	var executables []types.PathExecutable
	seen := make(map[string]bool)

	// Windows executable extensions
	execExts := map[string]bool{
		".exe": true,
		".cmd": true,
		".bat": true,
		".com": true,
		".ps1": true,
	}

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
			ext := strings.ToLower(filepath.Ext(name))
			if !execExts[ext] {
				continue
			}

			lowerName := strings.ToLower(name)
			if seen[lowerName] {
				continue
			}

			fullPath := filepath.Join(dir, name)
			info, err := entry.Info()
			if err != nil {
				continue
			}

			exec := types.PathExecutable{
				Name:    name,
				Path:    fullPath,
				Size:    info.Size(),
				Mode:    info.Mode().String(),
				ModTime: info.ModTime(),
			}

			executables = append(executables, exec)
			seen[lowerName] = true
		}
	}

	return &types.PathExecutablesResult{
		Executables: executables,
		Count:       len(executables),
		PathDirs:    pathDirs,
		Timestamp:   time.Now(),
	}, nil
}

// GetSystemPackages returns installed system packages using Windows package managers.
func (c *Collector) GetSystemPackages() (*types.SystemPackagesResult, error) {
	// Try chocolatey first
	if choco, err := cmdexec.LookPath("choco"); err == nil {
		return c.getChocoPackages(choco)
	}

	// Try winget
	if winget, err := cmdexec.LookPath("winget"); err == nil {
		return c.getWingetPackages(winget)
	}

	// Fall back to wmic (always available)
	return c.getWmicPackages()
}

// getChocoPackages retrieves packages using Chocolatey.
func (c *Collector) getChocoPackages(choco string) (*types.SystemPackagesResult, error) {
	// #nosec G204 -- choco path is from LookPath
	cmd := cmdexec.Command(choco, "list", "--local-only", "--limit-output")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "chocolatey",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parseChocoOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "chocolatey",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parseChocoOutput parses Chocolatey list output.
func parseChocoOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: package|version
		parts := strings.Split(line, "|")
		if len(parts) < 2 {
			continue
		}

		packages = append(packages, types.SystemPackage{
			Name:    parts[0],
			Version: parts[1],
			Source:  "chocolatey",
		})
	}

	return packages
}

// getWingetPackages retrieves packages using winget.
func (c *Collector) getWingetPackages(winget string) (*types.SystemPackagesResult, error) {
	// #nosec G204 -- winget path is from LookPath
	cmd := cmdexec.Command(winget, "list", "--disable-interactivity")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "winget",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parseWingetOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "winget",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parseWingetOutput parses winget list output.
func parseWingetOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header lines
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "---") {
			break
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Format is column-based, try to parse
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Last field is usually version
		version := fields[len(fields)-1]
		name := strings.Join(fields[:len(fields)-1], " ")

		packages = append(packages, types.SystemPackage{
			Name:    name,
			Version: version,
			Source:  "winget",
		})
	}

	return packages
}

// getWmicPackages retrieves installed programs using wmic.
func (c *Collector) getWmicPackages() (*types.SystemPackagesResult, error) {
	// #nosec G204 -- wmic is a system utility
	cmd := cmdexec.Command("wmic", "product", "get", "Name,Version", "/format:csv")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "wmic",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parseWmicOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "wmic",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parseWmicOutput parses wmic CSV output.
func parseWmicOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// CSV format: Node,Name,Version
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}

		name := parts[1]
		version := parts[2]
		if name == "" {
			continue
		}

		packages = append(packages, types.SystemPackage{
			Name:    name,
			Version: version,
			Source:  "wmic",
		})
	}

	return packages
}
