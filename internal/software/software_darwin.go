//go:build darwin

package software

import (
	"bufio"
	"bytes"
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
