//go:build linux

package software

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// MacOSApplication represents a macOS application (stub for Linux).
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

// MacOSApplicationsResult represents macOS applications query results (stub for Linux).
type MacOSApplicationsResult struct {
	Applications []MacOSApplication `json:"applications"`
	Count        int                `json:"count"`
	Timestamp    time.Time          `json:"timestamp"`
}

// GetMacOSApplications returns empty result on Linux (macOS only).
func (c *Collector) GetMacOSApplications() (*MacOSApplicationsResult, error) {
	return &MacOSApplicationsResult{
		Applications: []MacOSApplication{},
		Count:        0,
		Timestamp:    time.Now(),
	}, nil
}

// WindowsHotfix represents a Windows hotfix/update (stub for Linux).
type WindowsHotfix struct {
	HotfixID    string `json:"hotfix_id"`
	Description string `json:"description,omitempty"`
	InstalledBy string `json:"installed_by,omitempty"`
	InstalledOn string `json:"installed_on,omitempty"`
}

// WindowsHotfixesResult represents Windows hotfixes query results (stub for Linux).
type WindowsHotfixesResult struct {
	Hotfixes  []WindowsHotfix `json:"hotfixes"`
	Count     int             `json:"count"`
	Timestamp time.Time       `json:"timestamp"`
}

// GetWindowsHotfixes returns empty result on Linux (Windows only).
func (c *Collector) GetWindowsHotfixes() (*WindowsHotfixesResult, error) {
	return &WindowsHotfixesResult{
		Hotfixes:  []WindowsHotfix{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetPathExecutables returns executables found in PATH directories.
func (c *Collector) GetPathExecutables() (*types.PathExecutablesResult, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = "/usr/local/bin:/usr/bin:/bin"
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

// GetSystemPackages returns installed system packages using dpkg, rpm, or apk.
func (c *Collector) GetSystemPackages() (*types.SystemPackagesResult, error) {
	// Try dpkg (Debian/Ubuntu)
	if dpkg, err := cmdexec.LookPath("dpkg-query"); err == nil {
		return c.getDpkgPackages(dpkg)
	}

	// Try rpm (RHEL/Fedora/CentOS)
	if rpm, err := cmdexec.LookPath("rpm"); err == nil {
		return c.getRpmPackages(rpm)
	}

	// Try apk (Alpine)
	if apk, err := cmdexec.LookPath("apk"); err == nil {
		return c.getApkPackages(apk)
	}

	// Try pacman (Arch)
	if pacman, err := cmdexec.LookPath("pacman"); err == nil {
		return c.getPacmanPackages(pacman)
	}

	return &types.SystemPackagesResult{
		PackageManager: "unknown",
		Packages:       []types.SystemPackage{},
		Count:          0,
		Timestamp:      time.Now(),
	}, nil
}

// getDpkgPackages retrieves packages using dpkg-query.
func (c *Collector) getDpkgPackages(dpkgQuery string) (*types.SystemPackagesResult, error) {
	// #nosec G204 -- dpkgQuery path is from LookPath
	cmd := cmdexec.Command(dpkgQuery, "-W", "-f=${Package}\\t${Version}\\t${Architecture}\\t${Installed-Size}\\t${Status}\\t${binary:Summary}\\n")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "dpkg",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parseDpkgOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "dpkg",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parseDpkgOutput parses dpkg-query output.
func parseDpkgOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}

		pkg := types.SystemPackage{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       fields[4],
		}

		// Parse size (in KB)
		if size, err := strconv.ParseInt(fields[3], 10, 64); err == nil {
			pkg.Size = size * 1024 // Convert to bytes
		}

		if len(fields) > 5 {
			pkg.Description = fields[5]
		}

		packages = append(packages, pkg)
	}

	return packages
}

// getRpmPackages retrieves packages using rpm.
func (c *Collector) getRpmPackages(rpm string) (*types.SystemPackagesResult, error) {
	// #nosec G204 -- rpm path is from LookPath
	cmd := cmdexec.Command(rpm, "-qa", "--queryformat", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SIZE}\\t%{INSTALLTIME}\\t%{SUMMARY}\\n")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "rpm",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parseRpmOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "rpm",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parseRpmOutput parses rpm query output.
func parseRpmOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}

		pkg := types.SystemPackage{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
		}

		if size, err := strconv.ParseInt(fields[3], 10, 64); err == nil {
			pkg.Size = size
		}

		// Parse install time
		if installTime, err := strconv.ParseInt(fields[4], 10, 64); err == nil {
			pkg.InstallDate = time.Unix(installTime, 0).Format(time.RFC3339)
		}

		if len(fields) > 5 {
			pkg.Description = fields[5]
		}

		packages = append(packages, pkg)
	}

	return packages
}

// getApkPackages retrieves packages using apk.
func (c *Collector) getApkPackages(apk string) (*types.SystemPackagesResult, error) {
	// #nosec G204 -- apk path is from LookPath
	cmd := cmdexec.Command(apk, "info", "-v")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "apk",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parseApkOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "apk",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parseApkOutput parses apk info output.
func parseApkOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Format: package-name-version
		// Split on last hyphen that's followed by a digit
		lastHyphen := -1
		for i := len(line) - 1; i >= 0; i-- {
			if line[i] == '-' && i+1 < len(line) && line[i+1] >= '0' && line[i+1] <= '9' {
				lastHyphen = i
				break
			}
		}

		var name, version string
		if lastHyphen > 0 {
			name = line[:lastHyphen]
			version = line[lastHyphen+1:]
		} else {
			name = line
		}

		packages = append(packages, types.SystemPackage{
			Name:    name,
			Version: version,
		})
	}

	return packages
}

// getPacmanPackages retrieves packages using pacman.
func (c *Collector) getPacmanPackages(pacman string) (*types.SystemPackagesResult, error) {
	// #nosec G204 -- pacman path is from LookPath
	cmd := cmdexec.Command(pacman, "-Q")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemPackagesResult{
			PackageManager: "pacman",
			Packages:       []types.SystemPackage{},
			Count:          0,
			Timestamp:      time.Now(),
		}, nil
	}

	packages := parsePacmanOutput(output)

	return &types.SystemPackagesResult{
		PackageManager: "pacman",
		Packages:       packages,
		Count:          len(packages),
		Timestamp:      time.Now(),
	}, nil
}

// parsePacmanOutput parses pacman query output.
func parsePacmanOutput(output []byte) []types.SystemPackage {
	var packages []types.SystemPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		packages = append(packages, types.SystemPackage{
			Name:    fields[0],
			Version: fields[1],
		})
	}

	return packages
}
