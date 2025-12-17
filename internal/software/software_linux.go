//go:build linux

package software

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
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

// GetSnapPackages returns installed Snap packages.
func (c *Collector) GetSnapPackages() (*types.SnapPackagesResult, error) {
	snap, err := cmdexec.LookPath("snap")
	if err != nil {
		return &types.SnapPackagesResult{
			Packages:  []types.SnapPackage{},
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// #nosec G204 -- snap path is from LookPath
	cmd := cmdexec.Command(snap, "list", "--color=never")
	output, err := cmd.Output()
	if err != nil {
		return &types.SnapPackagesResult{
			Packages:  []types.SnapPackage{},
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	packages := parseSnapOutput(output)
	return &types.SnapPackagesResult{
		Packages:  packages,
		Count:     len(packages),
		Timestamp: time.Now(),
	}, nil
}

// parseSnapOutput parses snap list output.
func parseSnapOutput(output []byte) []types.SnapPackage {
	var packages []types.SnapPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header line (Name  Version  Rev  Tracking  Publisher  Notes)
	_ = scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pkg := types.SnapPackage{
			Name:     fields[0],
			Version:  fields[1],
			Revision: fields[2],
		}

		if len(fields) > 3 {
			pkg.Channel = fields[3]
		}
		if len(fields) > 4 {
			pkg.Publisher = fields[4]
		}
		if len(fields) > 5 {
			notes := fields[5]
			if strings.Contains(notes, "devmode") {
				pkg.DevMode = true
			}
			pkg.Confinement = notes
		}

		packages = append(packages, pkg)
	}

	return packages
}

// GetFlatpakPackages returns installed Flatpak packages.
func (c *Collector) GetFlatpakPackages() (*types.FlatpakPackagesResult, error) {
	flatpak, err := cmdexec.LookPath("flatpak")
	if err != nil {
		return &types.FlatpakPackagesResult{
			Packages:  []types.FlatpakPackage{},
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// #nosec G204 -- flatpak path is from LookPath
	cmd := cmdexec.Command(flatpak, "list", "--columns=name,application,version,branch,origin,arch")
	output, err := cmd.Output()
	if err != nil {
		return &types.FlatpakPackagesResult{
			Packages:  []types.FlatpakPackage{},
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	packages := parseFlatpakOutput(output)
	return &types.FlatpakPackagesResult{
		Packages:  packages,
		Count:     len(packages),
		Timestamp: time.Now(),
	}, nil
}

// parseFlatpakOutput parses flatpak list output.
func parseFlatpakOutput(output []byte) []types.FlatpakPackage {
	var packages []types.FlatpakPackage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}

		pkg := types.FlatpakPackage{
			Name:  strings.TrimSpace(fields[0]),
			AppID: strings.TrimSpace(fields[1]),
		}

		if len(fields) > 2 {
			pkg.Version = strings.TrimSpace(fields[2])
		}
		if len(fields) > 3 {
			pkg.Branch = strings.TrimSpace(fields[3])
		}
		if len(fields) > 4 {
			pkg.Origin = strings.TrimSpace(fields[4])
		}
		if len(fields) > 5 {
			pkg.Arch = strings.TrimSpace(fields[5])
		}

		packages = append(packages, pkg)
	}

	return packages
}

// GetHomebrewCasks returns empty on Linux (macOS only).
func (c *Collector) GetHomebrewCasks() (*types.HomebrewCasksResult, error) {
	return &types.HomebrewCasksResult{
		Casks:     []types.HomebrewCask{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetScoopPackages returns empty on Linux (Windows only).
func (c *Collector) GetScoopPackages() (*types.ScoopPackagesResult, error) {
	return &types.ScoopPackagesResult{
		Packages:  []types.ScoopPackage{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetWindowsPrograms returns empty on Linux (Windows only).
func (c *Collector) GetWindowsPrograms() (*types.WindowsProgramsResult, error) {
	return &types.WindowsProgramsResult{
		Programs:  []types.WindowsProgram{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetWindowsFeatures returns empty on Linux (Windows only).
func (c *Collector) GetWindowsFeatures() (*types.WindowsFeaturesResult, error) {
	return &types.WindowsFeaturesResult{
		Features:  []types.WindowsFeature{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// GetApplications discovers installed and running applications on Linux.
func (c *Collector) GetApplications() (*types.ApplicationsResult, error) {
	result := &types.ApplicationsResult{
		Applications: []types.Application{},
		Timestamp:    time.Now(),
	}

	// Get running processes
	runningProcs := getRunningProcesses()

	// Get systemd services
	services := getSystemdServices()

	// Get listening ports
	listeningPorts := getListeningPorts()

	// Check each known application
	for _, appDef := range GetKnownApplications() {
		app := types.Application{
			Name:        appDef.Name,
			Type:        appDef.Type,
			ConfigPaths: findExistingPaths(appDef.ConfigPaths),
			LogPaths:    findExistingPaths(appDef.LogPaths),
		}

		if appDef.DataDir != "" && fileExists(appDef.DataDir) {
			app.DataDir = appDef.DataDir
		}

		detected := false

		// Check by running process
		for _, procName := range appDef.ProcessName {
			if proc, ok := runningProcs[procName]; ok {
				app.Status = "running"
				app.PID = proc.pid
				app.User = proc.user
				app.BinaryPath = proc.exe
				app.Detected = "process"
				detected = true
				break
			}
		}

		// Check by systemd service
		if !detected {
			for _, serviceName := range appDef.ServiceName {
				if svc, ok := services[serviceName]; ok {
					app.Service = serviceName
					app.Status = svc.status
					if svc.pid > 0 {
						app.PID = int32(svc.pid) // #nosec G115 -- PID checked positive
					}
					app.Detected = "service"
					detected = true
					break
				}
				// Also check with .service suffix
				if svc, ok := services[serviceName+".service"]; ok {
					app.Service = serviceName + ".service"
					app.Status = svc.status
					if svc.pid > 0 {
						app.PID = int32(svc.pid) // #nosec G115 -- PID checked positive
					}
					app.Detected = "service"
					detected = true
					break
				}
			}
		}

		// Check by listening port
		if !detected {
			for _, port := range appDef.Ports {
				if portInfo, ok := listeningPorts[port]; ok {
					app.Port = port
					app.PID = portInfo.pid
					app.Status = "listening"
					app.Detected = "port"
					detected = true
					break
				}
			}
		}

		// Check by config path existence
		if !detected && len(app.ConfigPaths) > 0 {
			app.Status = "installed"
			app.Detected = "config"
			detected = true
		}

		if detected {
			// Try to get version
			if len(appDef.VersionCmd) > 0 {
				app.Version = getAppVersion(appDef.VersionCmd)
			}

			// Collect all listening ports for this app
			for _, port := range appDef.Ports {
				if _, ok := listeningPorts[port]; ok {
					app.Ports = append(app.Ports, port)
				}
			}
			if app.Port == 0 && len(app.Ports) > 0 {
				app.Port = app.Ports[0]
			}

			result.Applications = append(result.Applications, app)
		}
	}

	result.Count = len(result.Applications)
	return result, nil
}

type processInfo struct {
	pid  int32
	user string
	exe  string
}

func getRunningProcesses() map[string]processInfo {
	procs := make(map[string]processInfo)

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return procs
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		// Read comm (process name)
		commPath := filepath.Join("/proc", entry.Name(), "comm")
		commBytes, err := os.ReadFile(commPath) // #nosec G304 -- reading from /proc
		if err != nil {
			continue
		}
		procName := strings.TrimSpace(string(commBytes))

		// Read exe symlink
		exePath := filepath.Join("/proc", entry.Name(), "exe")
		exe, _ := os.Readlink(exePath)

		// Read status for user
		var user string
		statusPath := filepath.Join("/proc", entry.Name(), "status")
		// #nosec G304 -- reading from /proc
		if statusBytes, err := os.ReadFile(statusPath); err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(statusBytes))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						uid, _ := strconv.Atoi(fields[1])
						user = lookupUser(uid)
					}
					break
				}
			}
		}

		procs[procName] = processInfo{
			pid:  int32(pid),
			user: user,
			exe:  exe,
		}
	}

	return procs
}

func lookupUser(uid int) string {
	// Read /etc/passwd to lookup username
	content, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return strconv.Itoa(uid)
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 3 {
			if u, _ := strconv.Atoi(fields[2]); u == uid {
				return fields[0]
			}
		}
	}
	return strconv.Itoa(uid)
}

type serviceInfo struct {
	status string
	pid    int
}

func getSystemdServices() map[string]serviceInfo {
	services := make(map[string]serviceInfo)

	systemctl, err := cmdexec.LookPath("systemctl")
	if err != nil {
		return services
	}

	// List all services
	cmd := cmdexec.Command(systemctl, "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		// Fields: UNIT LOAD ACTIVE SUB DESCRIPTION...
		activeState := fields[2]
		subState := fields[3]

		status := activeState
		if activeState == "active" {
			status = subState // running, exited, etc.
		}

		services[name] = serviceInfo{status: status}
	}

	// Get main PIDs for running services
	for name, svc := range services {
		if svc.status == "running" {
			cmd := cmdexec.Command(systemctl, "show", name, "--property=MainPID", "--value")
			output, err := cmd.Output()
			if err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil && pid > 0 {
					svc.pid = pid
					services[name] = svc
				}
			}
		}
	}

	return services
}

type portInfo struct {
	port int
	pid  int32
}

func getListeningPorts() map[int]portInfo {
	ports := make(map[int]portInfo)

	// Parse /proc/net/tcp and /proc/net/tcp6
	for _, tcpFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		content, err := os.ReadFile(tcpFile) // #nosec G304 -- reading from known /proc paths
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(content))
		_ = scanner.Scan() // Skip header

		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}

			// State 0A = LISTEN
			if fields[3] != "0A" {
				continue
			}

			// Parse local address (format: IP:PORT in hex)
			localAddr := fields[1]
			parts := strings.Split(localAddr, ":")
			if len(parts) != 2 {
				continue
			}

			port64, err := strconv.ParseInt(parts[1], 16, 32)
			if err != nil {
				continue
			}
			port := int(port64)

			// Get inode
			inode := fields[9]

			// Find PID by inode
			pid := findPidByInode(inode)

			ports[port] = portInfo{port: port, pid: int32(pid)} // #nosec G115 -- port values fit in int32
		}
	}

	return ports
}

func findPidByInode(inode string) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	target := "socket:[" + inode + "]"

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				return pid
			}
		}
	}

	return 0
}

func getAppVersion(versionCmd []string) string {
	if len(versionCmd) == 0 {
		return ""
	}

	binary, err := cmdexec.LookPath(versionCmd[0])
	if err != nil {
		return ""
	}

	args := []string{}
	if len(versionCmd) > 1 {
		args = versionCmd[1:]
	}

	cmd := cmdexec.Command(binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}

	// Extract version from output
	outStr := string(output)

	// Common version patterns
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)version[:\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][a-zA-Z0-9.-]*)?)`),
		regexp.MustCompile(`(?i)v?([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+][a-zA-Z0-9.-]*)?)`),
	}

	for _, pattern := range patterns {
		if matches := pattern.FindStringSubmatch(outStr); len(matches) > 1 {
			return matches[1]
		}
	}

	// Return first line trimmed if no pattern matches
	lines := strings.Split(outStr, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}

	return ""
}
