//go:build darwin
// +build darwin

package compliance

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getSecurityScan performs a macOS security vulnerability scan.
func (c *Collector) getSecurityScan() (*types.SecurityScanResult, error) {
	result := &types.SecurityScanResult{
		Timestamp: time.Now(),
	}

	passedChecks := 0

	// Check SIP status
	if !isSIPEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-001",
			Category:    "system",
			Severity:    "critical",
			Title:       "System Integrity Protection disabled",
			Description: "SIP is disabled, which allows modifications to protected system files",
			Remediation: "Enable SIP by booting to Recovery Mode and running 'csrutil enable'",
			References:  []string{"Apple Security Guide"},
		})
	} else {
		passedChecks++
	}

	// Check Gatekeeper status
	if !isGatekeeperEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-002",
			Category:    "system",
			Severity:    "high",
			Title:       "Gatekeeper disabled",
			Description: "Gatekeeper is disabled, allowing unsigned apps to run",
			Remediation: "Enable Gatekeeper: sudo spctl --master-enable",
			References:  []string{"Apple Security Guide"},
		})
	} else {
		passedChecks++
	}

	// Check FileVault status
	if !isFileVaultEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-003",
			Category:    "encryption",
			Severity:    "high",
			Title:       "FileVault not enabled",
			Description: "Disk encryption is not enabled",
			Remediation: "Enable FileVault in System Preferences > Security & Privacy",
			References:  []string{"CIS macOS Benchmark 2.5.1"},
		})
	} else {
		passedChecks++
	}

	// Check Firewall status
	if !isFirewallEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-004",
			Category:    "network",
			Severity:    "medium",
			Title:       "Firewall not enabled",
			Description: "macOS firewall is not enabled",
			Remediation: "Enable firewall in System Preferences > Security & Privacy > Firewall",
			References:  []string{"CIS macOS Benchmark 2.2.1"},
		})
	} else {
		passedChecks++
	}

	// Check automatic updates
	if !isAutoUpdateEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-005",
			Category:    "updates",
			Severity:    "medium",
			Title:       "Automatic updates not enabled",
			Description: "System is not configured for automatic security updates",
			Remediation: "Enable automatic updates in System Preferences > Software Update",
			References:  []string{"CIS macOS Benchmark 1.2"},
		})
	} else {
		passedChecks++
	}

	// Check remote login (SSH)
	if isRemoteLoginEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-006",
			Category:    "network",
			Severity:    "low",
			Title:       "Remote Login (SSH) enabled",
			Description: "SSH access is enabled - ensure this is intentional",
			Remediation: "If not needed, disable in System Preferences > Sharing",
			References:  []string{"CIS macOS Benchmark 2.3.3.6"},
		})
	} else {
		passedChecks++
	}

	// Check screen lock
	if !isScreenLockEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-007",
			Category:    "physical",
			Severity:    "medium",
			Title:       "Screen lock not configured",
			Description: "Immediate screen lock on sleep/screen saver not enabled",
			Remediation: "Configure in System Preferences > Security & Privacy > General",
			References:  []string{"CIS macOS Benchmark 2.5.4"},
		})
	} else {
		passedChecks++
	}

	result.Summary = createSecuritySummary(result.Findings, passedChecks)
	result.Score, result.Grade = calculateSecurityScore(result.Findings)

	return result, nil
}

// getComplianceCheck performs a macOS compliance check.
func (c *Collector) getComplianceCheck(framework string) (*types.ComplianceCheckResult, error) {
	result := &types.ComplianceCheckResult{
		Framework: framework,
		Version:   "1.0",
		Timestamp: time.Now(),
	}

	switch strings.ToLower(framework) {
	case "cis", "cis-benchmark":
		result.Framework = "CIS macOS Benchmark"
		result.Checks = runMacOSCISChecks()
	case "apple":
		result.Framework = "Apple Security Guidelines"
		result.Checks = runAppleSecurityChecks()
	default:
		result.Framework = "Basic Security"
		result.Checks = runMacOSBasicChecks()
	}

	result.Summary = createComplianceSummary(result.Checks)
	result.Score = calculateComplianceScore(result.Checks)

	return result, nil
}

// getForensicSnapshot collects macOS forensic data.
func (c *Collector) getForensicSnapshot() (*types.ForensicSnapshotResult, error) {
	result := &types.ForensicSnapshotResult{
		SnapshotID:  generateSnapshotID(),
		CollectedAt: time.Now(),
		Timestamp:   time.Now(),
	}

	// Get system info
	result.System = getMacOSSystemInfo()

	// Get running processes
	result.Processes = getMacOSProcessSnapshot()

	// Get network connections
	result.NetworkConns = getMacOSNetworkSnapshot()

	// Get open files
	result.OpenFiles = getMacOSOpenFilesSnapshot()

	// Get recent logins
	result.RecentLogins = getMacOSRecentLoginSnapshot()

	// Get users
	result.Users = getMacOSUsersSnapshot()

	return result, nil
}

// getAuditTrail retrieves macOS audit events.
func (c *Collector) getAuditTrail(hours int) (*types.AuditTrailResult, error) {
	result := &types.AuditTrailResult{
		TimeRange: getTimeRange(hours),
		Timestamp: time.Now(),
		Sources:   []string{"Authorization", "sudo", "installer"},
	}

	// Get authentication events
	result.Events = append(result.Events, getMacOSAuthEvents(hours)...)

	// Get sudo events
	result.Events = append(result.Events, getMacOSSudoEvents(hours)...)

	// Get install events
	result.Events = append(result.Events, getMacOSInstallEvents(hours)...)

	result.Count = len(result.Events)

	return result, nil
}

// getHardeningRecommendations provides macOS hardening recommendations.
func (c *Collector) getHardeningRecommendations() (*types.HardeningRecommendationsResult, error) {
	result := &types.HardeningRecommendationsResult{
		Timestamp:     time.Now(),
		Categories:    make(map[string]int),
		PriorityCount: make(map[string]int),
	}

	// Check system hardening
	result.Recommendations = append(result.Recommendations, checkMacOSSystemHardening()...)

	// Check network hardening
	result.Recommendations = append(result.Recommendations, checkMacOSNetworkHardening()...)

	// Check privacy hardening
	result.Recommendations = append(result.Recommendations, checkMacOSPrivacyHardening()...)

	// Check application hardening
	result.Recommendations = append(result.Recommendations, checkMacOSAppHardening()...)

	// Sort by priority and count categories
	sortRecommendations(result.Recommendations)
	for _, rec := range result.Recommendations {
		result.Categories[rec.Category]++
		result.PriorityCount[rec.Priority]++
	}

	return result, nil
}

// Helper functions

func isSIPEnabled() bool {
	out, err := cmdexec.Command("csrutil", "status").Output()
	if err != nil {
		return true // Assume enabled if we can't check
	}
	return strings.Contains(string(out), "enabled")
}

func isGatekeeperEnabled() bool {
	out, err := cmdexec.Command("spctl", "--status").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "assessments enabled")
}

func isFileVaultEnabled() bool {
	out, err := cmdexec.Command("fdesetup", "status").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "FileVault is On")
}

func isFirewallEnabled() bool {
	out, err := cmdexec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "enabled")
}

func isAutoUpdateEnabled() bool {
	out, err := cmdexec.Command("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "1"
}

func isRemoteLoginEnabled() bool {
	out, err := cmdexec.Command("systemsetup", "-getremotelogin").Output()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "on")
}

func isScreenLockEnabled() bool {
	out, err := cmdexec.Command("defaults", "read", "com.apple.screensaver", "askForPassword").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "1"
}

func runMacOSCISChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	// 1.1 Verify all Apple provided software is current
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-1.1",
		Title:       "Software updates current",
		Description: "All Apple provided software should be current",
		Status:      checkSoftwareUpdateStatus(),
		Severity:    "high",
	})

	// 2.2.1 Enable Firewall
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-2.2.1",
		Title:       "Firewall enabled",
		Description: "The macOS firewall should be enabled",
		Status:      boolToStatus(isFirewallEnabled()),
		Severity:    "high",
	})

	// 2.4.1 Disable Remote Apple Events
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-2.4.1",
		Title:       "Remote Apple Events disabled",
		Description: "Remote Apple Events should be disabled",
		Status:      checkRemoteAppleEventsDisabled(),
		Severity:    "medium",
	})

	// 2.5.1 Enable FileVault
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-2.5.1",
		Title:       "FileVault enabled",
		Description: "FileVault disk encryption should be enabled",
		Status:      boolToStatus(isFileVaultEnabled()),
		Severity:    "high",
	})

	// 2.5.2 Enable Gatekeeper
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-2.5.2",
		Title:       "Gatekeeper enabled",
		Description: "Gatekeeper should be enabled",
		Status:      boolToStatus(isGatekeeperEnabled()),
		Severity:    "high",
	})

	// 5.1.1 Secure Home Folders
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-5.1.1",
		Title:       "Secure home folders",
		Description: "Home folders should have appropriate permissions",
		Status:      checkHomeFolderPermissions(),
		Severity:    "medium",
	})

	// 6.1.1 Display login window as name and password
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-6.1.1",
		Title:       "Login window security",
		Description: "Login window should prompt for username and password",
		Status:      checkLoginWindowConfig(),
		Severity:    "low",
	})

	return checks
}

func runAppleSecurityChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	// SIP Status
	checks = append(checks, types.ComplianceCheck{
		ID:          "APPLE-001",
		Title:       "System Integrity Protection",
		Description: "SIP should be enabled",
		Status:      boolToStatus(isSIPEnabled()),
		Severity:    "critical",
	})

	// XProtect
	checks = append(checks, types.ComplianceCheck{
		ID:          "APPLE-002",
		Title:       "XProtect enabled",
		Description: "XProtect malware protection should be active",
		Status:      checkXProtectStatus(),
		Severity:    "high",
	})

	// Secure Boot
	checks = append(checks, types.ComplianceCheck{
		ID:          "APPLE-003",
		Title:       "Secure Boot",
		Description: "Secure Boot should be enabled on supported hardware",
		Status:      checkSecureBoot(),
		Severity:    "medium",
	})

	return checks
}

func runMacOSBasicChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-001",
		Title:       "SIP enabled",
		Description: "System Integrity Protection enabled",
		Status:      boolToStatus(isSIPEnabled()),
		Severity:    "critical",
	})

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-002",
		Title:       "FileVault enabled",
		Description: "Disk encryption enabled",
		Status:      boolToStatus(isFileVaultEnabled()),
		Severity:    "high",
	})

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-003",
		Title:       "Firewall enabled",
		Description: "Firewall protection enabled",
		Status:      boolToStatus(isFirewallEnabled()),
		Severity:    "high",
	})

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-004",
		Title:       "Gatekeeper enabled",
		Description: "App signing verification enabled",
		Status:      boolToStatus(isGatekeeperEnabled()),
		Severity:    "high",
	})

	return checks
}

func checkSoftwareUpdateStatus() string {
	out, err := cmdexec.Command("softwareupdate", "-l").Output()
	if err != nil {
		return "fail"
	}
	if strings.Contains(string(out), "No new software available") {
		return "pass"
	}
	return "fail"
}

func checkRemoteAppleEventsDisabled() string {
	out, err := cmdexec.Command("systemsetup", "-getremoteappleevents").Output()
	if err != nil {
		return "fail"
	}
	if strings.Contains(strings.ToLower(string(out)), "off") {
		return "pass"
	}
	return "fail"
}

func checkHomeFolderPermissions() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "fail"
	}
	info, err := os.Stat(homeDir)
	if err != nil {
		return "fail"
	}
	// Check if group/other have no write access
	mode := info.Mode()
	if mode&0022 == 0 {
		return "pass"
	}
	return "fail"
}

func checkLoginWindowConfig() string {
	out, err := cmdexec.Command("defaults", "read", "/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME").Output()
	if err != nil {
		return "fail"
	}
	if strings.TrimSpace(string(out)) == "1" {
		return "pass"
	}
	return "fail"
}

func checkXProtectStatus() string {
	// XProtect is always on in modern macOS
	if _, err := os.Stat("/Library/Apple/System/Library/CoreServices/XProtect.bundle"); err == nil {
		return "pass"
	}
	return "fail"
}

func checkSecureBoot() string {
	// Check if running on Apple Silicon or T2 chip
	out, err := cmdexec.Command("system_profiler", "SPiBridgeDataType").Output()
	if err != nil {
		return "skip"
	}
	if strings.Contains(string(out), "Secure Boot") {
		return "pass"
	}
	return "skip"
}

func getMacOSSystemInfo() types.ForensicSystem {
	info := types.ForensicSystem{}

	// Hostname
	if name, err := os.Hostname(); err == nil {
		info.Hostname = name
	}

	// OS info
	if out, err := cmdexec.Command("sw_vers", "-productVersion").Output(); err == nil {
		info.OS = "macOS " + strings.TrimSpace(string(out))
	}

	// Kernel
	if out, err := cmdexec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	// Boot time
	if out, err := cmdexec.Command("sysctl", "-n", "kern.boottime").Output(); err == nil {
		// Parse boottime format: { sec = 1234567890, usec = 123456 }
		str := string(out)
		if idx := strings.Index(str, "sec = "); idx >= 0 {
			str = str[idx+6:]
			if endIdx := strings.Index(str, ","); endIdx >= 0 {
				if sec, err := strconv.ParseInt(str[:endIdx], 10, 64); err == nil {
					info.BootTime = time.Unix(sec, 0)
				}
			}
		}
	}

	// Uptime
	if out, err := cmdexec.Command("uptime").Output(); err == nil {
		info.Uptime = strings.TrimSpace(string(out))
	}

	// Timezone
	if out, err := cmdexec.Command("systemsetup", "-gettimezone").Output(); err == nil {
		info.Timezone = strings.TrimSpace(strings.TrimPrefix(string(out), "Time Zone:"))
	}

	return info
}

func getMacOSProcessSnapshot() []types.ForensicProcess {
	var processes []types.ForensicProcess

	out, err := cmdexec.Command("ps", "aux").Output()
	if err != nil {
		return processes
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 11 {
			pid, _ := strconv.ParseInt(fields[1], 10, 32)
			cpu, _ := strconv.ParseFloat(fields[2], 64)
			mem, _ := strconv.ParseFloat(fields[3], 32)
			processes = append(processes, types.ForensicProcess{
				PID:        int32(pid),
				User:       fields[0],
				CPUPercent: cpu,
				MemPercent: float32(mem),
				Name:       fields[10],
				Cmdline:    strings.Join(fields[10:], " "),
			})
		}
		if len(processes) >= 100 {
			break
		}
	}

	return processes
}

func getMacOSNetworkSnapshot() []types.ForensicConnection {
	var connections []types.ForensicConnection

	out, err := cmdexec.Command("netstat", "-anvp", "tcp").Output()
	if err != nil {
		return connections
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 6 && (strings.HasPrefix(fields[0], "tcp") || fields[0] == "tcp4" || fields[0] == "tcp6") {
			connections = append(connections, types.ForensicConnection{
				Protocol:   fields[0],
				LocalAddr:  safeGet(fields, 3),
				RemoteAddr: safeGet(fields, 4),
				State:      safeGet(fields, 5),
			})
		}
		if len(connections) >= 100 {
			break
		}
	}

	return connections
}

func getMacOSOpenFilesSnapshot() []types.ForensicOpenFile {
	var files []types.ForensicOpenFile

	out, err := cmdexec.Command("lsof", "-n", "-P", "+L1").Output()
	if err != nil {
		return files
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 9 {
			pid, _ := strconv.ParseInt(fields[1], 10, 32)
			files = append(files, types.ForensicOpenFile{
				Process: fields[0],
				PID:     int32(pid),
				Type:    fields[4],
				Path:    safeGet(fields, 8),
			})
		}
		if len(files) >= 100 {
			break
		}
	}

	return files
}

func getMacOSUsersSnapshot() []types.ForensicUser {
	var users []types.ForensicUser

	// Get user list from dscl
	out, err := cmdexec.Command("dscl", ".", "-list", "/Users").Output()
	if err != nil {
		return users
	}

	for _, username := range strings.Split(string(out), "\n") {
		username = strings.TrimSpace(username)
		if username == "" || strings.HasPrefix(username, "_") {
			continue
		}

		user := types.ForensicUser{Username: username}

		// Get UID
		if uidOut, err := cmdexec.Command("dscl", ".", "-read", "/Users/"+username, "UniqueID").Output(); err == nil {
			parts := strings.Split(strings.TrimSpace(string(uidOut)), " ")
			if len(parts) >= 2 {
				uid, _ := strconv.Atoi(parts[len(parts)-1])
				user.UID = uid
			}
		}

		// Get home directory
		if homeOut, err := cmdexec.Command("dscl", ".", "-read", "/Users/"+username, "NFSHomeDirectory").Output(); err == nil {
			parts := strings.Split(strings.TrimSpace(string(homeOut)), " ")
			if len(parts) >= 2 {
				user.HomeDir = parts[len(parts)-1]
			}
		}

		// Get shell
		if shellOut, err := cmdexec.Command("dscl", ".", "-read", "/Users/"+username, "UserShell").Output(); err == nil {
			parts := strings.Split(strings.TrimSpace(string(shellOut)), " ")
			if len(parts) >= 2 {
				user.Shell = parts[len(parts)-1]
			}
		}

		// Check if admin
		if groupOut, err := cmdexec.Command("dscl", ".", "-read", "/Groups/admin", "GroupMembership").Output(); err == nil {
			user.IsAdmin = strings.Contains(string(groupOut), username)
		}

		users = append(users, user)
	}

	return users
}

func getMacOSRecentLoginSnapshot() []types.ForensicLogin {
	var logins []types.ForensicLogin

	out, err := cmdexec.Command("last", "-50").Output()
	if err != nil {
		return logins
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "wtmp") || strings.HasPrefix(line, "reboot") || strings.HasPrefix(line, "shutdown") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			logins = append(logins, types.ForensicLogin{
				Username: fields[0],
				Terminal: fields[1],
				Host:     safeGet(fields, 2),
				Type:     "login",
			})
		}
		if len(logins) >= 50 {
			break
		}
	}

	return logins
}

func getMacOSAuthEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	// Use log show for authentication events
	start := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05")
	out, err := cmdexec.Command("log", "show", "--predicate", "subsystem == 'com.apple.Authorization'", "--start", start, "--style", "compact").Output()
	if err != nil {
		return events
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "Filtering") {
			events = append(events, types.AuditEvent{
				Type:     "auth",
				Action:   "authorization",
				Source:   "Authorization",
				Details:  line,
				Severity: "info",
			})
		}
		if len(events) >= 50 {
			break
		}
	}

	return events
}

func getMacOSSudoEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	start := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05")
	out, _ := cmdexec.Command("log", "show", "--predicate", "process == 'sudo'", "--start", start, "--style", "compact").Output()

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "Filtering") {
			events = append(events, types.AuditEvent{
				Type:     "privilege",
				Action:   "sudo",
				Source:   "sudo",
				Details:  line,
				Severity: "info",
			})
		}
		if len(events) >= 50 {
			break
		}
	}

	return events
}

func getMacOSInstallEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	start := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05")
	out, _ := cmdexec.Command("log", "show", "--predicate", "subsystem == 'com.apple.installer'", "--start", start, "--style", "compact").Output()

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "Filtering") {
			events = append(events, types.AuditEvent{
				Type:     "system",
				Action:   "install",
				Source:   "installer",
				Details:  line,
				Severity: "info",
			})
		}
		if len(events) >= 25 {
			break
		}
	}

	return events
}

func checkMacOSSystemHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check SIP
	if !isSIPEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "SYS-001",
			Title:        "Enable System Integrity Protection",
			Category:     "system",
			Priority:     "critical",
			Description:  "SIP provides protection against malware and system modifications",
			CurrentState: "disabled",
			TargetState:  "enabled",
			Remediation:  "Boot to Recovery Mode and run: csrutil enable",
		})
	}

	// Check Gatekeeper
	if !isGatekeeperEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "SYS-002",
			Title:        "Enable Gatekeeper",
			Category:     "system",
			Priority:     "high",
			Description:  "Gatekeeper verifies app signatures before allowing execution",
			CurrentState: "disabled",
			TargetState:  "enabled",
			Remediation:  "Enable Gatekeeper via Security preferences or spctl command",
			Commands:     []string{"sudo spctl --master-enable"},
		})
	}

	return recs
}

func checkMacOSNetworkHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check Firewall
	if !isFirewallEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "NET-001",
			Title:        "Enable macOS Firewall",
			Category:     "network",
			Priority:     "high",
			Description:  "The built-in firewall should be enabled for network protection",
			CurrentState: "disabled",
			TargetState:  "enabled",
			Remediation:  "Enable firewall via Security & Privacy preferences or socketfilterfw command",
			Commands:     []string{"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"},
		})
	}

	// Check Stealth Mode
	out, _ := cmdexec.Command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode").Output()
	if !strings.Contains(string(out), "enabled") {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "NET-002",
			Title:        "Enable Firewall Stealth Mode",
			Category:     "network",
			Priority:     "medium",
			Description:  "Stealth mode prevents responding to probing requests",
			CurrentState: "disabled",
			TargetState:  "enabled",
			Remediation:  "Enable stealth mode via socketfilterfw command",
			Commands:     []string{"sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"},
		})
	}

	return recs
}

func checkMacOSPrivacyHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check FileVault
	if !isFileVaultEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "PRIV-001",
			Title:        "Enable FileVault",
			Category:     "encryption",
			Priority:     "high",
			Description:  "Full disk encryption protects data if device is lost or stolen",
			CurrentState: "disabled",
			TargetState:  "enabled",
			Remediation:  "Enable FileVault via Security & Privacy preferences or fdesetup command",
			Commands:     []string{"sudo fdesetup enable"},
		})
	}

	// Check Screen Lock
	if !isScreenLockEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "PRIV-002",
			Title:        "Enable immediate screen lock",
			Category:     "physical",
			Priority:     "medium",
			Description:  "Require password immediately after sleep or screen saver",
			CurrentState: "disabled or delayed",
			TargetState:  "immediate",
			Remediation:  "Configure via defaults command or Security & Privacy preferences",
			Commands:     []string{"defaults write com.apple.screensaver askForPassword -int 1"},
		})
	}

	return recs
}

func checkMacOSAppHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check for Safari safe downloads
	out, _ := cmdexec.Command("defaults", "read", "com.apple.Safari", "AutoOpenSafeDownloads").Output()
	if strings.TrimSpace(string(out)) == "1" {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "APP-001",
			Title:        "Disable Safari auto-open downloads",
			Category:     "application",
			Priority:     "medium",
			Description:  "Safari should not automatically open 'safe' downloads",
			CurrentState: "enabled",
			TargetState:  "disabled",
			Remediation:  "Disable via defaults command or Safari preferences",
			Commands:     []string{"defaults write com.apple.Safari AutoOpenSafeDownloads -bool false"},
		})
	}

	return recs
}

func sortRecommendations(recs []types.HardeningRecommendation) {
	priorityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	for i := 0; i < len(recs)-1; i++ {
		for j := i + 1; j < len(recs); j++ {
			if priorityOrder[recs[i].Priority] > priorityOrder[recs[j].Priority] {
				recs[i], recs[j] = recs[j], recs[i]
			}
		}
	}
}

func boolToStatus(b bool) string {
	if b {
		return "pass"
	}
	return "fail"
}

func safeGet(slice []string, index int) string {
	if index < len(slice) {
		return slice[index]
	}
	return ""
}
