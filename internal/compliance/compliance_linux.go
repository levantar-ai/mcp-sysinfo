//go:build linux
// +build linux

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

// getSecurityScan performs a Linux security vulnerability scan.
func (c *Collector) getSecurityScan() (*types.SecurityScanResult, error) {
	result := &types.SecurityScanResult{
		Timestamp: time.Now(),
	}

	passedChecks := 0

	// Check for world-writable files in system directories
	wwFiles := checkWorldWritableFiles()
	if len(wwFiles) > 0 {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-001",
			Category:    "filesystem",
			Severity:    "medium",
			Title:       "World-writable files found",
			Description: fmt.Sprintf("Found %d world-writable files in system directories", len(wwFiles)),
			Remediation: "Review and fix permissions: chmod o-w <file>",
			References:  []string{"CIS Benchmark 6.1.10"},
		})
	} else {
		passedChecks++
	}

	// Check for SUID/SGID binaries
	suidFiles := checkSUIDFiles()
	if len(suidFiles) > 10 { // Some SUID files are expected
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-002",
			Category:    "filesystem",
			Severity:    "low",
			Title:       "Elevated SUID/SGID binary count",
			Description: fmt.Sprintf("Found %d SUID/SGID binaries", len(suidFiles)),
			Remediation: "Review SUID/SGID binaries and remove unnecessary ones",
			References:  []string{"CIS Benchmark 6.1.13-14"},
		})
	} else {
		passedChecks++
	}

	// Check SSH configuration
	sshFindings := checkSSHConfig()
	result.Findings = append(result.Findings, sshFindings...)
	if len(sshFindings) == 0 {
		passedChecks++
	}

	// Check for unowned files
	if hasUnownedFiles() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-003",
			Category:    "filesystem",
			Severity:    "low",
			Title:       "Unowned files detected",
			Description: "Files exist without valid user/group ownership",
			Remediation: "Assign proper ownership or remove files",
			References:  []string{"CIS Benchmark 6.1.11-12"},
		})
	} else {
		passedChecks++
	}

	// Check password policy
	pwdFindings := checkPasswordPolicy()
	result.Findings = append(result.Findings, pwdFindings...)
	if len(pwdFindings) == 0 {
		passedChecks++
	}

	// Check firewall status
	if !isFirewallActive() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-004",
			Category:    "network",
			Severity:    "high",
			Title:       "Firewall not active",
			Description: "No active firewall detected (iptables/nftables/ufw)",
			Remediation: "Enable and configure firewall: ufw enable or systemctl start firewalld",
			References:  []string{"CIS Benchmark 3.5"},
		})
	} else {
		passedChecks++
	}

	// Check for failed login attempts
	failedLogins := getFailedLoginCount()
	if failedLogins > 100 {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-005",
			Category:    "authentication",
			Severity:    "medium",
			Title:       "High number of failed logins",
			Description: fmt.Sprintf("Detected %d failed login attempts", failedLogins),
			Remediation: "Review auth logs, consider fail2ban, check for brute force attempts",
			References:  []string{"CIS Benchmark 5.4"},
		})
	} else {
		passedChecks++
	}

	// Check for root login enabled
	if isRootLoginEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-006",
			Category:    "authentication",
			Severity:    "medium",
			Title:       "Direct root login enabled",
			Description: "Root account can log in directly",
			Remediation: "Disable direct root login, use sudo instead",
			References:  []string{"CIS Benchmark 5.6"},
		})
	} else {
		passedChecks++
	}

	result.Summary = createSecuritySummary(result.Findings, passedChecks)
	result.Score, result.Grade = calculateSecurityScore(result.Findings)

	return result, nil
}

// getComplianceCheck performs a Linux compliance check.
func (c *Collector) getComplianceCheck(framework string) (*types.ComplianceCheckResult, error) {
	result := &types.ComplianceCheckResult{
		Framework: framework,
		Version:   "1.0",
		Timestamp: time.Now(),
	}

	switch strings.ToLower(framework) {
	case "cis", "cis-benchmark":
		result.Framework = "CIS Linux Benchmark"
		result.Checks = runCISChecks()
	case "pci", "pci-dss":
		result.Framework = "PCI-DSS"
		result.Checks = runPCIChecks()
	case "hipaa":
		result.Framework = "HIPAA"
		result.Checks = runHIPAAChecks()
	default:
		result.Framework = "Basic Security"
		result.Checks = runBasicChecks()
	}

	result.Summary = createComplianceSummary(result.Checks)
	result.Score = calculateComplianceScore(result.Checks)

	return result, nil
}

// getForensicSnapshot collects Linux forensic data.
func (c *Collector) getForensicSnapshot() (*types.ForensicSnapshotResult, error) {
	result := &types.ForensicSnapshotResult{
		SnapshotID:  generateSnapshotID(),
		CollectedAt: time.Now(),
		Timestamp:   time.Now(),
	}

	// Get system info
	result.System = getSystemForensicInfo()

	// Get running processes
	result.Processes = getProcessSnapshot()

	// Get network connections
	result.NetworkConns = getNetworkSnapshot()

	// Get open files
	result.OpenFiles = getOpenFilesSnapshot()

	// Get recent logins
	result.RecentLogins = getRecentLoginSnapshot()

	// Get user info
	result.Users = getUsersSnapshot()

	return result, nil
}

// getAuditTrail retrieves Linux audit events.
func (c *Collector) getAuditTrail(hours int) (*types.AuditTrailResult, error) {
	result := &types.AuditTrailResult{
		TimeRange: getTimeRange(hours),
		Timestamp: time.Now(),
		Sources:   []string{"sshd", "sudo", "systemd", "auditd"},
	}

	// Get authentication events
	result.Events = append(result.Events, getAuthEvents(hours)...)

	// Get sudo events
	result.Events = append(result.Events, getSudoEvents(hours)...)

	// Get service events
	result.Events = append(result.Events, getServiceEvents(hours)...)

	// Get file access events (if auditd is running)
	result.Events = append(result.Events, getAuditdEvents(hours)...)

	result.Count = len(result.Events)

	return result, nil
}

// getHardeningRecommendations provides Linux hardening recommendations.
func (c *Collector) getHardeningRecommendations() (*types.HardeningRecommendationsResult, error) {
	result := &types.HardeningRecommendationsResult{
		Timestamp:     time.Now(),
		Categories:    make(map[string]int),
		PriorityCount: make(map[string]int),
	}

	// Check kernel hardening
	result.Recommendations = append(result.Recommendations, checkKernelHardening()...)

	// Check network hardening
	result.Recommendations = append(result.Recommendations, checkNetworkHardening()...)

	// Check filesystem hardening
	result.Recommendations = append(result.Recommendations, checkFilesystemHardening()...)

	// Check service hardening
	result.Recommendations = append(result.Recommendations, checkServiceHardening()...)

	// Check authentication hardening
	result.Recommendations = append(result.Recommendations, checkAuthHardening()...)

	// Sort by priority and count categories
	sortRecommendations(result.Recommendations)
	for _, rec := range result.Recommendations {
		result.Categories[rec.Category]++
		result.PriorityCount[rec.Priority]++
	}

	return result, nil
}

// Helper functions

func checkWorldWritableFiles() []string {
	var files []string
	// Use find command with limited depth for performance
	out, err := cmdexec.Command("find", "/etc", "-maxdepth", "3", "-type", "f", "-perm", "-002", "-ls").Output()
	if err != nil {
		return files
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			files = append(files, line)
			if len(files) > 50 {
				break
			}
		}
	}
	return files
}

func checkSUIDFiles() []string {
	var files []string
	out, err := cmdexec.Command("find", "/usr", "-type", "f", "-perm", "/4000", "-o", "-perm", "/2000").Output()
	if err != nil {
		return files
	}
	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			files = append(files, line)
		}
	}
	return files
}

func checkSSHConfig() []types.SecurityFinding {
	var findings []types.SecurityFinding

	data, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return findings
	}
	content := string(data)

	// Check PermitRootLogin
	if strings.Contains(content, "PermitRootLogin yes") {
		findings = append(findings, types.SecurityFinding{
			ID:          "SSH-001",
			Category:    "ssh",
			Severity:    "high",
			Title:       "SSH root login enabled",
			Description: "Direct root SSH login is enabled",
			Remediation: "Set PermitRootLogin to 'no' or 'prohibit-password'",
			References:  []string{"CIS Benchmark 5.3.10"},
		})
	}

	// Check PasswordAuthentication
	if !strings.Contains(content, "PasswordAuthentication no") {
		findings = append(findings, types.SecurityFinding{
			ID:          "SSH-002",
			Category:    "ssh",
			Severity:    "medium",
			Title:       "SSH password authentication enabled",
			Description: "Password authentication is enabled for SSH",
			Remediation: "Use key-based authentication and set PasswordAuthentication to 'no'",
			References:  []string{"CIS Benchmark 5.3.12"},
		})
	}

	// Check Protocol version
	if strings.Contains(content, "Protocol 1") {
		findings = append(findings, types.SecurityFinding{
			ID:          "SSH-003",
			Category:    "ssh",
			Severity:    "critical",
			Title:       "SSH Protocol 1 enabled",
			Description: "Insecure SSH Protocol 1 is enabled",
			Remediation: "Remove Protocol 1 or set Protocol to '2'",
			References:  []string{"CIS Benchmark 5.3.1"},
		})
	}

	return findings
}

func hasUnownedFiles() bool {
	out, err := cmdexec.Command("find", "/etc", "-maxdepth", "2", "-nouser", "-o", "-nogroup").Output()
	if err != nil {
		return false
	}
	return len(strings.TrimSpace(string(out))) > 0
}

func checkPasswordPolicy() []types.SecurityFinding {
	var findings []types.SecurityFinding

	// Check /etc/login.defs
	data, err := os.ReadFile("/etc/login.defs")
	if err == nil {
		content := string(data)
		if !strings.Contains(content, "PASS_MAX_DAYS") || strings.Contains(content, "PASS_MAX_DAYS\t99999") {
			findings = append(findings, types.SecurityFinding{
				ID:          "PWD-001",
				Category:    "password",
				Severity:    "medium",
				Title:       "Password expiration not configured",
				Description: "Password maximum age is not properly configured",
				Remediation: "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs",
				References:  []string{"CIS Benchmark 5.5.1.1"},
			})
		}
	}

	return findings
}

func isFirewallActive() bool {
	// Check iptables
	if out, err := cmdexec.Command("iptables", "-L", "-n").Output(); err == nil {
		if strings.Contains(string(out), "Chain INPUT") {
			lines := strings.Split(string(out), "\n")
			ruleCount := 0
			for _, line := range lines {
				if strings.HasPrefix(line, "ACCEPT") || strings.HasPrefix(line, "DROP") || strings.HasPrefix(line, "REJECT") {
					ruleCount++
				}
			}
			if ruleCount > 0 {
				return true
			}
		}
	}

	// Check nftables
	if _, err := cmdexec.Command("nft", "list", "ruleset").Output(); err == nil {
		return true
	}

	// Check ufw
	if out, err := cmdexec.Command("ufw", "status").Output(); err == nil {
		if strings.Contains(string(out), "Status: active") {
			return true
		}
	}

	// Check firewalld
	if out, err := cmdexec.Command("firewall-cmd", "--state").Output(); err == nil {
		if strings.Contains(string(out), "running") {
			return true
		}
	}

	return false
}

func getFailedLoginCount() int {
	out, err := cmdexec.Command("journalctl", "-u", "sshd", "--since", "24 hours ago", "--no-pager").Output()
	if err != nil {
		// Try auth.log
		data, err := os.ReadFile("/var/log/auth.log")
		if err != nil {
			return 0
		}
		return strings.Count(string(data), "Failed password")
	}
	return strings.Count(string(out), "Failed password")
}

func isRootLoginEnabled() bool {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "root:") {
			fields := strings.Split(line, ":")
			if len(fields) >= 7 {
				shell := fields[6]
				// Check if root has a valid shell
				if shell != "/sbin/nologin" && shell != "/bin/false" && shell != "/usr/sbin/nologin" {
					// Check if root password is set
					shadowData, err := os.ReadFile("/etc/shadow")
					if err == nil {
						for _, shadowLine := range strings.Split(string(shadowData), "\n") {
							if strings.HasPrefix(shadowLine, "root:") {
								fields := strings.Split(shadowLine, ":")
								if len(fields) >= 2 {
									pwd := fields[1]
									// If password hash exists and is not locked
									if len(pwd) > 1 && pwd[0] != '!' && pwd[0] != '*' {
										return true
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return false
}

func runCISChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	// 1.1.1 Disable unused filesystems
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-1.1.1",
		Title:       "Disable cramfs filesystem",
		Description: "cramfs filesystem should be disabled",
		Status:      checkModuleDisabled("cramfs"),
		Severity:    "low",
	})

	// 1.4.1 Ensure bootloader password is set
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-1.4.1",
		Title:       "Bootloader password set",
		Description: "GRUB bootloader password should be configured",
		Status:      checkBootloaderPassword(),
		Severity:    "medium",
	})

	// 1.5.1 Ensure core dumps are restricted
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-1.5.1",
		Title:       "Core dumps restricted",
		Description: "Core dumps should be restricted",
		Status:      checkCoreDumpsRestricted(),
		Severity:    "low",
	})

	// 3.1.1 Ensure IP forwarding is disabled
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-3.1.1",
		Title:       "IP forwarding disabled",
		Description: "IPv4 forwarding should be disabled unless required",
		Status:      checkIPForwardingDisabled(),
		Severity:    "medium",
	})

	// 4.1.1 Ensure auditd is installed
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-4.1.1",
		Title:       "Auditd installed",
		Description: "The audit daemon should be installed",
		Status:      checkAuditdInstalled(),
		Severity:    "high",
	})

	// 5.2.1 Ensure sudo is installed
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-5.2.1",
		Title:       "Sudo installed",
		Description: "sudo should be installed for privilege escalation",
		Status:      checkSudoInstalled(),
		Severity:    "medium",
	})

	return checks
}

func runPCIChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	// PCI-DSS 2.2.2 Enable only necessary services
	checks = append(checks, types.ComplianceCheck{
		ID:          "PCI-2.2.2",
		Title:       "Unnecessary services disabled",
		Description: "Only necessary services should be enabled",
		Status:      "manual",
		Severity:    "medium",
	})

	// PCI-DSS 8.1.4 Remove inactive accounts
	checks = append(checks, types.ComplianceCheck{
		ID:          "PCI-8.1.4",
		Title:       "Inactive accounts removed",
		Description: "Inactive user accounts should be removed",
		Status:      checkInactiveAccounts(),
		Severity:    "medium",
	})

	// PCI-DSS 10.2.1 Audit logging
	checks = append(checks, types.ComplianceCheck{
		ID:          "PCI-10.2.1",
		Title:       "Audit logging enabled",
		Description: "Audit logging for user access should be enabled",
		Status:      checkAuditdInstalled(),
		Severity:    "high",
	})

	return checks
}

func runHIPAAChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	// HIPAA 164.312(b) - Audit controls
	checks = append(checks, types.ComplianceCheck{
		ID:          "HIPAA-312b",
		Title:       "Audit controls implemented",
		Description: "System activity audit controls should be in place",
		Status:      checkAuditdInstalled(),
		Severity:    "high",
	})

	// HIPAA 164.312(d) - Person authentication
	checks = append(checks, types.ComplianceCheck{
		ID:          "HIPAA-312d",
		Title:       "Strong authentication",
		Description: "Unique user identification and authentication required",
		Status:      checkStrongAuth(),
		Severity:    "high",
	})

	return checks
}

func runBasicChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-001",
		Title:       "Firewall active",
		Description: "A firewall should be active",
		Status:      boolToStatus(isFirewallActive()),
		Severity:    "high",
	})

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-002",
		Title:       "SSH hardened",
		Description: "SSH should be properly configured",
		Status:      boolToStatus(len(checkSSHConfig()) == 0),
		Severity:    "medium",
	})

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-003",
		Title:       "Automatic updates enabled",
		Description: "Automatic security updates should be enabled",
		Status:      checkAutoUpdates(),
		Severity:    "medium",
	})

	return checks
}

func checkModuleDisabled(module string) string {
	data, err := os.ReadFile("/etc/modprobe.d/blacklist.conf")
	if err != nil {
		return "fail"
	}
	if strings.Contains(string(data), "blacklist "+module) || strings.Contains(string(data), "install "+module+" /bin/true") {
		return "pass"
	}
	return "fail"
}

func checkBootloaderPassword() string {
	files := []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err == nil {
			if strings.Contains(string(data), "password") {
				return "pass"
			}
		}
	}
	return "fail"
}

func checkCoreDumpsRestricted() string {
	data, err := os.ReadFile("/etc/security/limits.conf")
	if err != nil {
		return "fail"
	}
	if strings.Contains(string(data), "hard core 0") {
		return "pass"
	}
	return "fail"
}

func checkIPForwardingDisabled() string {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "fail"
	}
	if strings.TrimSpace(string(data)) == "0" {
		return "pass"
	}
	return "fail"
}

func checkAuditdInstalled() string {
	if _, err := cmdexec.LookPath("auditd"); err == nil {
		return "pass"
	}
	if _, err := cmdexec.LookPath("auditctl"); err == nil {
		return "pass"
	}
	return "fail"
}

func checkSudoInstalled() string {
	if _, err := cmdexec.LookPath("sudo"); err == nil {
		return "pass"
	}
	return "fail"
}

func checkInactiveAccounts() string {
	// Check for accounts that haven't logged in for 90+ days
	out, _ := cmdexec.Command("lastlog", "-b", "90").Output()
	lines := strings.Split(string(out), "\n")
	inactiveCount := 0
	for _, line := range lines[1:] { // Skip header
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "**Never logged in**") {
			inactiveCount++
		}
	}
	if inactiveCount > 5 {
		return "fail"
	}
	return "pass"
}

func checkStrongAuth() string {
	// Check for PAM configuration
	data, err := os.ReadFile("/etc/pam.d/common-auth")
	if err != nil {
		data, err = os.ReadFile("/etc/pam.d/system-auth")
	}
	if err != nil {
		return "fail"
	}
	if strings.Contains(string(data), "pam_unix.so") {
		return "pass"
	}
	return "fail"
}

func checkAutoUpdates() string {
	// Check unattended-upgrades (Debian/Ubuntu)
	if _, err := os.Stat("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		return "pass"
	}
	// Check dnf-automatic (Fedora/RHEL)
	if out, err := cmdexec.Command("systemctl", "is-enabled", "dnf-automatic.timer").Output(); err == nil {
		if strings.TrimSpace(string(out)) == "enabled" {
			return "pass"
		}
	}
	return "fail"
}

func boolToStatus(b bool) string {
	if b {
		return "pass"
	}
	return "fail"
}

func getSystemForensicInfo() types.ForensicSystem {
	info := types.ForensicSystem{}

	// Hostname
	if name, err := os.Hostname(); err == nil {
		info.Hostname = name
	}

	// OS info
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				info.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}
	}

	// Kernel
	if out, err := cmdexec.Command("uname", "-r").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	// Boot time
	if data, err := os.ReadFile("/proc/stat"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "btime ") {
				if btime, err := strconv.ParseInt(strings.Fields(line)[1], 10, 64); err == nil {
					info.BootTime = time.Unix(btime, 0)
				}
			}
		}
	}

	// Uptime
	if out, err := cmdexec.Command("uptime", "-p").Output(); err == nil {
		info.Uptime = strings.TrimSpace(string(out))
	}

	// Timezone
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		info.Timezone = strings.TrimSpace(string(data))
	}

	return info
}

func getProcessSnapshot() []types.ForensicProcess {
	var processes []types.ForensicProcess

	out, err := cmdexec.Command("ps", "aux", "--no-headers").Output()
	if err != nil {
		return processes
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
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

func getNetworkSnapshot() []types.ForensicConnection {
	var connections []types.ForensicConnection

	out, err := cmdexec.Command("ss", "-tunapl").Output()
	if err != nil {
		return connections
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "tcp") || strings.HasPrefix(line, "udp") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				conn := types.ForensicConnection{
					Protocol:  fields[0],
					State:     fields[1],
					LocalAddr: fields[4],
				}
				if len(fields) > 5 {
					conn.RemoteAddr = fields[5]
				}
				if len(fields) > 6 {
					conn.Process = fields[6]
				}
				connections = append(connections, conn)
			}
		}
		if len(connections) >= 100 {
			break
		}
	}

	return connections
}

func getOpenFilesSnapshot() []types.ForensicOpenFile {
	var files []types.ForensicOpenFile

	out, err := cmdexec.Command("lsof", "-n", "-P", "+L1").Output()
	if err != nil {
		return files
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
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

func getUsersSnapshot() []types.ForensicUser {
	var users []types.ForensicUser

	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return users
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 {
			uid, _ := strconv.Atoi(fields[2])
			// Only include user accounts (UID >= 1000 or root)
			if uid >= 1000 || uid == 0 {
				users = append(users, types.ForensicUser{
					Username: fields[0],
					UID:      uid,
					Shell:    fields[6],
					HomeDir:  fields[5],
					IsAdmin:  uid == 0,
				})
			}
		}
	}

	return users
}

func getRecentLoginSnapshot() []types.ForensicLogin {
	var logins []types.ForensicLogin

	out, err := cmdexec.Command("last", "-n", "50", "-F").Output()
	if err != nil {
		return logins
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "wtmp") || strings.HasPrefix(line, "reboot") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			logins = append(logins, types.ForensicLogin{
				Username: fields[0],
				Terminal: fields[1],
				Host:     fields[2],
				Type:     "login",
			})
		}
		if len(logins) >= 50 {
			break
		}
	}

	return logins
}

func getAuthEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	since := fmt.Sprintf("%d hours ago", hours)
	out, err := cmdexec.Command("journalctl", "-u", "sshd", "--since", since, "--no-pager", "-o", "short").Output()
	if err != nil {
		return events
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Accepted") {
			events = append(events, types.AuditEvent{
				Type:     "auth",
				Action:   "login",
				Result:   "success",
				Source:   "sshd",
				Details:  line,
				Severity: "info",
			})
		} else if strings.Contains(line, "Failed") {
			events = append(events, types.AuditEvent{
				Type:     "auth",
				Action:   "login",
				Result:   "failure",
				Source:   "sshd",
				Details:  line,
				Severity: "warning",
			})
		}
		if len(events) >= 100 {
			break
		}
	}

	return events
}

func getSudoEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	since := fmt.Sprintf("%d hours ago", hours)
	out, _ := cmdexec.Command("journalctl", "--since", since, "--no-pager", "-o", "short", "_COMM=sudo").Output()

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		events = append(events, types.AuditEvent{
			Type:     "privilege",
			Action:   "sudo",
			Source:   "sudo",
			Details:  scanner.Text(),
			Severity: "info",
		})
		if len(events) >= 50 {
			break
		}
	}

	return events
}

func getServiceEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	since := fmt.Sprintf("%d hours ago", hours)
	out, _ := cmdexec.Command("journalctl", "--since", since, "--no-pager", "-o", "short", "-p", "warning..err").Output()

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		events = append(events, types.AuditEvent{
			Type:     "system",
			Action:   "service",
			Source:   "systemd",
			Details:  scanner.Text(),
			Severity: "warning",
		})
		if len(events) >= 50 {
			break
		}
	}

	return events
}

func getAuditdEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	// Check if ausearch is available
	if _, err := cmdexec.LookPath("ausearch"); err != nil {
		return events
	}

	startTime := time.Now().Add(-time.Duration(hours) * time.Hour)
	start := startTime.Format("01/02/2006 15:04:05")

	out, _ := cmdexec.Command("ausearch", "-ts", start, "-m", "USER_AUTH,USER_LOGIN,USER_CMD").Output()

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "type=") {
			events = append(events, types.AuditEvent{
				Type:     "audit",
				Action:   "audit_event",
				Source:   "auditd",
				Details:  line,
				Severity: "info",
			})
		}
		if len(events) >= 100 {
			break
		}
	}

	return events
}

func checkKernelHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check ASLR
	data, _ := os.ReadFile("/proc/sys/kernel/randomize_va_space")
	if strings.TrimSpace(string(data)) != "2" {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "KERN-001",
			Title:        "Enable full ASLR",
			Category:     "kernel",
			Priority:     "high",
			Description:  "Address Space Layout Randomization should be fully enabled",
			CurrentState: fmt.Sprintf("randomize_va_space = %s", strings.TrimSpace(string(data))),
			TargetState:  "randomize_va_space = 2",
			Remediation:  "Add 'kernel.randomize_va_space = 2' to /etc/sysctl.conf",
			Commands:     []string{"echo 2 > /proc/sys/kernel/randomize_va_space", "sysctl -w kernel.randomize_va_space=2"},
		})
	}

	// Check ptrace scope
	data, _ = os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if strings.TrimSpace(string(data)) == "0" {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "KERN-002",
			Title:        "Restrict ptrace",
			Category:     "kernel",
			Priority:     "medium",
			Description:  "Restrict ptrace to prevent process debugging by non-root users",
			CurrentState: "ptrace_scope = 0",
			TargetState:  "ptrace_scope = 1",
			Remediation:  "Add 'kernel.yama.ptrace_scope = 1' to /etc/sysctl.conf",
			Commands:     []string{"echo 1 > /proc/sys/kernel/yama/ptrace_scope"},
		})
	}

	return recs
}

func checkNetworkHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check SYN cookies
	data, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_syncookies")
	if strings.TrimSpace(string(data)) != "1" {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "NET-001",
			Title:        "Enable SYN cookies",
			Category:     "network",
			Priority:     "high",
			Description:  "Enable TCP SYN cookies to prevent SYN flood attacks",
			CurrentState: fmt.Sprintf("tcp_syncookies = %s", strings.TrimSpace(string(data))),
			TargetState:  "tcp_syncookies = 1",
			Remediation:  "Add 'net.ipv4.tcp_syncookies = 1' to /etc/sysctl.conf",
			Commands:     []string{"sysctl -w net.ipv4.tcp_syncookies=1"},
		})
	}

	// Check ICMP redirects
	data, _ = os.ReadFile("/proc/sys/net/ipv4/conf/all/accept_redirects")
	if strings.TrimSpace(string(data)) != "0" {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "NET-002",
			Title:        "Disable ICMP redirects",
			Category:     "network",
			Priority:     "medium",
			Description:  "Disable accepting ICMP redirects to prevent MITM attacks",
			CurrentState: "accept_redirects = 1",
			TargetState:  "accept_redirects = 0",
			Remediation:  "Add 'net.ipv4.conf.all.accept_redirects = 0' to /etc/sysctl.conf",
			Commands:     []string{"sysctl -w net.ipv4.conf.all.accept_redirects=0"},
		})
	}

	return recs
}

func checkFilesystemHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check /tmp mount options
	data, _ := os.ReadFile("/proc/mounts")
	if !strings.Contains(string(data), "/tmp") || !strings.Contains(string(data), "noexec") {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "FS-001",
			Title:        "Mount /tmp with noexec",
			Category:     "filesystem",
			Priority:     "medium",
			Description:  "Mount /tmp with noexec,nosuid,nodev options",
			CurrentState: "/tmp may allow execution",
			TargetState:  "/tmp mounted with noexec,nosuid,nodev",
			Remediation:  "Add 'noexec,nosuid,nodev' options to /tmp in /etc/fstab",
		})
	}

	return recs
}

func checkServiceHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check for unnecessary services
	riskyServices := []string{"telnet", "rsh", "rlogin", "tftp"}
	for _, svc := range riskyServices {
		out, _ := cmdexec.Command("systemctl", "is-enabled", svc).Output()
		if strings.TrimSpace(string(out)) == "enabled" {
			recs = append(recs, types.HardeningRecommendation{
				ID:           "SVC-001",
				Title:        fmt.Sprintf("Disable %s service", svc),
				Category:     "services",
				Priority:     "high",
				Description:  fmt.Sprintf("Insecure service %s is enabled", svc),
				CurrentState: "enabled",
				TargetState:  "disabled",
				Remediation:  fmt.Sprintf("Disable the %s service", svc),
				Commands:     []string{fmt.Sprintf("systemctl disable --now %s", svc)},
			})
		}
	}

	return recs
}

func checkAuthHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check for empty passwords
	data, err := os.ReadFile("/etc/shadow")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) >= 2 && fields[1] == "" {
				recs = append(recs, types.HardeningRecommendation{
					ID:           "AUTH-001",
					Title:        "Remove empty passwords",
					Category:     "authentication",
					Priority:     "critical",
					Description:  fmt.Sprintf("User %s has an empty password", fields[0]),
					CurrentState: "empty password",
					TargetState:  "password set or account locked",
					Remediation:  fmt.Sprintf("Lock the %s account or set a password", fields[0]),
					Commands:     []string{fmt.Sprintf("passwd -l %s", fields[0])},
				})
			}
		}
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

func safeGet(slice []string, index int) string {
	if index < len(slice) {
		return slice[index]
	}
	return ""
}
