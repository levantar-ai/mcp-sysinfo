//go:build windows
// +build windows

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

// getSecurityScan performs a Windows security vulnerability scan.
func (c *Collector) getSecurityScan() (*types.SecurityScanResult, error) {
	result := &types.SecurityScanResult{
		Timestamp: time.Now(),
	}

	passedChecks := 0

	// Check Windows Defender status
	if !isDefenderEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-001",
			Category:    "antivirus",
			Severity:    "critical",
			Title:       "Windows Defender not active",
			Description: "Windows Defender real-time protection is not enabled",
			Remediation: "Enable Windows Defender in Windows Security settings",
			References:  []string{"CIS Windows Benchmark 18.9.45"},
		})
	} else {
		passedChecks++
	}

	// Check Windows Firewall status
	if !isWindowsFirewallEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-002",
			Category:    "network",
			Severity:    "high",
			Title:       "Windows Firewall not enabled",
			Description: "Windows Firewall is not enabled for all profiles",
			Remediation: "Enable Windows Firewall in Control Panel or via netsh",
			References:  []string{"CIS Windows Benchmark 9.1"},
		})
	} else {
		passedChecks++
	}

	// Check UAC status
	if !isUACEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-003",
			Category:    "authentication",
			Severity:    "high",
			Title:       "User Account Control disabled",
			Description: "UAC is disabled, reducing protection against unauthorized changes",
			Remediation: "Enable UAC in Control Panel > User Accounts",
			References:  []string{"CIS Windows Benchmark 2.3.17"},
		})
	} else {
		passedChecks++
	}

	// Check BitLocker status
	if !isBitLockerEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-004",
			Category:    "encryption",
			Severity:    "medium",
			Title:       "BitLocker not enabled",
			Description: "BitLocker disk encryption is not enabled on the system drive",
			Remediation: "Enable BitLocker in Control Panel > BitLocker Drive Encryption",
			References:  []string{"CIS Windows Benchmark 18.9.11"},
		})
	} else {
		passedChecks++
	}

	// Check Windows Update status
	if !isWindowsUpdateEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-005",
			Category:    "updates",
			Severity:    "high",
			Title:       "Automatic updates not configured",
			Description: "Windows Update is not configured for automatic updates",
			Remediation: "Configure Windows Update for automatic downloads and installation",
			References:  []string{"CIS Windows Benchmark 18.9.101"},
		})
	} else {
		passedChecks++
	}

	// Check Remote Desktop status
	if isRDPEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-006",
			Category:    "network",
			Severity:    "medium",
			Title:       "Remote Desktop enabled",
			Description: "Remote Desktop is enabled - ensure this is intentional and properly secured",
			Remediation: "Disable RDP if not needed, or ensure NLA is required",
			References:  []string{"CIS Windows Benchmark 18.9.59"},
		})
	} else {
		passedChecks++
	}

	// Check Guest account status
	if isGuestAccountEnabled() {
		result.Findings = append(result.Findings, types.SecurityFinding{
			ID:          "SEC-007",
			Category:    "authentication",
			Severity:    "medium",
			Title:       "Guest account enabled",
			Description: "The Guest account is enabled",
			Remediation: "Disable the Guest account: net user Guest /active:no",
			References:  []string{"CIS Windows Benchmark 1.1.1"},
		})
	} else {
		passedChecks++
	}

	result.Summary = createSecuritySummary(result.Findings, passedChecks)
	result.Score, result.Grade = calculateSecurityScore(result.Findings)

	return result, nil
}

// getComplianceCheck performs a Windows compliance check.
func (c *Collector) getComplianceCheck(framework string) (*types.ComplianceCheckResult, error) {
	result := &types.ComplianceCheckResult{
		Framework: framework,
		Version:   "1.0",
		Timestamp: time.Now(),
	}

	switch strings.ToLower(framework) {
	case "cis", "cis-benchmark":
		result.Framework = "CIS Windows Benchmark"
		result.Checks = runWindowsCISChecks()
	case "stig":
		result.Framework = "Windows STIG"
		result.Checks = runWindowsSTIGChecks()
	default:
		result.Framework = "Basic Security"
		result.Checks = runWindowsBasicChecks()
	}

	result.Summary = createComplianceSummary(result.Checks)
	result.Score = calculateComplianceScore(result.Checks)

	return result, nil
}

// getForensicSnapshot collects Windows forensic data.
func (c *Collector) getForensicSnapshot() (*types.ForensicSnapshotResult, error) {
	result := &types.ForensicSnapshotResult{
		SnapshotID:  generateSnapshotID(),
		CollectedAt: time.Now(),
		Timestamp:   time.Now(),
	}

	// Get system info
	result.System = getWindowsSystemInfo()

	// Get running processes
	result.Processes = getWindowsProcessSnapshot()

	// Get network connections
	result.NetworkConns = getWindowsNetworkSnapshot()

	// Get user sessions
	result.Users = getWindowsUsersSnapshot()

	// Get recent logins
	result.RecentLogins = getWindowsRecentLoginSnapshot()

	return result, nil
}

// getAuditTrail retrieves Windows audit events.
func (c *Collector) getAuditTrail(hours int) (*types.AuditTrailResult, error) {
	result := &types.AuditTrailResult{
		TimeRange: getTimeRange(hours),
		Timestamp: time.Now(),
		Sources:   []string{"Security", "System", "Application"},
	}

	// Get Security events
	result.Events = append(result.Events, getWindowsSecurityEvents(hours)...)

	// Get System events
	result.Events = append(result.Events, getWindowsSystemEvents(hours)...)

	// Get Application events
	result.Events = append(result.Events, getWindowsApplicationEvents(hours)...)

	result.Count = len(result.Events)

	return result, nil
}

// getHardeningRecommendations provides Windows hardening recommendations.
func (c *Collector) getHardeningRecommendations() (*types.HardeningRecommendationsResult, error) {
	result := &types.HardeningRecommendationsResult{
		Timestamp:     time.Now(),
		Categories:    make(map[string]int),
		PriorityCount: make(map[string]int),
	}

	// Check system hardening
	result.Recommendations = append(result.Recommendations, checkWindowsSystemHardening()...)

	// Check network hardening
	result.Recommendations = append(result.Recommendations, checkWindowsNetworkHardening()...)

	// Check authentication hardening
	result.Recommendations = append(result.Recommendations, checkWindowsAuthHardening()...)

	// Check service hardening
	result.Recommendations = append(result.Recommendations, checkWindowsServiceHardening()...)

	// Sort by priority and count categories
	sortRecommendations(result.Recommendations)
	for _, rec := range result.Recommendations {
		result.Categories[rec.Category]++
		result.PriorityCount[rec.Priority]++
	}

	return result, nil
}

// Helper functions

func isDefenderEnabled() bool {
	out, err := cmdexec.Command("powershell", "-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "True"
}

func isWindowsFirewallEnabled() bool {
	out, err := cmdexec.Command("netsh", "advfirewall", "show", "allprofiles", "state").Output()
	if err != nil {
		return false
	}
	// Check if any profile is OFF
	return !strings.Contains(string(out), "State                                 OFF")
}

func isUACEnabled() bool {
	out, err := cmdexec.Command("powershell", "-Command", "(Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System).EnableLUA").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "1"
}

func isBitLockerEnabled() bool {
	out, err := cmdexec.Command("powershell", "-Command", "(Get-BitLockerVolume -MountPoint C:).ProtectionStatus").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "On"
}

func isWindowsUpdateEnabled() bool {
	out, err := cmdexec.Command("powershell", "-Command", "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update').AUOptions").Output()
	if err != nil {
		return false
	}
	// AUOptions 4 = Auto download and install
	val, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return val >= 3
}

func isRDPEnabled() bool {
	out, err := cmdexec.Command("powershell", "-Command", "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}

func isGuestAccountEnabled() bool {
	out, err := cmdexec.Command("net", "user", "Guest").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "Account active               Yes")
}

func runWindowsCISChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	// 1.1.1 Ensure Guest Account is Disabled
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-1.1.1",
		Title:       "Guest account disabled",
		Description: "The Guest account should be disabled",
		Status:      boolToStatus(!isGuestAccountEnabled()),
		Severity:    "medium",
	})

	// 2.2.21 Deny access to this computer from the network
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-2.2.21",
		Title:       "Network access restricted",
		Description: "Guest should be denied network access",
		Status:      checkNetworkAccessPolicy(),
		Severity:    "medium",
	})

	// 9.1.1 Windows Firewall Domain Profile
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-9.1.1",
		Title:       "Domain Firewall enabled",
		Description: "Windows Firewall should be enabled for Domain profile",
		Status:      checkFirewallProfile("domain"),
		Severity:    "high",
	})

	// 9.2.1 Windows Firewall Private Profile
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-9.2.1",
		Title:       "Private Firewall enabled",
		Description: "Windows Firewall should be enabled for Private profile",
		Status:      checkFirewallProfile("private"),
		Severity:    "high",
	})

	// 9.3.1 Windows Firewall Public Profile
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-9.3.1",
		Title:       "Public Firewall enabled",
		Description: "Windows Firewall should be enabled for Public profile",
		Status:      checkFirewallProfile("public"),
		Severity:    "high",
	})

	// 18.9.45 Windows Defender
	checks = append(checks, types.ComplianceCheck{
		ID:          "CIS-18.9.45",
		Title:       "Windows Defender enabled",
		Description: "Windows Defender real-time protection should be enabled",
		Status:      boolToStatus(isDefenderEnabled()),
		Severity:    "critical",
	})

	return checks
}

func runWindowsSTIGChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	// V-63319 - UAC
	checks = append(checks, types.ComplianceCheck{
		ID:          "V-63319",
		Title:       "UAC enabled",
		Description: "User Account Control must be enabled",
		Status:      boolToStatus(isUACEnabled()),
		Severity:    "high",
	})

	// V-63405 - BitLocker
	checks = append(checks, types.ComplianceCheck{
		ID:          "V-63405",
		Title:       "BitLocker enabled",
		Description: "BitLocker must be enabled on the system drive",
		Status:      boolToStatus(isBitLockerEnabled()),
		Severity:    "high",
	})

	// V-63597 - Windows Firewall
	checks = append(checks, types.ComplianceCheck{
		ID:          "V-63597",
		Title:       "Firewall enabled",
		Description: "Windows Firewall must be enabled",
		Status:      boolToStatus(isWindowsFirewallEnabled()),
		Severity:    "high",
	})

	// V-63687 - Automatic Updates
	checks = append(checks, types.ComplianceCheck{
		ID:          "V-63687",
		Title:       "Automatic updates",
		Description: "Windows must be configured for automatic updates",
		Status:      boolToStatus(isWindowsUpdateEnabled()),
		Severity:    "medium",
	})

	return checks
}

func runWindowsBasicChecks() []types.ComplianceCheck {
	var checks []types.ComplianceCheck

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-001",
		Title:       "Antivirus active",
		Description: "Windows Defender should be enabled",
		Status:      boolToStatus(isDefenderEnabled()),
		Severity:    "critical",
	})

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-002",
		Title:       "Firewall active",
		Description: "Windows Firewall should be enabled",
		Status:      boolToStatus(isWindowsFirewallEnabled()),
		Severity:    "high",
	})

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-003",
		Title:       "UAC enabled",
		Description: "User Account Control should be enabled",
		Status:      boolToStatus(isUACEnabled()),
		Severity:    "high",
	})

	checks = append(checks, types.ComplianceCheck{
		ID:          "BASIC-004",
		Title:       "Disk encryption",
		Description: "BitLocker should be enabled",
		Status:      boolToStatus(isBitLockerEnabled()),
		Severity:    "medium",
	})

	return checks
}

func checkNetworkAccessPolicy() string {
	out, err := cmdexec.Command("secedit", "/export", "/cfg", os.TempDir()+"\\secpol.cfg").Output()
	if err != nil {
		return "fail"
	}
	_ = out
	data, err := os.ReadFile(os.TempDir() + "\\secpol.cfg")
	if err != nil {
		return "fail"
	}
	if strings.Contains(string(data), "SeDenyNetworkLogonRight") && strings.Contains(string(data), "Guest") {
		os.Remove(os.TempDir() + "\\secpol.cfg")
		return "pass"
	}
	os.Remove(os.TempDir() + "\\secpol.cfg")
	return "fail"
}

func checkFirewallProfile(profile string) string {
	out, err := cmdexec.Command("netsh", "advfirewall", "show", profile+"profile", "state").Output()
	if err != nil {
		return "fail"
	}
	if strings.Contains(string(out), "State                                 ON") {
		return "pass"
	}
	return "fail"
}

func getWindowsSystemInfo() types.ForensicSystem {
	info := types.ForensicSystem{}

	// Hostname
	if name, err := os.Hostname(); err == nil {
		info.Hostname = name
	}

	// OS info
	if out, err := cmdexec.Command("powershell", "-Command", "(Get-WmiObject -Class Win32_OperatingSystem).Caption").Output(); err == nil {
		info.OS = strings.TrimSpace(string(out))
	}

	// Kernel (Windows version)
	if out, err := cmdexec.Command("powershell", "-Command", "[System.Environment]::OSVersion.VersionString").Output(); err == nil {
		info.Kernel = strings.TrimSpace(string(out))
	}

	// Boot time
	if out, err := cmdexec.Command("powershell", "-Command", "(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime | Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'").Output(); err == nil {
		if t, err := time.Parse("2006-01-02T15:04:05", strings.TrimSpace(string(out))); err == nil {
			info.BootTime = t
		}
	}

	// Uptime
	if out, err := cmdexec.Command("powershell", "-Command", "(Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime | ForEach-Object { $_.ToString() }").Output(); err == nil {
		info.Uptime = strings.TrimSpace(string(out))
	}

	// Timezone
	if out, err := cmdexec.Command("powershell", "-Command", "[System.TimeZoneInfo]::Local.DisplayName").Output(); err == nil {
		info.Timezone = strings.TrimSpace(string(out))
	}

	return info
}

func getWindowsProcessSnapshot() []types.ForensicProcess {
	var processes []types.ForensicProcess

	out, err := cmdexec.Command("powershell", "-Command", "Get-Process | Select-Object Id,ProcessName,UserName,CPU | ConvertTo-Csv -NoTypeInformation").Output()
	if err != nil {
		return processes
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		if len(fields) >= 4 {
			pid, _ := strconv.ParseInt(strings.Trim(fields[0], "\""), 10, 32)
			cpu, _ := strconv.ParseFloat(strings.Trim(fields[3], "\""), 64)
			processes = append(processes, types.ForensicProcess{
				PID:        int32(pid),
				User:       strings.Trim(fields[2], "\""),
				Name:       strings.Trim(fields[1], "\""),
				CPUPercent: cpu,
			})
		}
		if len(processes) >= 100 {
			break
		}
	}

	return processes
}

func getWindowsNetworkSnapshot() []types.ForensicConnection {
	var connections []types.ForensicConnection

	out, err := cmdexec.Command("netstat", "-ano").Output()
	if err != nil {
		return connections
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && (fields[0] == "TCP" || fields[0] == "UDP") {
			pid, _ := strconv.ParseInt(fields[4], 10, 32)
			connections = append(connections, types.ForensicConnection{
				Protocol:  fields[0],
				LocalAddr: fields[1],
				State:     safeGet(fields, 3),
				PID:       int32(pid),
			})
			if len(fields) > 2 && fields[0] == "TCP" {
				connections[len(connections)-1].RemoteAddr = fields[2]
			}
		}
		if len(connections) >= 100 {
			break
		}
	}

	return connections
}

func getWindowsUsersSnapshot() []types.ForensicUser {
	var users []types.ForensicUser

	out, err := cmdexec.Command("powershell", "-Command", "Get-LocalUser | Select-Object Name,Enabled,SID | ConvertTo-Csv -NoTypeInformation").Output()
	if err != nil {
		return users
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		if len(fields) >= 3 {
			username := strings.Trim(fields[0], "\"")
			enabled := strings.Trim(fields[1], "\"") == "True"
			users = append(users, types.ForensicUser{
				Username: username,
				IsLocked: !enabled,
			})
		}
	}

	// Check admin membership
	adminOut, _ := cmdexec.Command("powershell", "-Command", "Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name").Output()
	adminMembers := strings.Split(string(adminOut), "\n")
	for i := range users {
		for _, admin := range adminMembers {
			if strings.Contains(admin, users[i].Username) {
				users[i].IsAdmin = true
				break
			}
		}
	}

	return users
}

func getWindowsRecentLoginSnapshot() []types.ForensicLogin {
	var logins []types.ForensicLogin

	// Query Security event log for login events (Event ID 4624)
	out, err := cmdexec.Command("powershell", "-Command",
		"Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624} -MaxEvents 50 2>$null | "+
			"Select-Object TimeCreated,@{N='User';E={$_.Properties[5].Value}} | "+
			"ConvertTo-Csv -NoTypeInformation").Output()
	if err != nil {
		return logins
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ",")
		if len(fields) >= 2 {
			timeStr := strings.Trim(fields[0], "\"")
			loginTime, _ := time.Parse("1/2/2006 3:04:05 PM", timeStr)
			logins = append(logins, types.ForensicLogin{
				Username:  strings.Trim(fields[1], "\""),
				LoginTime: loginTime,
				Type:      "login",
			})
		}
		if len(logins) >= 50 {
			break
		}
	}

	return logins
}

func getWindowsSecurityEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	startTime := time.Now().Add(-time.Duration(hours) * time.Hour).Format("01/02/2006 15:04:05")

	out, err := cmdexec.Command("powershell", "-Command",
		fmt.Sprintf("Get-WinEvent -FilterHashtable @{LogName='Security';StartTime='%s'} -MaxEvents 100 2>$null | "+
			"Select-Object TimeCreated,Id,Message | ConvertTo-Csv -NoTypeInformation", startTime)).Output()
	if err != nil {
		return events
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			events = append(events, types.AuditEvent{
				Type:     "auth",
				Action:   "security_event",
				Source:   "Security",
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

func getWindowsSystemEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	startTime := time.Now().Add(-time.Duration(hours) * time.Hour).Format("01/02/2006 15:04:05")

	out, _ := cmdexec.Command("powershell", "-Command",
		fmt.Sprintf("Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2,3;StartTime='%s'} -MaxEvents 50 2>$null | "+
			"Select-Object TimeCreated,LevelDisplayName,Message | ConvertTo-Csv -NoTypeInformation", startTime)).Output()

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			events = append(events, types.AuditEvent{
				Type:     "system",
				Action:   "system_event",
				Source:   "System",
				Details:  line,
				Severity: "warning",
			})
		}
		if len(events) >= 25 {
			break
		}
	}

	return events
}

func getWindowsApplicationEvents(hours int) []types.AuditEvent {
	var events []types.AuditEvent

	startTime := time.Now().Add(-time.Duration(hours) * time.Hour).Format("01/02/2006 15:04:05")

	out, _ := cmdexec.Command("powershell", "-Command",
		fmt.Sprintf("Get-WinEvent -FilterHashtable @{LogName='Application';Level=1,2,3;StartTime='%s'} -MaxEvents 50 2>$null | "+
			"Select-Object TimeCreated,ProviderName,Message | ConvertTo-Csv -NoTypeInformation", startTime)).Output()

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Scan() // Skip header
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			events = append(events, types.AuditEvent{
				Type:     "application",
				Action:   "app_event",
				Source:   "Application",
				Details:  line,
				Severity: "warning",
			})
		}
		if len(events) >= 25 {
			break
		}
	}

	return events
}

func checkWindowsSystemHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check UAC
	if !isUACEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "SYS-001",
			Title:        "Enable User Account Control",
			Category:     "system",
			Priority:     "critical",
			Description:  "UAC provides protection against unauthorized changes",
			CurrentState: "disabled",
			TargetState:  "enabled",
			Remediation:  "Enable UAC via registry or Control Panel",
			Commands:     []string{`reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f`},
		})
	}

	// Check BitLocker
	if !isBitLockerEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "SYS-002",
			Title:        "Enable BitLocker encryption",
			Category:     "encryption",
			Priority:     "high",
			Description:  "Full disk encryption protects data if device is lost or stolen",
			CurrentState: "disabled",
			TargetState:  "enabled",
			Remediation:  "Enable BitLocker via Control Panel or manage-bde command",
			Commands:     []string{"manage-bde -on C: -RecoveryPassword"},
		})
	}

	return recs
}

func checkWindowsNetworkHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check Firewall
	if !isWindowsFirewallEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "NET-001",
			Title:        "Enable Windows Firewall",
			Category:     "network",
			Priority:     "critical",
			Description:  "Windows Firewall should be enabled for all profiles",
			CurrentState: "disabled",
			TargetState:  "enabled for all profiles",
			Remediation:  "Enable firewall via netsh command",
			Commands:     []string{"netsh advfirewall set allprofiles state on"},
		})
	}

	// Check SMBv1
	out, _ := cmdexec.Command("powershell", "-Command", "Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol").Output()
	if strings.TrimSpace(string(out)) == "True" {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "NET-002",
			Title:        "Disable SMBv1",
			Category:     "network",
			Priority:     "high",
			Description:  "SMBv1 is vulnerable to attacks like WannaCry",
			CurrentState: "enabled",
			TargetState:  "disabled",
			Remediation:  "Disable SMBv1 via PowerShell",
			Commands:     []string{"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"},
		})
	}

	// Check RDP NLA
	if isRDPEnabled() {
		out, _ := cmdexec.Command("powershell", "-Command", "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication").Output()
		if strings.TrimSpace(string(out)) != "1" {
			recs = append(recs, types.HardeningRecommendation{
				ID:           "NET-003",
				Title:        "Require NLA for RDP",
				Category:     "network",
				Priority:     "high",
				Description:  "Network Level Authentication should be required for RDP",
				CurrentState: "not required",
				TargetState:  "required",
				Remediation:  "Enable NLA via registry",
				Commands:     []string{`reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f`},
			})
		}
	}

	return recs
}

func checkWindowsAuthHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check Guest account
	if isGuestAccountEnabled() {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "AUTH-001",
			Title:        "Disable Guest account",
			Category:     "authentication",
			Priority:     "high",
			Description:  "The Guest account should be disabled",
			CurrentState: "enabled",
			TargetState:  "disabled",
			Remediation:  "Disable Guest account via net user command",
			Commands:     []string{"net user Guest /active:no"},
		})
	}

	// Check password policy
	out, _ := cmdexec.Command("net", "accounts").Output()
	if strings.Contains(string(out), "Minimum password length: 0") {
		recs = append(recs, types.HardeningRecommendation{
			ID:           "AUTH-002",
			Title:        "Set minimum password length",
			Category:     "authentication",
			Priority:     "high",
			Description:  "Minimum password length should be at least 14 characters",
			CurrentState: "0 characters",
			TargetState:  "14 characters",
			Remediation:  "Set minimum password length via net accounts command",
			Commands:     []string{"net accounts /minpwlen:14"},
		})
	}

	return recs
}

func checkWindowsServiceHardening() []types.HardeningRecommendation {
	var recs []types.HardeningRecommendation

	// Check for unnecessary services
	riskyServices := map[string]string{
		"RemoteRegistry": "Remote Registry service",
		"Telnet":         "Telnet service",
	}

	for svc, desc := range riskyServices {
		out, err := cmdexec.Command("powershell", "-Command", fmt.Sprintf("(Get-Service -Name '%s' -ErrorAction SilentlyContinue).Status", svc)).Output()
		if err == nil && strings.TrimSpace(string(out)) == "Running" {
			recs = append(recs, types.HardeningRecommendation{
				ID:           "SVC-001",
				Title:        fmt.Sprintf("Disable %s", desc),
				Category:     "services",
				Priority:     "medium",
				Description:  fmt.Sprintf("Consider disabling the %s if not needed", desc),
				CurrentState: "running",
				TargetState:  "disabled",
				Remediation:  fmt.Sprintf("Stop and disable the %s", desc),
				Commands:     []string{fmt.Sprintf("Stop-Service -Name '%s' -Force; Set-Service -Name '%s' -StartupType Disabled", svc, svc)},
			})
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
