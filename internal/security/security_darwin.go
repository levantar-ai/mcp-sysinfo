//go:build darwin

package security

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/internal/redact"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Windows stubs - return not supported on macOS
func (c *Collector) getWindowsDefenderStatus() (*types.WindowsDefenderStatus, error) {
	return &types.WindowsDefenderStatus{
		Error:     "Windows Defender not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsFirewallProfiles() (*types.WindowsFirewallProfiles, error) {
	return &types.WindowsFirewallProfiles{
		Error:     "Windows Firewall not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getBitLockerStatus() (*types.BitLockerStatus, error) {
	return &types.BitLockerStatus{
		Error:     "BitLocker not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsSMBShares() (*types.WindowsSMBShares, error) {
	return &types.WindowsSMBShares{
		Error:     "Windows SMB shares not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsRDPConfig() (*types.WindowsRDPConfig, error) {
	return &types.WindowsRDPConfig{
		Error:     "Windows RDP not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsWinRMConfig() (*types.WindowsWinRMConfig, error) {
	return &types.WindowsWinRMConfig{
		Error:     "WinRM not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsAppLockerPolicy() (*types.WindowsAppLockerPolicy, error) {
	return &types.WindowsAppLockerPolicy{
		Error:     "AppLocker not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsWDACStatus() (*types.WindowsWDACStatus, error) {
	return &types.WindowsWDACStatus{
		Error:     "WDAC not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsLocalSecurityPolicy() (*types.WindowsLocalSecurityPolicy, error) {
	return &types.WindowsLocalSecurityPolicy{
		Error:     "Windows Local Security Policy not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsGPOApplied() (*types.WindowsGPOApplied, error) {
	return &types.WindowsGPOApplied{
		Error:     "Windows GPO not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsCredentialGuard() (*types.WindowsCredentialGuard, error) {
	return &types.WindowsCredentialGuard{
		Error:     "Credential Guard not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsUpdateHealth() (*types.WindowsUpdateHealth, error) {
	return &types.WindowsUpdateHealth{
		Error:     "Windows Update not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

// Linux stubs - return not supported on macOS
func (c *Collector) getLinuxAuditdStatus() (*types.LinuxAuditdStatus, error) {
	return &types.LinuxAuditdStatus{
		Error:     "auditd not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxKernelLockdown() (*types.LinuxKernelLockdown, error) {
	return &types.LinuxKernelLockdown{
		Error:     "Kernel lockdown not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxSysctlSecurity() (*types.LinuxSysctlSecurity, error) {
	return &types.LinuxSysctlSecurity{
		Error:     "Linux sysctl not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxFirewallBackend() (*types.LinuxFirewallBackend, error) {
	return &types.LinuxFirewallBackend{
		Error:     "Linux firewall backend not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxMACDetailed() (*types.LinuxMACDetailed, error) {
	return &types.LinuxMACDetailed{
		Error:     "SELinux/AppArmor not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxPackageRepos() (*types.LinuxPackageRepos, error) {
	return &types.LinuxPackageRepos{
		Error:     "Linux package repos not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxAutoUpdates() (*types.LinuxAutoUpdates, error) {
	return &types.LinuxAutoUpdates{
		Error:     "Linux auto-updates not available on macOS",
		Timestamp: time.Now(),
	}, nil
}

// macOS implementations

func (c *Collector) getMacOSFileVaultStatus() (*types.MacOSFileVaultStatus, error) {
	result := &types.MacOSFileVaultStatus{
		Timestamp: time.Now(),
	}

	// Get FileVault status
	output, err := cmdexec.Command("fdesetup", "status").Output()
	if err != nil {
		result.Error = "failed to get FileVault status: " + err.Error()
		return result, nil
	}

	outStr := string(output)
	result.Enabled = strings.Contains(outStr, "FileVault is On")

	if strings.Contains(outStr, "Encryption in progress") {
		result.Status = "Encrypting"
		// Try to get percentage
		pctRe := regexp.MustCompile(`(\d+)%`)
		if matches := pctRe.FindStringSubmatch(outStr); len(matches) > 1 {
			result.EncryptionPercent, _ = strconv.Atoi(matches[1])
		}
	} else if strings.Contains(outStr, "Decryption in progress") {
		result.Status = "Decrypting"
	} else if result.Enabled {
		result.Status = "On"
		result.EncryptionPercent = 100
	} else {
		result.Status = "Off"
	}

	// Check for deferred enablement
	output, err = cmdexec.Command("fdesetup", "showdeferralinfo").Output()
	if err == nil && strings.Contains(string(output), "Deferred") {
		result.DeferredEnablement = true
	}

	// Get enabled users
	output, err = cmdexec.Command("fdesetup", "list").Output()
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				// Format: username,UUID
				parts := strings.Split(line, ",")
				if len(parts) > 0 {
					result.Users = append(result.Users, parts[0])
				}
			}
		}
	}

	// Check for recovery key
	output, err = cmdexec.Command("fdesetup", "haspersonalrecoverykey").Output()
	if err == nil && strings.Contains(string(output), "true") {
		result.HasRecoveryKey = true
	}

	// Check for institutional key
	output, err = cmdexec.Command("fdesetup", "hasinstitutionalrecoverykey").Output()
	if err == nil && strings.Contains(string(output), "true") {
		result.HasInstitutionalKey = true
	}

	return result, nil
}

func (c *Collector) getMacOSGatekeeperStatus() (*types.MacOSGatekeeperStatus, error) {
	result := &types.MacOSGatekeeperStatus{
		Timestamp: time.Now(),
	}

	// Get Gatekeeper status
	output, err := cmdexec.Command("spctl", "--status").Output()
	if err != nil {
		result.Error = "failed to get Gatekeeper status: " + err.Error()
		return result, nil
	}

	outStr := string(output)
	result.Enabled = strings.Contains(outStr, "assessments enabled")

	// Get assessment status
	output, err = cmdexec.Command("spctl", "--assess", "--verbose", "/Applications/Safari.app").Output()
	if err == nil {
		result.AssessmentEnabled = true
	}

	// Determine status level
	output, err = cmdexec.Command("spctl", "--status", "--verbose").Output()
	if err == nil {
		outStr = string(output)
		if strings.Contains(outStr, "developer id enabled") {
			result.DevIDEnabled = true
			result.Status = "App Store and identified developers"
		} else {
			result.Status = "App Store"
		}
	}

	// Check notarization requirement (macOS 10.15+)
	result.NotarizationRequired = true // Default for modern macOS

	return result, nil
}

func (c *Collector) getMacOSSIPStatus() (*types.MacOSSIPStatus, error) {
	result := &types.MacOSSIPStatus{
		Timestamp: time.Now(),
	}

	// Get SIP status
	output, err := cmdexec.Command("csrutil", "status").Output()
	if err != nil {
		result.Error = "failed to get SIP status: " + err.Error()
		return result, nil
	}

	outStr := string(output)
	result.Enabled = strings.Contains(outStr, "enabled")
	result.Status = strings.TrimSpace(outStr)

	// Parse configuration flags if SIP is partially disabled
	if strings.Contains(outStr, "configuration") {
		lines := strings.Split(outStr, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ":") && !strings.HasPrefix(line, "System Integrity") {
				result.ConfigurationFlags = append(result.ConfigurationFlags, line)
			}
		}
	}

	return result, nil
}

func (c *Collector) getMacOSXProtectStatus() (*types.MacOSXProtectStatus, error) {
	result := &types.MacOSXProtectStatus{
		Timestamp: time.Now(),
	}

	// XProtect version from system_profiler
	output, err := cmdexec.Command("system_profiler", "SPInstallHistoryDataType", "-json").Output()
	if err == nil {
		var data map[string]interface{}
		if json.Unmarshal(output, &data) == nil {
			// Parse for XProtect updates
			if history, ok := data["SPInstallHistoryDataType"].([]interface{}); ok {
				for _, item := range history {
					if install, ok := item.(map[string]interface{}); ok {
						if name, ok := install["_name"].(string); ok {
							if strings.Contains(name, "XProtect") {
								result.XProtectVersion = name
								if date, ok := install["install_date"].(string); ok {
									if t, err := time.Parse("2006-01-02T15:04:05Z", date); err == nil {
										result.LastUpdate = t
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// Get XProtect bundle version
	plistPath := "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
	if _, err := os.Stat(plistPath); err == nil {
		output, err = cmdexec.Command("defaults", "read", plistPath, "CFBundleShortVersionString").Output()
		if err == nil {
			result.XProtectBundleVersion = strings.TrimSpace(string(output))
		}
	}

	// Check MRT (Malware Removal Tool) version
	mrtPlist := "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"
	if _, err := os.Stat(mrtPlist); err == nil {
		output, err = cmdexec.Command("defaults", "read", mrtPlist, "CFBundleShortVersionString").Output()
		if err == nil {
			result.MRTVersion = strings.TrimSpace(string(output))
		}
	}

	// Gatekeeper config data version
	gkPlist := "/private/var/db/gkopaque.bundle/Contents/Info.plist"
	if _, err := os.Stat(gkPlist); err == nil {
		output, err = cmdexec.Command("defaults", "read", gkPlist, "CFBundleShortVersionString").Output()
		if err == nil {
			result.GatekeeperConfigData = strings.TrimSpace(string(output))
		}
	}

	return result, nil
}

func (c *Collector) getMacOSPFRules() (*types.MacOSPFRules, error) {
	result := &types.MacOSPFRules{
		Timestamp: time.Now(),
	}

	// Check if pf is enabled
	output, err := cmdexec.Command("pfctl", "-s", "info").Output()
	if err != nil {
		// Try with sudo context - might fail without privileges
		result.Error = "insufficient privileges to read PF status"
		return result, nil
	}

	outStr := string(output)
	result.Enabled = strings.Contains(outStr, "Status: Enabled")
	result.Status = "Disabled"
	if result.Enabled {
		result.Status = "Enabled"
	}

	// Get rules
	output, err = cmdexec.Command("pfctl", "-s", "rules").Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			rule := types.PFRule{
				Number: i + 1,
			}

			if strings.HasPrefix(line, "pass") {
				rule.Action = "pass"
			} else if strings.HasPrefix(line, "block") {
				rule.Action = "block"
			} else if strings.HasPrefix(line, "scrub") {
				rule.Action = "scrub"
			}

			if strings.Contains(line, "in") {
				rule.Direction = "in"
			} else if strings.Contains(line, "out") {
				rule.Direction = "out"
			}

			result.Rules = append(result.Rules, rule)
		}
		result.RuleCount = len(result.Rules)
	}

	// Get anchors
	output, err = cmdexec.Command("pfctl", "-s", "Anchors").Output()
	if err == nil {
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				result.Anchors = append(result.Anchors, line)
			}
		}
	}

	return result, nil
}

func (c *Collector) getMacOSMDMProfiles() (*types.MacOSMDMProfiles, error) {
	result := &types.MacOSMDMProfiles{
		Timestamp: time.Now(),
	}

	// Get profiles
	output, err := cmdexec.Command("profiles", "list", "-output", "stdout-xml").Output()
	if err != nil {
		// Try simpler command
		output, err = cmdexec.Command("profiles", "show", "-all").Output()
		if err != nil {
			result.Error = "failed to list profiles: " + err.Error()
			return result, nil
		}
	}

	outStr := string(output)

	// Check if MDM enrolled
	result.MDMEnrolled = strings.Contains(outStr, "MDM") || strings.Contains(outStr, "com.apple.mdm")

	// Parse profiles from text output
	var currentProfile *types.MDMProfile
	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "attribute:") || strings.HasPrefix(line, "profileIdentifier:") {
			if currentProfile != nil {
				result.Profiles = append(result.Profiles, *currentProfile)
			}
			currentProfile = &types.MDMProfile{}

			if strings.HasPrefix(line, "profileIdentifier:") {
				currentProfile.Identifier = strings.TrimPrefix(line, "profileIdentifier:")
				currentProfile.Identifier = strings.TrimSpace(currentProfile.Identifier)
			}
		}

		if currentProfile != nil {
			if strings.HasPrefix(line, "profileDisplayName:") {
				currentProfile.Name = strings.TrimSpace(strings.TrimPrefix(line, "profileDisplayName:"))
			} else if strings.HasPrefix(line, "profileOrganization:") {
				currentProfile.Organization = strings.TrimSpace(strings.TrimPrefix(line, "profileOrganization:"))
			} else if strings.HasPrefix(line, "profileInstallDate:") {
				currentProfile.InstallDate = strings.TrimSpace(strings.TrimPrefix(line, "profileInstallDate:"))
			} else if strings.HasPrefix(line, "profileType:") {
				currentProfile.ProfileType = strings.TrimSpace(strings.TrimPrefix(line, "profileType:"))
			}
		}
	}

	if currentProfile != nil {
		result.Profiles = append(result.Profiles, *currentProfile)
	}

	result.Count = len(result.Profiles)
	return result, nil
}

func (c *Collector) getMacOSTCCPermissions() (*types.MacOSTCCPermissions, error) {
	result := &types.MacOSTCCPermissions{
		Timestamp: time.Now(),
	}

	// TCC database is protected, we can only see what's granted to current user
	// via tccutil or by reading the database with proper permissions
	
	// Try to get some TCC info from system_profiler
	output, err := cmdexec.Command("sqlite3", filepath.Join(os.Getenv("HOME"), "Library/Application Support/com.apple.TCC/TCC.db"),
		"SELECT service, client, auth_value FROM access WHERE auth_value > 0;").Output()
	if err != nil {
		// TCC database is protected, this is expected
		result.Error = "TCC database access requires Full Disk Access permission"
		return result, nil
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) >= 3 {
			perm := types.TCCPermission{
				Service:    parts[0],
				Client:     parts[1],
				ClientType: "bundle",
				Allowed:    parts[2] == "2" || parts[2] == "3",
			}
			result.Permissions = append(result.Permissions, perm)
		}
	}

	result.Count = len(result.Permissions)
	return result, nil
}

func (c *Collector) getMacOSSecurityLogEvents() (*types.MacOSSecurityLogEvents, error) {
	result := &types.MacOSSecurityLogEvents{
		Timestamp: time.Now(),
	}

	// Query unified log for security events
	// Limit to last 100 events to avoid huge output
	output, err := cmdexec.Command("log", "show",
		"--predicate", "subsystem == 'com.apple.securityd' OR category == 'security'",
		"--style", "compact",
		"--last", "1h").Output()
	if err != nil {
		result.Error = "failed to query security logs: " + err.Error()
		return result, nil
	}

	// Parse log output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Timestamp") {
			continue
		}

		// Format: timestamp processname[pid]: message
		event := types.SecurityLogEvent{}

		// Try to parse timestamp (first ~24 chars)
		if len(line) > 24 {
			if t, err := time.Parse("2006-01-02 15:04:05.000000", line[:26]); err == nil {
				event.Timestamp = t
			}
		}

		// Extract process name
		if idx := strings.Index(line, "["); idx > 0 {
			parts := strings.Fields(line[:idx])
			if len(parts) > 1 {
				event.Process = parts[len(parts)-1]
			}
		}

		// Extract message
		if idx := strings.Index(line, "]:"); idx > 0 {
			event.Message = strings.TrimSpace(line[idx+2:])
		} else {
			event.Message = line
		}

		// Categorize event
		if strings.Contains(event.Message, "authentication") || strings.Contains(event.Message, "login") {
			event.EventType = "authentication"
		} else if strings.Contains(event.Message, "keychain") {
			event.EventType = "keychain"
		} else if strings.Contains(event.Message, "certificate") || strings.Contains(event.Message, "cert") {
			event.EventType = "certificate"
		} else if strings.Contains(event.Message, "code signing") {
			event.EventType = "code_signing"
		} else {
			event.EventType = "general"
		}

		result.Events = append(result.Events, event)

		// Limit to 100 events
		if len(result.Events) >= 100 {
			break
		}
	}

	result.Count = len(result.Events)
	return result, nil
}

func (c *Collector) getVendorServices() (*types.VendorServicesResult, error) {
	result := &types.VendorServicesResult{
		Platform:  "darwin",
		Timestamp: time.Now(),
	}

	// Get launchd services
	output, err := cmdexec.Command("launchctl", "list").Output()
	if err != nil {
		result.Error = "failed to list services: " + err.Error()
		return result, nil
	}

	// Apple vendor prefixes
	vendorPrefixes := []string{
		"com.apple.",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		serviceName := fields[2]

		// Check if it's a vendor service
		isVendor := false
		for _, prefix := range vendorPrefixes {
			if strings.HasPrefix(serviceName, prefix) {
				isVendor = true
				break
			}
		}

		if !isVendor {
			continue
		}

		service := types.VendorService{
			Name:   serviceName,
			Vendor: "Apple",
		}

		// Status based on PID
		if fields[0] == "-" {
			service.Status = "stopped"
		} else {
			service.Status = "running"
		}

		// Categorize
		if strings.Contains(serviceName, "network") || strings.Contains(serviceName, "wifi") {
			service.Category = "networking"
		} else if strings.Contains(serviceName, "security") || strings.Contains(serviceName, "keychain") {
			service.Category = "security"
		} else if strings.Contains(serviceName, "CoreServices") {
			service.Category = "system"
		} else if strings.Contains(serviceName, "WindowServer") || strings.Contains(serviceName, "loginwindow") {
			service.Category = "display"
		}

		result.Services = append(result.Services, service)
	}

	result.Count = len(result.Services)
	return result, nil
}

// =============================================================================
// Original Phase 1.2.5 Security Configuration methods (existing functionality)
// =============================================================================

// getEnvVars returns system environment variables on macOS.
func (c *Collector) getEnvVars() (*types.EnvVarsResult, error) {
	var vars []types.EnvVar

	// Get current process environment
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			// Use centralized redaction for sensitive values
			value := redact.RedactValue(parts[0], parts[1])
			vars = append(vars, types.EnvVar{
				Name:   parts[0],
				Value:  value,
				Source: "process",
			})
		}
	}

	// Try launchctl getenv for system environment
	cmd := cmdexec.Command("launchctl", "print", "system")
	if output, err := cmd.Output(); err == nil {
		// Parse environment section if present
		lines := strings.Split(string(output), "\n")
		inEnv := false
		for _, line := range lines {
			if strings.Contains(line, "environment = {") {
				inEnv = true
				continue
			}
			if inEnv {
				if strings.Contains(line, "}") {
					break
				}
				line = strings.TrimSpace(line)
				parts := strings.SplitN(line, " => ", 2)
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[0])
					value := strings.Trim(parts[1], "\"")
					// Use centralized redaction for sensitive values
					value = redact.RedactValue(name, value)
					vars = append(vars, types.EnvVar{
						Name:   name,
						Value:  value,
						Source: "system",
					})
				}
			}
		}
	}

	return &types.EnvVarsResult{
		Variables: vars,
		Count:     len(vars),
		Source:    "darwin",
		Timestamp: time.Now(),
	}, nil
}

// getUserAccounts returns local user accounts on macOS.
func (c *Collector) getUserAccounts() (*types.UserAccountsResult, error) {
	var users []types.UserAccount
	var groups []types.UserGroup

	// Use dscl to list users
	cmd := cmdexec.Command("dscl", ".", "-list", "/Users")
	output, err := cmd.Output()
	if err != nil {
		return &types.UserAccountsResult{
			Users:     users,
			Groups:    groups,
			UserCount: 0,
			Timestamp: time.Now(),
		}, nil
	}

	usernames := strings.Split(strings.TrimSpace(string(output)), "\n")
	for _, username := range usernames {
		username = strings.TrimSpace(username)
		if username == "" {
			continue
		}

		user := types.UserAccount{Username: username}

		// Get user details
		cmd := cmdexec.Command("dscl", ".", "-read", "/Users/"+username)
		if details, err := cmd.Output(); err == nil {
			lines := strings.Split(string(details), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "UniqueID:") {
					user.UID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "UniqueID:")))
				} else if strings.HasPrefix(line, "PrimaryGroupID:") {
					user.GID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PrimaryGroupID:")))
				} else if strings.HasPrefix(line, "RealName:") {
					user.DisplayName = strings.TrimSpace(strings.TrimPrefix(line, "RealName:"))
				} else if strings.HasPrefix(line, "NFSHomeDirectory:") {
					user.HomeDir = strings.TrimSpace(strings.TrimPrefix(line, "NFSHomeDirectory:"))
				} else if strings.HasPrefix(line, "UserShell:") {
					user.Shell = strings.TrimSpace(strings.TrimPrefix(line, "UserShell:"))
				}
			}
		}

		// System users typically have UID < 500 on macOS
		user.IsSystem = user.UID < 500

		users = append(users, user)
	}

	// Get groups
	cmd = cmdexec.Command("dscl", ".", "-list", "/Groups")
	if output, err := cmd.Output(); err == nil {
		groupNames := strings.Split(strings.TrimSpace(string(output)), "\n")
		for _, groupName := range groupNames {
			groupName = strings.TrimSpace(groupName)
			if groupName == "" {
				continue
			}

			group := types.UserGroup{Name: groupName}

			// Get group details
			cmd := cmdexec.Command("dscl", ".", "-read", "/Groups/"+groupName)
			if details, err := cmd.Output(); err == nil {
				lines := strings.Split(string(details), "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "PrimaryGroupID:") {
						group.GID, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PrimaryGroupID:")))
					} else if strings.HasPrefix(line, "GroupMembership:") {
						members := strings.TrimSpace(strings.TrimPrefix(line, "GroupMembership:"))
						if members != "" {
							group.Members = strings.Fields(members)
						}
					}
				}
			}

			groups = append(groups, group)
		}
	}

	return &types.UserAccountsResult{
		Users:     users,
		Groups:    groups,
		UserCount: len(users),
		Timestamp: time.Now(),
	}, nil
}

// getSudoConfig returns sudo configuration on macOS.
func (c *Collector) getSudoConfig() (*types.SudoConfigResult, error) {
	var rules []types.SudoRule
	sudoersPath := "/etc/sudoers"

	// Try to read /etc/sudoers (same format as Linux)
	rules = append(rules, parseSudoersFile(sudoersPath)...)

	// Read /etc/sudoers.d/ directory
	sudoersD := "/etc/sudoers.d"
	if entries, err := os.ReadDir(sudoersD); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join(sudoersD, entry.Name())
			rules = append(rules, parseSudoersFile(path)...)
		}
	}

	return &types.SudoConfigResult{
		Rules:       rules,
		Count:       len(rules),
		SudoersPath: sudoersPath,
		Timestamp:   time.Now(),
	}, nil
}

// parseSudoersFile parses a sudoers file.
func parseSudoersFile(path string) []types.SudoRule {
	var rules []types.SudoRule

	// #nosec G304 -- path is from known system locations
	file, err := os.Open(path)
	if err != nil {
		return rules
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
			continue
		}

		rule := types.SudoRule{Raw: line}

		if strings.Contains(line, "NOPASSWD") {
			rule.NoPasswd = true
		}

		parts := strings.Fields(line)
		if len(parts) > 0 {
			rule.User = parts[0]
		}

		rules = append(rules, rule)
	}

	return rules
}

// getSSHConfig returns SSH configuration on macOS.
func (c *Collector) getSSHConfig() (*types.SSHConfigResult, error) {
	result := &types.SSHConfigResult{
		ServerConfig: make(map[string]string),
		ClientConfig: make(map[string]string),
		Timestamp:    time.Now(),
	}

	// Parse /etc/ssh/sshd_config
	sshdConfig := "/etc/ssh/sshd_config"
	result.SSHDPath = sshdConfig
	// #nosec G304 -- reading from known system path
	if file, err := os.Open(sshdConfig); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				result.ServerConfig[parts[0]] = strings.Join(parts[1:], " ")
			}
		}
	}

	// Check if SSH server is running
	cmd := cmdexec.Command("pgrep", "-x", "sshd")
	if err := cmd.Run(); err == nil {
		result.ServerRunning = true
	}

	// Parse ~/.ssh/config
	homeDir := os.Getenv("HOME")
	if homeDir != "" {
		clientConfig := filepath.Join(homeDir, ".ssh", "config")
		// #nosec G304 -- path is constructed from HOME env
		if file, err := os.Open(clientConfig); err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					result.ClientConfig[parts[0]] = strings.Join(parts[1:], " ")
				}
			}
		}

		// Read authorized_keys
		authKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
		result.AuthorizedKeys = parseAuthorizedKeys(authKeysPath)
	}

	return result, nil
}

// parseAuthorizedKeys parses an authorized_keys file.
func parseAuthorizedKeys(path string) []types.SSHAuthorizedKey {
	var keys []types.SSHAuthorizedKey

	// #nosec G304 -- path is from known locations
	file, err := os.Open(path)
	if err != nil {
		return keys
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := types.SSHAuthorizedKey{}

		idx := 0
		if !strings.HasPrefix(parts[0], "ssh-") && !strings.HasPrefix(parts[0], "ecdsa-") {
			key.Options = parts[0]
			idx = 1
		}

		if idx < len(parts) {
			key.KeyType = parts[idx]
		}
		if idx+2 < len(parts) {
			key.Comment = strings.Join(parts[idx+2:], " ")
		}

		keys = append(keys, key)
	}

	return keys
}

// getMACStatus returns Mandatory Access Control status on macOS.
func (c *Collector) getMACStatus() (*types.MACStatusResult, error) {
	result := &types.MACStatusResult{
		Type:      "sip", // System Integrity Protection
		Enabled:   false,
		Timestamp: time.Now(),
	}

	// Check SIP status
	cmd := cmdexec.Command("csrutil", "status")
	if output, err := cmd.Output(); err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "enabled") {
			result.Enabled = true
			result.Mode = "enabled"
		} else {
			result.Mode = "disabled"
		}
	}

	return result, nil
}

// getCertificates returns SSL/TLS certificates on macOS.
func (c *Collector) getCertificates() (*types.CertificatesResult, error) {
	var certs []types.Certificate

	// Use security command to list certificates
	cmd := cmdexec.Command("security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to /etc/ssl/certs
		return c.getCertificatesFromDir()
	}

	maxCerts := 100
	data := output

	for certCount := 0; certCount < maxCerts; {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		now := time.Now()
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		fingerprint := sha256.Sum256(cert.Raw)

		certs = append(certs, types.Certificate{
			Subject:         cert.Subject.String(),
			Issuer:          cert.Issuer.String(),
			NotBefore:       cert.NotBefore,
			NotAfter:        cert.NotAfter,
			SerialNumber:    cert.SerialNumber.String(),
			Fingerprint:     fmt.Sprintf("%X", fingerprint),
			IsCA:            cert.IsCA,
			IsExpired:       now.After(cert.NotAfter),
			DaysUntilExpiry: daysUntilExpiry,
		})
		certCount++
	}

	// Sort by expiry date
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].NotAfter.Before(certs[j].NotAfter)
	})

	return &types.CertificatesResult{
		Certificates: certs,
		Count:        len(certs),
		StorePath:    "/System/Library/Keychains/SystemRootCertificates.keychain",
		Timestamp:    time.Now(),
	}, nil
}

// getCertificatesFromDir reads certificates from /etc/ssl/certs.
func (c *Collector) getCertificatesFromDir() (*types.CertificatesResult, error) {
	var certs []types.Certificate
	certDir := "/etc/ssl/certs"

	maxCerts := 100
	certCount := 0

	err := filepath.Walk(certDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || certCount >= maxCerts {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".crt" && ext != ".pem" {
			return nil
		}

		// #nosec G304 -- path is from filepath.Walk
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		for {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest

			if block.Type != "CERTIFICATE" {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			now := time.Now()
			daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
			fingerprint := sha256.Sum256(cert.Raw)

			certs = append(certs, types.Certificate{
				Subject:         cert.Subject.String(),
				Issuer:          cert.Issuer.String(),
				NotBefore:       cert.NotBefore,
				NotAfter:        cert.NotAfter,
				SerialNumber:    cert.SerialNumber.String(),
				Fingerprint:     fmt.Sprintf("%X", fingerprint),
				IsCA:            cert.IsCA,
				IsExpired:       now.After(cert.NotAfter),
				DaysUntilExpiry: daysUntilExpiry,
			})
			certCount++

			if certCount >= maxCerts {
				break
			}
		}

		return nil
	})

	if err != nil {
		// Return what we have
	}

	sort.Slice(certs, func(i, j int) bool {
		return certs[i].NotAfter.Before(certs[j].NotAfter)
	})

	return &types.CertificatesResult{
		Certificates: certs,
		Count:        len(certs),
		StorePath:    certDir,
		Timestamp:    time.Now(),
	}, nil
}
