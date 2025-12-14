//go:build windows

package security

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getEnvVars returns system environment variables on Windows.
func (c *Collector) getEnvVars() (*types.EnvVarsResult, error) {
	var vars []types.EnvVar

	// Get current process environment
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			// Redact sensitive values
			value := parts[1]
			name := strings.ToUpper(parts[0])
			if strings.Contains(name, "PASSWORD") || strings.Contains(name, "SECRET") ||
				strings.Contains(name, "TOKEN") || strings.Contains(name, "KEY") ||
				strings.Contains(name, "CREDENTIAL") {
				value = "[REDACTED]"
			}
			vars = append(vars, types.EnvVar{
				Name:   parts[0],
				Value:  value,
				Source: "process",
			})
		}
	}

	return &types.EnvVarsResult{
		Variables: vars,
		Count:     len(vars),
		Source:    "windows",
		Timestamp: time.Now(),
	}, nil
}

// getUserAccounts returns local user accounts on Windows.
func (c *Collector) getUserAccounts() (*types.UserAccountsResult, error) {
	var users []types.UserAccount
	var groups []types.UserGroup

	// Use PowerShell to get local users
	psCmd := `Get-LocalUser | Select-Object Name,Enabled,Description,SID | ConvertTo-Json`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err == nil {
		users = parseWindowsUsers(output)
	}

	// Use net user as fallback
	if len(users) == 0 {
		cmd := cmdexec.Command("net", "user")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "-") || strings.Contains(line, "accounts for") {
					continue
				}
				names := strings.Fields(line)
				for _, name := range names {
					if name != "" {
						users = append(users, types.UserAccount{
							Username: name,
						})
					}
				}
			}
		}
	}

	// Get local groups
	psCmd = `Get-LocalGroup | Select-Object Name,Description,SID | ConvertTo-Json`
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command", psCmd)
	if output, err := cmd.Output(); err == nil {
		groups = parseWindowsGroups(output)
	}

	return &types.UserAccountsResult{
		Users:     users,
		Groups:    groups,
		UserCount: len(users),
		Timestamp: time.Now(),
	}, nil
}

// parseWindowsUsers parses PowerShell user output.
func parseWindowsUsers(output []byte) []types.UserAccount {
	var users []types.UserAccount
	content := string(output)
	lines := strings.Split(content, "\n")

	var currentUser types.UserAccount
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\"Name\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentUser.Username = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "\"Enabled\":") {
			currentUser.IsLocked = !strings.Contains(line, "true")
		} else if strings.Contains(line, "\"Description\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentUser.DisplayName = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "}") && currentUser.Username != "" {
			users = append(users, currentUser)
			currentUser = types.UserAccount{}
		}
	}

	return users
}

// parseWindowsGroups parses PowerShell group output.
func parseWindowsGroups(output []byte) []types.UserGroup {
	var groups []types.UserGroup
	content := string(output)
	lines := strings.Split(content, "\n")

	var currentGroup types.UserGroup
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\"Name\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentGroup.Name = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "}") && currentGroup.Name != "" {
			groups = append(groups, currentGroup)
			currentGroup = types.UserGroup{}
		}
	}

	return groups
}

// getSudoConfig returns admin configuration on Windows.
func (c *Collector) getSudoConfig() (*types.SudoConfigResult, error) {
	var rules []types.SudoRule

	// Get members of Administrators group
	psCmd := `Get-LocalGroupMember -Group "Administrators" | Select-Object Name,ObjectClass | ConvertTo-Json`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psCmd)
	if output, err := cmd.Output(); err == nil {
		content := string(output)
		lines := strings.Split(content, "\n")
		var currentName string
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "\"Name\":") {
				if idx := strings.Index(line, ":"); idx > 0 {
					currentName = strings.Trim(line[idx+1:], `", `)
				}
			} else if strings.Contains(line, "}") && currentName != "" {
				rules = append(rules, types.SudoRule{
					User:     currentName,
					Commands: []string{"ALL"},
					Raw:      "Member of Administrators group",
				})
				currentName = ""
			}
		}
	}

	// Fallback to net localgroup
	if len(rules) == 0 {
		cmd := cmdexec.Command("net", "localgroup", "Administrators")
		if output, err := cmd.Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			inMembers := false
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "---") {
					inMembers = true
					continue
				}
				if inMembers && line != "" && !strings.HasPrefix(line, "The command") {
					rules = append(rules, types.SudoRule{
						User:     line,
						Commands: []string{"ALL"},
						Raw:      "Member of Administrators group",
					})
				}
			}
		}
	}

	return &types.SudoConfigResult{
		Rules:       rules,
		Count:       len(rules),
		SudoersPath: "Local Administrators Group",
		Timestamp:   time.Now(),
	}, nil
}

// getSSHConfig returns SSH configuration on Windows.
func (c *Collector) getSSHConfig() (*types.SSHConfigResult, error) {
	result := &types.SSHConfigResult{
		ServerConfig: make(map[string]string),
		ClientConfig: make(map[string]string),
		Timestamp:    time.Now(),
	}

	// Check for OpenSSH server config
	sshdConfig := `C:\ProgramData\ssh\sshd_config`
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

	// Check if SSH server service is running
	cmd := cmdexec.Command("sc", "query", "sshd")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "RUNNING") {
			result.ServerRunning = true
		}
	}

	// Parse user SSH config
	homeDir := os.Getenv("USERPROFILE")
	if homeDir != "" {
		clientConfig := filepath.Join(homeDir, ".ssh", "config")
		// #nosec G304 -- path is constructed from env
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

// getMACStatus returns security status on Windows.
func (c *Collector) getMACStatus() (*types.MACStatusResult, error) {
	result := &types.MACStatusResult{
		Type:      "windows-security",
		Enabled:   false,
		Timestamp: time.Now(),
	}

	// Check Windows Defender status
	psCmd := `Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntispywareEnabled,AntivirusEnabled | ConvertTo-Json`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psCmd)
	if output, err := cmd.Output(); err == nil {
		outputStr := string(output)
		if strings.Contains(outputStr, "true") {
			result.Enabled = true
			result.Mode = "enabled"

			// Check which protections are enabled
			var profiles []types.MACProfile
			if strings.Contains(outputStr, "RealTimeProtectionEnabled") && strings.Contains(outputStr, "true") {
				profiles = append(profiles, types.MACProfile{
					Name:   "RealTimeProtection",
					Status: "enabled",
				})
			}
			if strings.Contains(outputStr, "AntivirusEnabled") {
				profiles = append(profiles, types.MACProfile{
					Name:   "Antivirus",
					Status: "enabled",
				})
			}
			result.Profiles = profiles
		}
	}

	// Check UAC status
	cmd = cmdexec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "/v", "EnableLUA")
	if output, err := cmd.Output(); err == nil {
		if strings.Contains(string(output), "0x1") {
			result.Profiles = append(result.Profiles, types.MACProfile{
				Name:   "UAC",
				Status: "enabled",
			})
		}
	}

	return result, nil
}

// getCertificates returns SSL/TLS certificates on Windows.
func (c *Collector) getCertificates() (*types.CertificatesResult, error) {
	var certs []types.Certificate

	// Use PowerShell to get certificates from system store
	psCmd := `Get-ChildItem -Path Cert:\LocalMachine\Root | Select-Object Subject,Issuer,NotBefore,NotAfter,Thumbprint | ConvertTo-Json`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return &types.CertificatesResult{
			Certificates: certs,
			Count:        0,
			StorePath:    "Cert:\\LocalMachine\\Root",
			Timestamp:    time.Now(),
		}, nil
	}

	certs = parseWindowsCerts(output)

	return &types.CertificatesResult{
		Certificates: certs,
		Count:        len(certs),
		StorePath:    "Cert:\\LocalMachine\\Root",
		Timestamp:    time.Now(),
	}, nil
}

// parseWindowsCerts parses PowerShell certificate output.
func parseWindowsCerts(output []byte) []types.Certificate {
	var certs []types.Certificate
	content := string(output)
	lines := strings.Split(content, "\n")

	var currentCert types.Certificate
	maxCerts := 100

	for _, line := range lines {
		if len(certs) >= maxCerts {
			break
		}

		line = strings.TrimSpace(line)

		if strings.Contains(line, "\"Subject\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentCert.Subject = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "\"Issuer\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentCert.Issuer = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "\"Thumbprint\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentCert.Fingerprint = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "\"NotBefore\":") {
			// Parse date - PowerShell format varies
			if idx := strings.Index(line, ":"); idx > 0 {
				dateStr := strings.Trim(line[idx+1:], `", `)
				// Try to extract date portion
				if t, err := parseWindowsDate(dateStr); err == nil {
					currentCert.NotBefore = t
				}
			}
		} else if strings.Contains(line, "\"NotAfter\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				dateStr := strings.Trim(line[idx+1:], `", `)
				if t, err := parseWindowsDate(dateStr); err == nil {
					currentCert.NotAfter = t
					now := time.Now()
					currentCert.IsExpired = now.After(t)
					currentCert.DaysUntilExpiry = int(t.Sub(now).Hours() / 24)
				}
			}
		} else if strings.Contains(line, "}") && currentCert.Subject != "" {
			certs = append(certs, currentCert)
			currentCert = types.Certificate{}
		}
	}

	return certs
}

// parseWindowsDate attempts to parse Windows date formats.
func parseWindowsDate(s string) (time.Time, error) {
	// Extract date from various PowerShell formats
	// Common format: /Date(1234567890000)/
	if strings.Contains(s, "/Date(") {
		start := strings.Index(s, "(") + 1
		end := strings.Index(s, ")")
		if start > 0 && end > start {
			msStr := s[start:end]
			// Remove timezone offset if present
			if idx := strings.Index(msStr, "+"); idx > 0 {
				msStr = msStr[:idx]
			}
			if idx := strings.Index(msStr, "-"); idx > 0 {
				msStr = msStr[:idx]
			}
			if ms, err := strconv.ParseInt(msStr, 10, 64); err == nil {
				return time.Unix(ms/1000, (ms%1000)*1000000), nil
			}
		}
	}

	// Try common date formats
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"01/02/2006 15:04:05",
		"1/2/2006 3:04:05 PM",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}

	return time.Time{}, nil
}
