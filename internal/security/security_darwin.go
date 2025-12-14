//go:build darwin

package security

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getEnvVars returns system environment variables on macOS.
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
					vars = append(vars, types.EnvVar{
						Name:   strings.TrimSpace(parts[0]),
						Value:  strings.Trim(parts[1], "\""),
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
