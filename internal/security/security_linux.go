//go:build linux

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
	"github.com/levantar-ai/mcp-sysinfo/internal/redact"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getEnvVars returns system environment variables on Linux.
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

	// Read system-wide environment from /etc/environment
	// #nosec G304 -- reading from known system path
	if file, err := os.Open("/etc/environment"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.Trim(parts[0], "\"'")
				value := strings.Trim(parts[1], "\"'")
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

	return &types.EnvVarsResult{
		Variables: vars,
		Count:     len(vars),
		Source:    "linux",
		Timestamp: time.Now(),
	}, nil
}

// getUserAccounts returns local user accounts on Linux.
func (c *Collector) getUserAccounts() (*types.UserAccountsResult, error) {
	var users []types.UserAccount
	var groups []types.UserGroup

	// Parse /etc/passwd
	// #nosec G304 -- reading from known system path
	if file, err := os.Open("/etc/passwd"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) < 7 {
				continue
			}
			uid, _ := strconv.Atoi(fields[2])
			gid, _ := strconv.Atoi(fields[3])
			users = append(users, types.UserAccount{
				Username:    fields[0],
				UID:         uid,
				GID:         gid,
				DisplayName: fields[4],
				HomeDir:     fields[5],
				Shell:       fields[6],
				IsSystem:    uid < 1000,
			})
		}
	}

	// Parse /etc/group
	// #nosec G304 -- reading from known system path
	if file, err := os.Open("/etc/group"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) < 4 {
				continue
			}
			gid, _ := strconv.Atoi(fields[2])
			var members []string
			if fields[3] != "" {
				members = strings.Split(fields[3], ",")
			}
			groups = append(groups, types.UserGroup{
				Name:    fields[0],
				GID:     gid,
				Members: members,
			})
		}
	}

	// Check for locked accounts in /etc/shadow (if readable)
	lockedUsers := make(map[string]bool)
	// #nosec G304 -- reading from known system path
	if file, err := os.Open("/etc/shadow"); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) >= 2 {
				// Account is locked if password starts with ! or *
				if strings.HasPrefix(fields[1], "!") || strings.HasPrefix(fields[1], "*") {
					lockedUsers[fields[0]] = true
				}
			}
		}
	}

	// Update user locked status
	for i := range users {
		users[i].IsLocked = lockedUsers[users[i].Username]
	}

	return &types.UserAccountsResult{
		Users:     users,
		Groups:    groups,
		UserCount: len(users),
		Timestamp: time.Now(),
	}, nil
}

// getSudoConfig returns sudo configuration on Linux.
func (c *Collector) getSudoConfig() (*types.SudoConfigResult, error) {
	var rules []types.SudoRule
	sudoersPath := "/etc/sudoers"

	// Try to read /etc/sudoers
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

		// Simple parsing - look for user rules
		// Format: user host=(runas) commands
		rule := types.SudoRule{Raw: line}

		// Check for NOPASSWD
		if strings.Contains(line, "NOPASSWD") {
			rule.NoPasswd = true
		}

		// Try to extract user
		parts := strings.Fields(line)
		if len(parts) > 0 {
			rule.User = parts[0]
		}

		rules = append(rules, rule)
	}

	return rules
}

// getSSHConfig returns SSH configuration on Linux.
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

	// Parse ~/.ssh/config for current user
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

		// Check if first field is options or key type
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

// getMACStatus returns Mandatory Access Control status on Linux.
func (c *Collector) getMACStatus() (*types.MACStatusResult, error) {
	result := &types.MACStatusResult{
		Type:      "none",
		Enabled:   false,
		Timestamp: time.Now(),
	}

	// Check for SELinux
	// #nosec G304 -- reading from known system path
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		result.Type = "selinux"
		result.Enabled = true
		if strings.TrimSpace(string(data)) == "1" {
			result.Mode = "enforcing"
		} else {
			result.Mode = "permissive"
		}
		return result, nil
	}

	// Check for AppArmor
	// #nosec G304 -- reading from known system path
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		result.Type = "apparmor"
		result.Enabled = true
		result.Mode = "enabled"

		// Read profiles
		profilesPath := "/sys/kernel/security/apparmor/profiles"
		// #nosec G304 -- reading from known system path
		if file, err := os.Open(profilesPath); err == nil {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.Split(line, " ")
				if len(parts) >= 2 {
					profile := types.MACProfile{
						Name:   parts[0],
						Status: strings.Trim(parts[1], "()"),
					}
					result.Profiles = append(result.Profiles, profile)
				}
			}
		}
		return result, nil
	}

	return result, nil
}

// getCertificates returns SSL/TLS certificates on Linux.
func (c *Collector) getCertificates() (*types.CertificatesResult, error) {
	var certs []types.Certificate
	certDirs := []string{
		"/etc/ssl/certs",
		"/etc/pki/tls/certs",
	}

	storePath := ""
	for _, dir := range certDirs {
		if _, err := os.Stat(dir); err == nil {
			storePath = dir
			break
		}
	}

	if storePath == "" {
		return &types.CertificatesResult{
			Certificates: certs,
			Count:        0,
			Timestamp:    time.Now(),
		}, nil
	}

	// Limit number of certs to parse
	maxCerts := 100
	certCount := 0

	// Walk the certificate directory
	err := filepath.Walk(storePath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || certCount >= maxCerts {
			return nil
		}

		// Only process .crt, .pem files
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".crt" && ext != ".pem" {
			return nil
		}

		// Skip symlinks to avoid duplicates
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		// #nosec G304 -- path is from filepath.Walk of known directory
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Parse PEM blocks
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
		return &types.CertificatesResult{
			Certificates: certs,
			Count:        len(certs),
			StorePath:    storePath,
			Timestamp:    time.Now(),
		}, nil
	}

	// Sort by expiry date
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].NotAfter.Before(certs[j].NotAfter)
	})

	return &types.CertificatesResult{
		Certificates: certs,
		Count:        len(certs),
		StorePath:    storePath,
		Timestamp:    time.Now(),
	}, nil
}
