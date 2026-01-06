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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/internal/redact"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Windows stubs - return not supported on Linux
func (c *Collector) getWindowsDefenderStatus() (*types.WindowsDefenderStatus, error) {
	return &types.WindowsDefenderStatus{
		Error:     "Windows Defender not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsFirewallProfiles() (*types.WindowsFirewallProfiles, error) {
	return &types.WindowsFirewallProfiles{
		Error:     "Windows Firewall not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getBitLockerStatus() (*types.BitLockerStatus, error) {
	return &types.BitLockerStatus{
		Error:     "BitLocker not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsSMBShares() (*types.WindowsSMBShares, error) {
	return &types.WindowsSMBShares{
		Error:     "Windows SMB shares not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsRDPConfig() (*types.WindowsRDPConfig, error) {
	return &types.WindowsRDPConfig{
		Error:     "Windows RDP not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsWinRMConfig() (*types.WindowsWinRMConfig, error) {
	return &types.WindowsWinRMConfig{
		Error:     "WinRM not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsAppLockerPolicy() (*types.WindowsAppLockerPolicy, error) {
	return &types.WindowsAppLockerPolicy{
		Error:     "AppLocker not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsWDACStatus() (*types.WindowsWDACStatus, error) {
	return &types.WindowsWDACStatus{
		Error:     "WDAC not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsLocalSecurityPolicy() (*types.WindowsLocalSecurityPolicy, error) {
	return &types.WindowsLocalSecurityPolicy{
		Error:     "Windows Local Security Policy not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsGPOApplied() (*types.WindowsGPOApplied, error) {
	return &types.WindowsGPOApplied{
		Error:     "Windows GPO not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsCredentialGuard() (*types.WindowsCredentialGuard, error) {
	return &types.WindowsCredentialGuard{
		Error:     "Credential Guard not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getWindowsUpdateHealth() (*types.WindowsUpdateHealth, error) {
	return &types.WindowsUpdateHealth{
		Error:     "Windows Update not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

// macOS stubs - return not supported on Linux
func (c *Collector) getMacOSFileVaultStatus() (*types.MacOSFileVaultStatus, error) {
	return &types.MacOSFileVaultStatus{
		Error:     "FileVault not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSGatekeeperStatus() (*types.MacOSGatekeeperStatus, error) {
	return &types.MacOSGatekeeperStatus{
		Error:     "Gatekeeper not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSSIPStatus() (*types.MacOSSIPStatus, error) {
	return &types.MacOSSIPStatus{
		Error:     "SIP not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSXProtectStatus() (*types.MacOSXProtectStatus, error) {
	return &types.MacOSXProtectStatus{
		Error:     "XProtect not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSPFRules() (*types.MacOSPFRules, error) {
	return &types.MacOSPFRules{
		Error:     "macOS PF not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSMDMProfiles() (*types.MacOSMDMProfiles, error) {
	return &types.MacOSMDMProfiles{
		Error:     "macOS MDM not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSTCCPermissions() (*types.MacOSTCCPermissions, error) {
	return &types.MacOSTCCPermissions{
		Error:     "TCC not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSSecurityLogEvents() (*types.MacOSSecurityLogEvents, error) {
	return &types.MacOSSecurityLogEvents{
		Error:     "macOS unified logs not available on Linux",
		Timestamp: time.Now(),
	}, nil
}

// Linux implementations

func (c *Collector) getLinuxAuditdStatus() (*types.LinuxAuditdStatus, error) {
	result := &types.LinuxAuditdStatus{
		Timestamp: time.Now(),
	}

	// Check if auditd is running
	output, err := cmdexec.Command("systemctl", "is-active", "auditd").Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		result.Running = true
	}

	// Check if enabled
	output, err = cmdexec.Command("systemctl", "is-enabled", "auditd").Output()
	if err == nil && strings.TrimSpace(string(output)) == "enabled" {
		result.Enabled = true
	}

	// Get auditctl status
	output, err = cmdexec.Command("auditctl", "-s").Output()
	if err == nil {
		parseAuditctlStatus(string(output), result)
	}

	// Get rules
	output, err = cmdexec.Command("auditctl", "-l").Output()
	if err == nil {
		result.Rules = parseAuditRules(string(output))
		result.RuleCount = len(result.Rules)
	}

	return result, nil
}

func parseAuditctlStatus(output string, result *types.LinuxAuditdStatus) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "pid":
			result.PID, _ = strconv.Atoi(value)
		case "backlog_limit":
			result.BacklogLimit, _ = strconv.Atoi(value)
		case "backlog_wait_time":
			result.BacklogWaitTime, _ = strconv.Atoi(value)
		case "failure":
			result.Failure = value
		case "rate_limit":
			result.RateLimit, _ = strconv.Atoi(value)
		case "lost":
			result.LostEvents, _ = strconv.Atoi(value)
		}
	}
}

func parseAuditRules(output string) []types.AuditRule {
	var rules []types.AuditRule
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "No rules" {
			continue
		}

		rule := types.AuditRule{Rule: line}
		if strings.Contains(line, "-w") {
			rule.Type = "file"
		} else if strings.Contains(line, "-a") {
			rule.Type = "syscall"
		} else if strings.Contains(line, "-e") {
			rule.Type = "exclude"
		}

		// Extract key if present
		keyRe := regexp.MustCompile(`-k\s+(\S+)`)
		if matches := keyRe.FindStringSubmatch(line); len(matches) > 1 {
			rule.Key = matches[1]
		}

		// Extract permissions for file watches
		permRe := regexp.MustCompile(`-p\s+([rwxa]+)`)
		if matches := permRe.FindStringSubmatch(line); len(matches) > 1 {
			rule.Permissions = matches[1]
		}

		rules = append(rules, rule)
	}
	return rules
}

func (c *Collector) getLinuxKernelLockdown() (*types.LinuxKernelLockdown, error) {
	result := &types.LinuxKernelLockdown{
		Timestamp: time.Now(),
	}

	// Check kernel lockdown mode
	lockdownPath := "/sys/kernel/security/lockdown"
	if data, err := os.ReadFile(lockdownPath); err == nil {
		result.Supported = true
		content := strings.TrimSpace(string(data))
		// Format: [none] integrity confidentiality
		if strings.Contains(content, "[none]") {
			result.Mode = "none"
		} else if strings.Contains(content, "[integrity]") {
			result.Mode = "integrity"
		} else if strings.Contains(content, "[confidentiality]") {
			result.Mode = "confidentiality"
		} else {
			result.Mode = content
		}
	} else {
		result.Supported = false
		result.Mode = "not_supported"
	}

	// Check Secure Boot status
	if data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-*"); err == nil {
		result.SecureBoot = len(data) > 4 && data[4] == 1
	} else {
		// Try alternate path
		output, err := cmdexec.Command("mokutil", "--sb-state").Output()
		if err == nil && strings.Contains(string(output), "SecureBoot enabled") {
			result.SecureBoot = true
		}
	}

	return result, nil
}

func (c *Collector) getLinuxSysctlSecurity() (*types.LinuxSysctlSecurity, error) {
	result := &types.LinuxSysctlSecurity{
		Values:    make(map[string]string),
		Timestamp: time.Now(),
	}

	// Security-relevant sysctls to check
	securitySysctls := []struct {
		key         string
		recommended string
		description string
	}{
		{"kernel.randomize_va_space", "2", "ASLR enabled"},
		{"kernel.exec-shield", "1", "Exec shield enabled"},
		{"kernel.kptr_restrict", "1", "Kernel pointer hiding"},
		{"kernel.dmesg_restrict", "1", "Restrict dmesg access"},
		{"kernel.perf_event_paranoid", "2", "Restrict perf events"},
		{"kernel.yama.ptrace_scope", "1", "Restrict ptrace"},
		{"net.ipv4.conf.all.rp_filter", "1", "Reverse path filtering"},
		{"net.ipv4.conf.default.rp_filter", "1", "Default reverse path filtering"},
		{"net.ipv4.icmp_echo_ignore_broadcasts", "1", "Ignore ICMP broadcasts"},
		{"net.ipv4.conf.all.accept_redirects", "0", "Reject ICMP redirects"},
		{"net.ipv4.conf.default.accept_redirects", "0", "Default reject ICMP redirects"},
		{"net.ipv4.conf.all.secure_redirects", "0", "Reject secure ICMP redirects"},
		{"net.ipv4.conf.all.send_redirects", "0", "Don't send ICMP redirects"},
		{"net.ipv4.conf.all.accept_source_route", "0", "Reject source routing"},
		{"net.ipv4.conf.all.log_martians", "1", "Log martian packets"},
		{"net.ipv4.tcp_syncookies", "1", "SYN cookies enabled"},
		{"net.ipv6.conf.all.accept_redirects", "0", "IPv6 reject redirects"},
		{"net.ipv6.conf.default.accept_redirects", "0", "IPv6 default reject redirects"},
		{"fs.protected_hardlinks", "1", "Protected hardlinks"},
		{"fs.protected_symlinks", "1", "Protected symlinks"},
		{"fs.suid_dumpable", "0", "SUID core dumps disabled"},
	}

	passed := 0
	for _, sc := range securitySysctls {
		value := readSysctl(sc.key)
		result.Values[sc.key] = value

		check := types.SysctlCheck{
			Key:              sc.key,
			CurrentValue:     value,
			RecommendedValue: sc.recommended,
			Passed:           value == sc.recommended,
			Description:      sc.description,
		}
		if check.Passed {
			passed++
		}
		result.Hardened = append(result.Hardened, check)
	}

	if len(securitySysctls) > 0 {
		result.Score = (passed * 100) / len(securitySysctls)
	}

	return result, nil
}

func readSysctl(key string) string {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

func (c *Collector) getLinuxFirewallBackend() (*types.LinuxFirewallBackend, error) {
	result := &types.LinuxFirewallBackend{
		Timestamp: time.Now(),
	}

	// Check for firewalld first (RHEL/Fedora/CentOS)
	output, err := cmdexec.Command("systemctl", "is-active", "firewalld").Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		result.Backend = "firewalld"
		result.Active = true

		// Get zones
		output, err = cmdexec.Command("firewall-cmd", "--get-active-zones").Output()
		if err == nil {
			for _, line := range strings.Split(string(output), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "interfaces:") && !strings.HasPrefix(line, "sources:") {
					result.Zones = append(result.Zones, line)
				}
			}
		}

		// Get version
		output, err = cmdexec.Command("firewall-cmd", "--version").Output()
		if err == nil {
			result.Version = strings.TrimSpace(string(output))
		}

		return result, nil
	}

	// Check for ufw (Ubuntu/Debian)
	output, err = cmdexec.Command("ufw", "status").Output()
	if err == nil {
		outStr := string(output)
		if strings.Contains(outStr, "Status: active") {
			result.Backend = "ufw"
			result.Active = true
			result.RuleCount = strings.Count(outStr, "\n") - 4 // Approximate rule count
			return result, nil
		}
	}

	// Check for nftables
	output, err = cmdexec.Command("nft", "list", "ruleset").Output()
	if err == nil && len(output) > 0 {
		result.Backend = "nftables"
		result.Active = true
		result.RuleCount = strings.Count(string(output), "rule ")

		// Get version
		output, err = cmdexec.Command("nft", "--version").Output()
		if err == nil {
			result.Version = strings.TrimSpace(string(output))
		}
		return result, nil
	}

	// Check for iptables
	output, err = cmdexec.Command("iptables", "-L", "-n").Output()
	if err == nil {
		result.Backend = "iptables"
		result.Active = true
		result.RuleCount = strings.Count(string(output), "\n") - 6 // Approximate

		// Get default policy
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Chain INPUT") {
				if strings.Contains(line, "DROP") {
					result.DefaultPolicy = "DROP"
				} else if strings.Contains(line, "ACCEPT") {
					result.DefaultPolicy = "ACCEPT"
				}
				break
			}
		}

		// Get version
		output, err = cmdexec.Command("iptables", "--version").Output()
		if err == nil {
			result.Version = strings.TrimSpace(string(output))
		}
		return result, nil
	}

	result.Backend = "none"
	result.Active = false

	return result, nil
}

func (c *Collector) getLinuxMACDetailed() (*types.LinuxMACDetailed, error) {
	result := &types.LinuxMACDetailed{
		Timestamp: time.Now(),
	}

	// Check for SELinux
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		result.Type = "selinux"
		result.Enabled = true

		selinux := &types.SELinuxDetails{}

		// Get current mode
		if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
			if strings.TrimSpace(string(data)) == "1" {
				selinux.CurrentMode = "enforcing"
				result.Mode = "enforcing"
			} else {
				selinux.CurrentMode = "permissive"
				result.Mode = "permissive"
			}
		}

		// Get config mode
		if data, err := os.ReadFile("/etc/selinux/config"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "SELINUX=") {
					selinux.ConfigMode = strings.TrimPrefix(line, "SELINUX=")
				} else if strings.HasPrefix(line, "SELINUXTYPE=") {
					result.PolicyType = strings.TrimPrefix(line, "SELINUXTYPE=")
				}
			}
		}

		// Get policy name
		if data, err := os.ReadFile("/sys/fs/selinux/policyvers"); err == nil {
			result.PolicyVersion = strings.TrimSpace(string(data))
		}

		// Check MLS
		if _, err := os.Stat("/sys/fs/selinux/mls"); err == nil {
			selinux.MLS = true
		}

		result.SELinuxStatus = selinux
		return result, nil
	}

	// Check for AppArmor
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		result.Type = "apparmor"
		result.Enabled = true

		apparmor := &types.AppArmorDetails{}

		// Parse AppArmor status
		output, err := cmdexec.Command("aa-status", "--json").Output()
		if err == nil {
			parseAppArmorJSON(string(output), apparmor)
		} else {
			// Fallback to non-JSON
			output, err = cmdexec.Command("aa-status").Output()
			if err == nil {
				parseAppArmorText(string(output), apparmor)
			}
		}

		if apparmor.ProfilesEnforce > 0 {
			result.Mode = "enforce"
		} else if apparmor.ProfilesComplain > 0 {
			result.Mode = "complain"
		}

		result.AppArmorStatus = apparmor
		return result, nil
	}

	result.Type = "none"
	result.Enabled = false

	return result, nil
}

func parseAppArmorJSON(output string, apparmor *types.AppArmorDetails) {
	// Simple JSON parsing without external deps
	if strings.Contains(output, "\"profiles\"") {
		// Count profiles in enforce/complain mode
		apparmor.ProfilesEnforce = strings.Count(output, "\"enforce\"")
		apparmor.ProfilesComplain = strings.Count(output, "\"complain\"")
		apparmor.ProfilesLoaded = apparmor.ProfilesEnforce + apparmor.ProfilesComplain
	}
}

func parseAppArmorText(output string, apparmor *types.AppArmorDetails) {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "profiles are loaded") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				apparmor.ProfilesLoaded, _ = strconv.Atoi(parts[0])
			}
		} else if strings.Contains(line, "profiles are in enforce mode") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				apparmor.ProfilesEnforce, _ = strconv.Atoi(parts[0])
			}
		} else if strings.Contains(line, "profiles are in complain mode") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				apparmor.ProfilesComplain, _ = strconv.Atoi(parts[0])
			}
		} else if strings.Contains(line, "processes have profiles defined") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				apparmor.ProcessesConfined, _ = strconv.Atoi(parts[0])
			}
		} else if strings.Contains(line, "processes are unconfined") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				apparmor.ProcessesUnconfined, _ = strconv.Atoi(parts[0])
			}
		}
	}
}

func (c *Collector) getLinuxPackageRepos() (*types.LinuxPackageRepos, error) {
	result := &types.LinuxPackageRepos{
		Timestamp: time.Now(),
	}

	// Detect package manager and parse repos
	if _, err := os.Stat("/etc/apt/sources.list"); err == nil {
		result.PackageManager = "apt"
		result.Repos = parseAptRepos()
	} else if _, err := os.Stat("/etc/yum.repos.d"); err == nil {
		result.PackageManager = "dnf"
		result.Repos = parseDnfRepos()
	} else if _, err := os.Stat("/etc/zypp/repos.d"); err == nil {
		result.PackageManager = "zypper"
		result.Repos = parseZypperRepos()
	} else if _, err := os.Stat("/etc/pacman.d/mirrorlist"); err == nil {
		result.PackageManager = "pacman"
		result.Repos = parsePacmanRepos()
	}

	result.Count = len(result.Repos)
	return result, nil
}

func parseAptRepos() []types.PackageRepo {
	var repos []types.PackageRepo

	// Parse main sources.list
	parseAptSourcesFile("/etc/apt/sources.list", &repos)

	// Parse sources.list.d
	files, _ := filepath.Glob("/etc/apt/sources.list.d/*.list")
	for _, f := range files {
		parseAptSourcesFile(f, &repos)
	}

	return repos
}

func parseAptSourcesFile(path string, repos *[]types.PackageRepo) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}

		repo := types.PackageRepo{
			Type:    parts[0], // deb or deb-src
			URL:     parts[1],
			Name:    filepath.Base(path) + ":" + parts[2],
			Enabled: !strings.HasPrefix(line, "#"),
		}

		if len(parts) > 3 {
			repo.Components = parts[3:]
		}

		*repos = append(*repos, repo)
	}
}

func parseDnfRepos() []types.PackageRepo {
	var repos []types.PackageRepo

	files, _ := filepath.Glob("/etc/yum.repos.d/*.repo")
	for _, f := range files {
		parseRepoFile(f, &repos)
	}

	return repos
}

func parseRepoFile(path string, repos *[]types.PackageRepo) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var currentRepo *types.PackageRepo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentRepo != nil {
				*repos = append(*repos, *currentRepo)
			}
			currentRepo = &types.PackageRepo{
				Name: strings.Trim(line, "[]"),
				Type: "rpm",
			}
			continue
		}

		if currentRepo == nil {
			continue
		}

		if strings.HasPrefix(line, "baseurl=") {
			currentRepo.URL = strings.TrimPrefix(line, "baseurl=")
		} else if strings.HasPrefix(line, "enabled=") {
			currentRepo.Enabled = strings.TrimPrefix(line, "enabled=") == "1"
		} else if strings.HasPrefix(line, "gpgcheck=") {
			currentRepo.GPGCheck = strings.TrimPrefix(line, "gpgcheck=") == "1"
		}
	}

	if currentRepo != nil {
		*repos = append(*repos, *currentRepo)
	}
}

func parseZypperRepos() []types.PackageRepo {
	var repos []types.PackageRepo

	files, _ := filepath.Glob("/etc/zypp/repos.d/*.repo")
	for _, f := range files {
		parseRepoFile(f, &repos)
	}

	return repos
}

func parsePacmanRepos() []types.PackageRepo {
	var repos []types.PackageRepo

	file, err := os.Open("/etc/pacman.conf")
	if err != nil {
		return repos
	}
	defer file.Close()

	var currentRepo *types.PackageRepo
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.Trim(line, "[]")
			if name != "options" {
				if currentRepo != nil {
					repos = append(repos, *currentRepo)
				}
				currentRepo = &types.PackageRepo{
					Name:    name,
					Type:    "pacman",
					Enabled: true,
				}
			}
			continue
		}

		if currentRepo != nil && strings.HasPrefix(line, "Server") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				currentRepo.URL = strings.TrimSpace(parts[1])
			}
		}
	}

	if currentRepo != nil {
		repos = append(repos, *currentRepo)
	}

	return repos
}

func (c *Collector) getLinuxAutoUpdates() (*types.LinuxAutoUpdates, error) {
	result := &types.LinuxAutoUpdates{
		Timestamp: time.Now(),
	}

	// Check for unattended-upgrades (Debian/Ubuntu)
	if _, err := os.Stat("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		result.Service = "unattended-upgrades"
		parseUnattendedUpgrades(result)
		return result, nil
	}

	// Check for dnf-automatic (Fedora/RHEL)
	output, err := cmdexec.Command("systemctl", "is-enabled", "dnf-automatic.timer").Output()
	if err == nil && strings.TrimSpace(string(output)) == "enabled" {
		result.Service = "dnf-automatic"
		result.Enabled = true
		parseDnfAutomatic(result)
		return result, nil
	}

	// Check for yum-cron (older RHEL/CentOS)
	output, err = cmdexec.Command("systemctl", "is-enabled", "yum-cron").Output()
	if err == nil && strings.TrimSpace(string(output)) == "enabled" {
		result.Service = "yum-cron"
		result.Enabled = true
		return result, nil
	}

	result.Service = "none"
	result.Enabled = false

	return result, nil
}

func parseUnattendedUpgrades(result *types.LinuxAutoUpdates) {
	// Check if enabled
	if data, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		content := string(data)
		result.Enabled = strings.Contains(content, "APT::Periodic::Unattended-Upgrade \"1\"")
	}

	// Check configuration
	if data, err := os.ReadFile("/etc/apt/apt.conf.d/50unattended-upgrades"); err == nil {
		content := string(data)
		result.AutoReboot = strings.Contains(content, "Unattended-Upgrade::Automatic-Reboot \"true\"")

		// Extract reboot time
		rebootTimeRe := regexp.MustCompile(`Unattended-Upgrade::Automatic-Reboot-Time\s+"([^"]+)"`)
		if matches := rebootTimeRe.FindStringSubmatch(content); len(matches) > 1 {
			result.RebootTime = matches[1]
		}

		// Check if security only
		result.SecurityOnly = !strings.Contains(content, "${distro_id}:${distro_codename}-updates")
	}

	// Get last run time
	if info, err := os.Stat("/var/log/unattended-upgrades/unattended-upgrades.log"); err == nil {
		result.LastRun = info.ModTime()
	}
}

func parseDnfAutomatic(result *types.LinuxAutoUpdates) {
	if data, err := os.ReadFile("/etc/dnf/automatic.conf"); err == nil {
		content := string(data)
		result.SecurityOnly = strings.Contains(content, "upgrade_type = security")

		// Check for email
		if strings.Contains(content, "emit_via = email") {
			result.MailOnError = true
		}
	}
}

func (c *Collector) getVendorServices() (*types.VendorServicesResult, error) {
	result := &types.VendorServicesResult{
		Platform:  "linux",
		Timestamp: time.Now(),
	}

	// Get systemd services
	output, err := cmdexec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain").Output()
	if err != nil {
		result.Error = "failed to list services: " + err.Error()
		return result, nil
	}

	// Vendor service prefixes for Linux
	vendorPrefixes := []string{
		"systemd-", "dbus", "NetworkManager", "polkit", "udev",
		"accounts-daemon", "avahi", "bluetooth", "cups", "gdm",
		"lightdm", "sddm", "snapd", "flatpak", "packagekit",
		"rsyslog", "syslog", "journald", "cron", "atd",
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		serviceName := strings.TrimSuffix(fields[0], ".service")

		// Check if it's a vendor service
		isVendor := false
		for _, prefix := range vendorPrefixes {
			if strings.HasPrefix(serviceName, prefix) || serviceName == prefix {
				isVendor = true
				break
			}
		}

		if !isVendor {
			continue
		}

		service := types.VendorService{
			Name:   serviceName,
			Status: fields[3], // active/inactive
			Vendor: "Linux",
		}

		// Categorize
		if strings.Contains(serviceName, "network") || strings.Contains(serviceName, "Network") {
			service.Category = "networking"
		} else if strings.Contains(serviceName, "log") || strings.Contains(serviceName, "journal") {
			service.Category = "logging"
		} else if strings.Contains(serviceName, "udev") || strings.Contains(serviceName, "dbus") {
			service.Category = "system"
		} else if strings.Contains(serviceName, "gdm") || strings.Contains(serviceName, "lightdm") {
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
