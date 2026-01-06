// Package security provides platform security controls diagnostics including
// Windows Defender, BitLocker, FileVault, Gatekeeper, SELinux, AppArmor, etc.
package security

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects platform security information.
type Collector struct{}

// NewCollector creates a new security collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetWindowsDefenderStatus retrieves Windows Defender status.
func (c *Collector) GetWindowsDefenderStatus() (*types.WindowsDefenderStatus, error) {
	return c.getWindowsDefenderStatus()
}

// GetWindowsFirewallProfiles retrieves Windows Firewall profile states.
func (c *Collector) GetWindowsFirewallProfiles() (*types.WindowsFirewallProfiles, error) {
	return c.getWindowsFirewallProfiles()
}

// GetBitLockerStatus retrieves BitLocker encryption status.
func (c *Collector) GetBitLockerStatus() (*types.BitLockerStatus, error) {
	return c.getBitLockerStatus()
}

// GetWindowsSMBShares retrieves SMB shares and permissions.
func (c *Collector) GetWindowsSMBShares() (*types.WindowsSMBShares, error) {
	return c.getWindowsSMBShares()
}

// GetWindowsRDPConfig retrieves RDP configuration.
func (c *Collector) GetWindowsRDPConfig() (*types.WindowsRDPConfig, error) {
	return c.getWindowsRDPConfig()
}

// GetWindowsWinRMConfig retrieves WinRM configuration.
func (c *Collector) GetWindowsWinRMConfig() (*types.WindowsWinRMConfig, error) {
	return c.getWindowsWinRMConfig()
}

// GetWindowsAppLockerPolicy retrieves AppLocker policy.
func (c *Collector) GetWindowsAppLockerPolicy() (*types.WindowsAppLockerPolicy, error) {
	return c.getWindowsAppLockerPolicy()
}

// GetWindowsWDACStatus retrieves WDAC/Code Integrity status.
func (c *Collector) GetWindowsWDACStatus() (*types.WindowsWDACStatus, error) {
	return c.getWindowsWDACStatus()
}

// GetWindowsLocalSecurityPolicy retrieves local security policy summary.
func (c *Collector) GetWindowsLocalSecurityPolicy() (*types.WindowsLocalSecurityPolicy, error) {
	return c.getWindowsLocalSecurityPolicy()
}

// GetWindowsGPOApplied retrieves applied Group Policy Objects.
func (c *Collector) GetWindowsGPOApplied() (*types.WindowsGPOApplied, error) {
	return c.getWindowsGPOApplied()
}

// GetWindowsCredentialGuard retrieves Credential Guard status.
func (c *Collector) GetWindowsCredentialGuard() (*types.WindowsCredentialGuard, error) {
	return c.getWindowsCredentialGuard()
}

// GetWindowsUpdateHealth retrieves Windows Update health status.
func (c *Collector) GetWindowsUpdateHealth() (*types.WindowsUpdateHealth, error) {
	return c.getWindowsUpdateHealth()
}

// GetMacOSFileVaultStatus retrieves FileVault status.
func (c *Collector) GetMacOSFileVaultStatus() (*types.MacOSFileVaultStatus, error) {
	return c.getMacOSFileVaultStatus()
}

// GetMacOSGatekeeperStatus retrieves Gatekeeper status.
func (c *Collector) GetMacOSGatekeeperStatus() (*types.MacOSGatekeeperStatus, error) {
	return c.getMacOSGatekeeperStatus()
}

// GetMacOSSIPStatus retrieves System Integrity Protection status.
func (c *Collector) GetMacOSSIPStatus() (*types.MacOSSIPStatus, error) {
	return c.getMacOSSIPStatus()
}

// GetMacOSXProtectStatus retrieves XProtect/MRT status.
func (c *Collector) GetMacOSXProtectStatus() (*types.MacOSXProtectStatus, error) {
	return c.getMacOSXProtectStatus()
}

// GetMacOSPFRules retrieves Packet Filter rules.
func (c *Collector) GetMacOSPFRules() (*types.MacOSPFRules, error) {
	return c.getMacOSPFRules()
}

// GetMacOSMDMProfiles retrieves MDM configuration profiles.
func (c *Collector) GetMacOSMDMProfiles() (*types.MacOSMDMProfiles, error) {
	return c.getMacOSMDMProfiles()
}

// GetMacOSTCCPermissions retrieves TCC permissions.
func (c *Collector) GetMacOSTCCPermissions() (*types.MacOSTCCPermissions, error) {
	return c.getMacOSTCCPermissions()
}

// GetMacOSSecurityLogEvents retrieves security-related log events.
func (c *Collector) GetMacOSSecurityLogEvents() (*types.MacOSSecurityLogEvents, error) {
	return c.getMacOSSecurityLogEvents()
}

// GetLinuxAuditdStatus retrieves auditd status and rules.
func (c *Collector) GetLinuxAuditdStatus() (*types.LinuxAuditdStatus, error) {
	return c.getLinuxAuditdStatus()
}

// GetLinuxKernelLockdown retrieves kernel lockdown mode.
func (c *Collector) GetLinuxKernelLockdown() (*types.LinuxKernelLockdown, error) {
	return c.getLinuxKernelLockdown()
}

// GetLinuxSysctlSecurity retrieves security-related sysctl values.
func (c *Collector) GetLinuxSysctlSecurity() (*types.LinuxSysctlSecurity, error) {
	return c.getLinuxSysctlSecurity()
}

// GetLinuxFirewallBackend retrieves the active firewall backend.
func (c *Collector) GetLinuxFirewallBackend() (*types.LinuxFirewallBackend, error) {
	return c.getLinuxFirewallBackend()
}

// GetLinuxMACDetailed retrieves detailed MAC (SELinux/AppArmor) status.
func (c *Collector) GetLinuxMACDetailed() (*types.LinuxMACDetailed, error) {
	return c.getLinuxMACDetailed()
}

// GetLinuxPackageRepos retrieves package repository summary.
func (c *Collector) GetLinuxPackageRepos() (*types.LinuxPackageRepos, error) {
	return c.getLinuxPackageRepos()
}

// GetLinuxAutoUpdates retrieves automatic update configuration.
func (c *Collector) GetLinuxAutoUpdates() (*types.LinuxAutoUpdates, error) {
	return c.getLinuxAutoUpdates()
}

// GetVendorServices retrieves OS vendor services inventory.
func (c *Collector) GetVendorServices() (*types.VendorServicesResult, error) {
	return c.getVendorServices()
}

// =============================================================================
// Original Phase 1.2.5 Security Configuration methods (existing functionality)
// =============================================================================

// GetEnvVars returns system environment variables.
func (c *Collector) GetEnvVars() (*types.EnvVarsResult, error) {
	return c.getEnvVars()
}

// GetUserAccounts returns local user accounts and groups.
func (c *Collector) GetUserAccounts() (*types.UserAccountsResult, error) {
	return c.getUserAccounts()
}

// GetSudoConfig returns sudo configuration (Unix-like systems).
func (c *Collector) GetSudoConfig() (*types.SudoConfigResult, error) {
	return c.getSudoConfig()
}

// GetSSHConfig returns SSH server and client configuration.
func (c *Collector) GetSSHConfig() (*types.SSHConfigResult, error) {
	return c.getSSHConfig()
}

// GetMACStatus returns Mandatory Access Control status (SELinux/AppArmor).
func (c *Collector) GetMACStatus() (*types.MACStatusResult, error) {
	return c.getMACStatus()
}

// GetCertificates returns SSL/TLS certificates from system trust store.
func (c *Collector) GetCertificates() (*types.CertificatesResult, error) {
	return c.getCertificates()
}
