// Package security provides security configuration collection across platforms.
package security

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects security configuration information.
type Collector struct{}

// NewCollector creates a new security collector.
func NewCollector() *Collector {
	return &Collector{}
}

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
