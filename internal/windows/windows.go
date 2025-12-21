// Package windows provides Windows Enterprise feature queries for Phase 1.10.
// This includes Registry, DCOM/COM, and IIS diagnostics.
package windows

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector provides Windows Enterprise diagnostic queries.
type Collector struct{}

// NewCollector creates a new Windows Enterprise collector.
func NewCollector() *Collector {
	return &Collector{}
}

// =============================================================================
// Registry Queries (Phase 1.10.1)
// =============================================================================

// GetRegistryKey reads a registry key and its values.
func (c *Collector) GetRegistryKey(hive, path string) (*types.RegistryKeyResult, error) {
	return c.getRegistryKey(hive, path)
}

// GetRegistryTree enumerates registry keys recursively up to maxDepth.
func (c *Collector) GetRegistryTree(hive, path string, maxDepth int) (*types.RegistryTreeResult, error) {
	return c.getRegistryTree(hive, path, maxDepth)
}

// GetRegistrySecurity retrieves the security descriptor for a registry key.
func (c *Collector) GetRegistrySecurity(hive, path string) (*types.RegistrySecurityResult, error) {
	return c.getRegistrySecurity(hive, path)
}

// =============================================================================
// DCOM/COM Queries (Phase 1.10.2)
// =============================================================================

// GetDCOMApplications lists all registered DCOM applications.
func (c *Collector) GetDCOMApplications() (*types.DCOMApplicationsResult, error) {
	return c.getDCOMApplications()
}

// GetDCOMPermissions retrieves launch and access permissions for a DCOM application.
func (c *Collector) GetDCOMPermissions(appID string) (*types.DCOMPermissionsResult, error) {
	return c.getDCOMPermissions(appID)
}

// GetDCOMIdentities lists RunAs identities for all DCOM applications.
func (c *Collector) GetDCOMIdentities() (*types.DCOMIdentitiesResult, error) {
	return c.getDCOMIdentities()
}

// GetCOMSecurityDefaults retrieves machine-wide COM security settings.
func (c *Collector) GetCOMSecurityDefaults() (*types.COMSecurityDefaults, error) {
	return c.getCOMSecurityDefaults()
}

// =============================================================================
// IIS Queries (Phase 1.10.3)
// =============================================================================

// GetIISSites lists all IIS websites.
func (c *Collector) GetIISSites() (*types.IISSitesResult, error) {
	return c.getIISSites()
}

// GetIISAppPools lists all IIS application pools.
func (c *Collector) GetIISAppPools() (*types.IISAppPoolsResult, error) {
	return c.getIISAppPools()
}

// GetIISBindings lists all site bindings across all IIS sites.
func (c *Collector) GetIISBindings() (*types.IISBindingsResult, error) {
	return c.getIISBindings()
}

// GetIISVirtualDirs lists all virtual directories across all IIS sites.
func (c *Collector) GetIISVirtualDirs() (*types.IISVirtualDirsResult, error) {
	return c.getIISVirtualDirs()
}

// GetIISHandlers lists all handler mappings configured in IIS.
func (c *Collector) GetIISHandlers() (*types.IISHandlersResult, error) {
	return c.getIISHandlers()
}

// GetIISModules lists all modules installed in IIS.
func (c *Collector) GetIISModules() (*types.IISModulesResult, error) {
	return c.getIISModules()
}

// GetIISSSLCerts lists all SSL certificate bindings in IIS.
func (c *Collector) GetIISSSLCerts() (*types.IISSSLCertsResult, error) {
	return c.getIISSSLCerts()
}

// GetIISAuthConfig retrieves authentication configuration for all IIS sites.
func (c *Collector) GetIISAuthConfig() (*types.IISAuthConfigResult, error) {
	return c.getIISAuthConfig()
}
