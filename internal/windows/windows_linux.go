//go:build linux

package windows

import (
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// =============================================================================
// Registry Queries - Empty stubs for Linux
// =============================================================================

func (c *Collector) getRegistryKey(hive, path string) (*types.RegistryKeyResult, error) {
	return &types.RegistryKeyResult{
		Hive:      hive,
		Path:      path,
		Values:    []types.RegistryValue{},
		SubKeys:   []string{},
		Error:     "Registry access is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getRegistryTree(hive, path string, maxDepth int) (*types.RegistryTreeResult, error) {
	return &types.RegistryTreeResult{
		Hive:      hive,
		Path:      path,
		Root:      types.RegistryTreeNode{Name: path, Path: path},
		TotalKeys: 0,
		MaxDepth:  maxDepth,
		Error:     "Registry access is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getRegistrySecurity(hive, path string) (*types.RegistrySecurityResult, error) {
	return &types.RegistrySecurityResult{
		Hive:      hive,
		Path:      path,
		Owner:     "",
		Group:     "",
		DACL:      []types.RegistryACE{},
		Error:     "Registry access is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

// =============================================================================
// DCOM/COM Queries - Empty stubs for Linux
// =============================================================================

func (c *Collector) getDCOMApplications() (*types.DCOMApplicationsResult, error) {
	return &types.DCOMApplicationsResult{
		Applications: []types.DCOMApplication{},
		Count:        0,
		Error:        "DCOM is only available on Windows",
		Timestamp:    time.Now(),
	}, nil
}

func (c *Collector) getDCOMPermissions(appID string) (*types.DCOMPermissionsResult, error) {
	return &types.DCOMPermissionsResult{
		AppID:             appID,
		Name:              "",
		LaunchPermissions: []types.DCOMPermissionACE{},
		AccessPermissions: []types.DCOMPermissionACE{},
		Error:             "DCOM is only available on Windows",
		Timestamp:         time.Now(),
	}, nil
}

func (c *Collector) getDCOMIdentities() (*types.DCOMIdentitiesResult, error) {
	return &types.DCOMIdentitiesResult{
		Identities: []types.DCOMIdentity{},
		Count:      0,
		Error:      "DCOM is only available on Windows",
		Timestamp:  time.Now(),
	}, nil
}

func (c *Collector) getCOMSecurityDefaults() (*types.COMSecurityDefaults, error) {
	return &types.COMSecurityDefaults{
		Error:     "COM security is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

// =============================================================================
// IIS Queries - Empty stubs for Linux
// =============================================================================

func (c *Collector) getIISSites() (*types.IISSitesResult, error) {
	return &types.IISSitesResult{
		Sites:     []types.IISSite{},
		Count:     0,
		Error:     "IIS is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getIISAppPools() (*types.IISAppPoolsResult, error) {
	return &types.IISAppPoolsResult{
		AppPools:  []types.IISAppPool{},
		Count:     0,
		Error:     "IIS is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getIISBindings() (*types.IISBindingsResult, error) {
	return &types.IISBindingsResult{
		Bindings:  []types.IISSiteBinding{},
		Count:     0,
		Error:     "IIS is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getIISVirtualDirs() (*types.IISVirtualDirsResult, error) {
	return &types.IISVirtualDirsResult{
		Sites:     []types.IISSiteVirtualDirs{},
		Count:     0,
		Error:     "IIS is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getIISHandlers() (*types.IISHandlersResult, error) {
	return &types.IISHandlersResult{
		Handlers:  []types.IISHandler{},
		Count:     0,
		Error:     "IIS is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getIISModules() (*types.IISModulesResult, error) {
	return &types.IISModulesResult{
		GlobalModules: []types.IISModule{},
		Modules:       []types.IISModule{},
		Count:         0,
		Error:         "IIS is only available on Windows",
		Timestamp:     time.Now(),
	}, nil
}

func (c *Collector) getIISSSLCerts() (*types.IISSSLCertsResult, error) {
	return &types.IISSSLCertsResult{
		Certificates: []types.IISSSLCert{},
		Count:        0,
		Error:        "IIS is only available on Windows",
		Timestamp:    time.Now(),
	}, nil
}

func (c *Collector) getIISAuthConfig() (*types.IISAuthConfigResult, error) {
	return &types.IISAuthConfigResult{
		Sites:     []types.IISSiteAuth{},
		Count:     0,
		Error:     "IIS is only available on Windows",
		Timestamp: time.Now(),
	}, nil
}
