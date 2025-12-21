//go:build windows

package windows

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// PowerShell JSON output structures for IIS
type psIISSite struct {
	Name            string         `json:"Name"`
	ID              int            `json:"ID"`
	State           string         `json:"State"`
	PhysicalPath    string         `json:"PhysicalPath"`
	Bindings        []psIISBinding `json:"Bindings"`
	ServerAutoStart bool           `json:"ServerAutoStart"`
}

type psIISBinding struct {
	Protocol             string `json:"Protocol"`
	BindingInformation   string `json:"BindingInformation"`
	CertificateHash      string `json:"CertificateHash"`
	CertificateStoreName string `json:"CertificateStoreName"`
	SSLFlags             int    `json:"SSLFlags"`
}

type psIISAppPool struct {
	Name                  string `json:"Name"`
	State                 string `json:"State"`
	ManagedRuntimeVersion string `json:"ManagedRuntimeVersion"`
	ManagedPipelineMode   string `json:"ManagedPipelineMode"`
	Enable32BitAppOnWin64 bool   `json:"Enable32BitAppOnWin64"`
	StartMode             string `json:"StartMode"`
	AutoStart             bool   `json:"AutoStart"`
	QueueLength           int    `json:"QueueLength"`
}

// getIISSites lists all IIS websites.
func (c *Collector) getIISSites() (*types.IISSitesResult, error) {
	result := &types.IISSitesResult{
		Sites:     []types.IISSite{},
		Timestamp: time.Now(),
	}

	// Check if IIS is installed
	if !isIISInstalled() {
		result.Error = "IIS is not installed"
		return result, nil
	}

	// Use PowerShell to get IIS sites
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", `
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		Get-Website | ForEach-Object {
			$bindings = @()
			foreach ($b in $_.Bindings.Collection) {
				$bindings += @{
					Protocol = $b.Protocol
					BindingInformation = $b.BindingInformation
					CertificateHash = if ($b.CertificateHash) { [System.BitConverter]::ToString($b.CertificateHash) -replace '-','' } else { '' }
					CertificateStoreName = $b.CertificateStoreName
					SSLFlags = $b.SSLFlags
				}
			}
			@{
				Name = $_.Name
				ID = $_.ID
				State = $_.State
				PhysicalPath = $_.PhysicalPath
				Bindings = $bindings
				ServerAutoStart = $_.ServerAutoStart
			}
		} | ConvertTo-Json -Depth 4
	`)

	out, err := cmd.Output()
	if err != nil {
		result.Error = fmt.Sprintf("failed to query IIS sites: %v", err)
		return result, nil
	}

	// Parse JSON output
	var sites []psIISSite
	outStr := strings.TrimSpace(string(out))
	if outStr == "" || outStr == "null" {
		return result, nil
	}

	// Handle single object vs array
	if strings.HasPrefix(outStr, "[") {
		if err := json.Unmarshal([]byte(outStr), &sites); err != nil {
			result.Error = fmt.Sprintf("failed to parse sites: %v", err)
			return result, nil
		}
	} else {
		var site psIISSite
		if err := json.Unmarshal([]byte(outStr), &site); err != nil {
			result.Error = fmt.Sprintf("failed to parse site: %v", err)
			return result, nil
		}
		sites = []psIISSite{site}
	}

	// Convert to result type
	for _, s := range sites {
		site := types.IISSite{
			ID:              s.ID,
			Name:            s.Name,
			State:           s.State,
			PhysicalPath:    s.PhysicalPath,
			ServerAutoStart: s.ServerAutoStart,
			Bindings:        []types.IISBinding{},
		}

		for _, b := range s.Bindings {
			binding := parseBindingInfo(b)
			site.Bindings = append(site.Bindings, binding)
		}

		result.Sites = append(result.Sites, site)
	}

	result.Count = len(result.Sites)
	return result, nil
}

// parseBindingInfo parses a binding information string.
func parseBindingInfo(b psIISBinding) types.IISBinding {
	binding := types.IISBinding{
		Protocol:           b.Protocol,
		BindingInformation: b.BindingInformation,
		CertificateHash:    b.CertificateHash,
		CertificateStore:   b.CertificateStoreName,
		SSLFlags:           b.SSLFlags,
	}

	// Parse binding information: IP:Port:Hostname
	parts := strings.Split(b.BindingInformation, ":")
	if len(parts) >= 2 {
		binding.IPAddress = parts[0]
		if binding.IPAddress == "*" {
			binding.IPAddress = "0.0.0.0"
		}
		port, _ := strconv.Atoi(parts[1])
		binding.Port = port
		if len(parts) >= 3 {
			binding.HostName = parts[2]
		}
	}

	return binding
}

// getIISAppPools lists all IIS application pools.
func (c *Collector) getIISAppPools() (*types.IISAppPoolsResult, error) {
	result := &types.IISAppPoolsResult{
		AppPools:  []types.IISAppPool{},
		Timestamp: time.Now(),
	}

	if !isIISInstalled() {
		result.Error = "IIS is not installed"
		return result, nil
	}

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", `
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		Get-ChildItem IIS:\AppPools | ForEach-Object {
			@{
				Name = $_.Name
				State = $_.State
				ManagedRuntimeVersion = $_.ManagedRuntimeVersion
				ManagedPipelineMode = $_.ManagedPipelineMode
				Enable32BitAppOnWin64 = $_.Enable32BitAppOnWin64
				StartMode = $_.StartMode
				AutoStart = $_.AutoStart
				QueueLength = $_.QueueLength
			}
		} | ConvertTo-Json -Depth 3
	`)

	out, err := cmd.Output()
	if err != nil {
		result.Error = fmt.Sprintf("failed to query app pools: %v", err)
		return result, nil
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" || outStr == "null" {
		return result, nil
	}

	var pools []psIISAppPool
	if strings.HasPrefix(outStr, "[") {
		if err := json.Unmarshal([]byte(outStr), &pools); err != nil {
			result.Error = fmt.Sprintf("failed to parse app pools: %v", err)
			return result, nil
		}
	} else {
		var pool psIISAppPool
		if err := json.Unmarshal([]byte(outStr), &pool); err != nil {
			result.Error = fmt.Sprintf("failed to parse app pool: %v", err)
			return result, nil
		}
		pools = []psIISAppPool{pool}
	}

	for _, p := range pools {
		pool := types.IISAppPool{
			Name:                  p.Name,
			State:                 p.State,
			ManagedRuntimeVersion: p.ManagedRuntimeVersion,
			ManagedPipelineMode:   p.ManagedPipelineMode,
			Enable32BitAppOnWin64: p.Enable32BitAppOnWin64,
			StartMode:             p.StartMode,
			AutoStart:             p.AutoStart,
			QueueLength:           p.QueueLength,
		}
		result.AppPools = append(result.AppPools, pool)
	}

	result.Count = len(result.AppPools)
	return result, nil
}

// getIISBindings lists all site bindings across all IIS sites.
func (c *Collector) getIISBindings() (*types.IISBindingsResult, error) {
	result := &types.IISBindingsResult{
		Bindings:  []types.IISSiteBinding{},
		Timestamp: time.Now(),
	}

	sitesResult, err := c.getIISSites()
	if err != nil {
		return result, err
	}

	if sitesResult.Error != "" {
		result.Error = sitesResult.Error
		return result, nil
	}

	for _, site := range sitesResult.Sites {
		for _, binding := range site.Bindings {
			result.Bindings = append(result.Bindings, types.IISSiteBinding{
				SiteName: site.Name,
				SiteID:   site.ID,
				Binding:  binding,
			})
		}
	}

	result.Count = len(result.Bindings)
	return result, nil
}

// getIISVirtualDirs lists all virtual directories across all IIS sites.
func (c *Collector) getIISVirtualDirs() (*types.IISVirtualDirsResult, error) {
	result := &types.IISVirtualDirsResult{
		Sites:     []types.IISSiteVirtualDirs{},
		Timestamp: time.Now(),
	}

	if !isIISInstalled() {
		result.Error = "IIS is not installed"
		return result, nil
	}

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", `
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		Get-Website | ForEach-Object {
			$siteName = $_.Name
			$siteID = $_.ID
			$vdirs = Get-WebVirtualDirectory -Site $siteName -ErrorAction SilentlyContinue | ForEach-Object {
				@{
					Path = $_.Path
					PhysicalPath = $_.PhysicalPath
				}
			}
			@{
				SiteName = $siteName
				SiteID = $siteID
				VirtualDirectories = $vdirs
			}
		} | ConvertTo-Json -Depth 4
	`)

	out, err := cmd.Output()
	if err != nil {
		result.Error = fmt.Sprintf("failed to query virtual directories: %v", err)
		return result, nil
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" || outStr == "null" {
		return result, nil
	}

	// Parse the output
	type psVDir struct {
		Path         string `json:"Path"`
		PhysicalPath string `json:"PhysicalPath"`
	}
	type psSiteVDirs struct {
		SiteName           string   `json:"SiteName"`
		SiteID             int      `json:"SiteID"`
		VirtualDirectories []psVDir `json:"VirtualDirectories"`
	}

	var sites []psSiteVDirs
	if strings.HasPrefix(outStr, "[") {
		if err := json.Unmarshal([]byte(outStr), &sites); err != nil {
			result.Error = fmt.Sprintf("failed to parse: %v", err)
			return result, nil
		}
	} else {
		var site psSiteVDirs
		if err := json.Unmarshal([]byte(outStr), &site); err != nil {
			result.Error = fmt.Sprintf("failed to parse: %v", err)
			return result, nil
		}
		sites = []psSiteVDirs{site}
	}

	totalCount := 0
	for _, s := range sites {
		siteVDirs := types.IISSiteVirtualDirs{
			SiteName:           s.SiteName,
			SiteID:             s.SiteID,
			VirtualDirectories: []types.IISVirtualDirectory{},
		}
		for _, v := range s.VirtualDirectories {
			siteVDirs.VirtualDirectories = append(siteVDirs.VirtualDirectories, types.IISVirtualDirectory{
				Path:         v.Path,
				PhysicalPath: v.PhysicalPath,
			})
			totalCount++
		}
		result.Sites = append(result.Sites, siteVDirs)
	}

	result.Count = totalCount
	return result, nil
}

// getIISHandlers lists all handler mappings configured in IIS.
func (c *Collector) getIISHandlers() (*types.IISHandlersResult, error) {
	result := &types.IISHandlersResult{
		Handlers:  []types.IISHandler{},
		Timestamp: time.Now(),
	}

	if !isIISInstalled() {
		result.Error = "IIS is not installed"
		return result, nil
	}

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", `
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		Get-WebHandler -PSPath 'IIS:\' | Select-Object Name, Path, Verb, Type, Modules, ScriptProcessor, ResourceType, RequireAccess, PreCondition | ConvertTo-Json
	`)

	out, err := cmd.Output()
	if err != nil {
		result.Error = fmt.Sprintf("failed to query handlers: %v", err)
		return result, nil
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" || outStr == "null" {
		return result, nil
	}

	type psHandler struct {
		Name            string `json:"Name"`
		Path            string `json:"Path"`
		Verb            string `json:"Verb"`
		Type            string `json:"Type"`
		Modules         string `json:"Modules"`
		ScriptProcessor string `json:"ScriptProcessor"`
		ResourceType    string `json:"ResourceType"`
		RequireAccess   string `json:"RequireAccess"`
		PreCondition    string `json:"PreCondition"`
	}

	var handlers []psHandler
	if strings.HasPrefix(outStr, "[") {
		if err := json.Unmarshal([]byte(outStr), &handlers); err != nil {
			result.Error = fmt.Sprintf("failed to parse: %v", err)
			return result, nil
		}
	} else {
		var handler psHandler
		if err := json.Unmarshal([]byte(outStr), &handler); err != nil {
			result.Error = fmt.Sprintf("failed to parse: %v", err)
			return result, nil
		}
		handlers = []psHandler{handler}
	}

	for _, h := range handlers {
		result.Handlers = append(result.Handlers, types.IISHandler{
			Name:            h.Name,
			Path:            h.Path,
			Verb:            h.Verb,
			Type:            h.Type,
			Modules:         h.Modules,
			ScriptProcessor: h.ScriptProcessor,
			ResourceType:    h.ResourceType,
			RequireAccess:   h.RequireAccess,
			PreCondition:    h.PreCondition,
		})
	}

	result.Count = len(result.Handlers)
	return result, nil
}

// getIISModules lists all modules installed in IIS.
func (c *Collector) getIISModules() (*types.IISModulesResult, error) {
	result := &types.IISModulesResult{
		GlobalModules: []types.IISModule{},
		Modules:       []types.IISModule{},
		Timestamp:     time.Now(),
	}

	if !isIISInstalled() {
		result.Error = "IIS is not installed"
		return result, nil
	}

	// Get global modules
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", `
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		Get-WebGlobalModule | Select-Object Name, Image, PreCondition | ConvertTo-Json
	`)

	out, err := cmd.Output()
	if err == nil {
		outStr := strings.TrimSpace(string(out))
		if outStr != "" && outStr != "null" {
			type psModule struct {
				Name         string `json:"Name"`
				Image        string `json:"Image"`
				PreCondition string `json:"PreCondition"`
			}

			var modules []psModule
			if strings.HasPrefix(outStr, "[") {
				json.Unmarshal([]byte(outStr), &modules)
			} else {
				var m psModule
				if err := json.Unmarshal([]byte(outStr), &m); err == nil {
					modules = []psModule{m}
				}
			}

			for _, m := range modules {
				result.GlobalModules = append(result.GlobalModules, types.IISModule{
					Name:         m.Name,
					Image:        m.Image,
					Type:         "Native",
					PreCondition: m.PreCondition,
				})
			}
		}
	}

	// Get managed modules
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command", `
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		Get-WebManagedModule -PSPath 'IIS:\' | Select-Object Name, Type, PreCondition | ConvertTo-Json
	`)

	out, err = cmd.Output()
	if err == nil {
		outStr := strings.TrimSpace(string(out))
		if outStr != "" && outStr != "null" {
			type psModule struct {
				Name         string `json:"Name"`
				Type         string `json:"Type"`
				PreCondition string `json:"PreCondition"`
			}

			var modules []psModule
			if strings.HasPrefix(outStr, "[") {
				json.Unmarshal([]byte(outStr), &modules)
			} else {
				var m psModule
				if err := json.Unmarshal([]byte(outStr), &m); err == nil {
					modules = []psModule{m}
				}
			}

			for _, m := range modules {
				result.Modules = append(result.Modules, types.IISModule{
					Name:         m.Name,
					Type:         m.Type,
					PreCondition: m.PreCondition,
				})
			}
		}
	}

	result.Count = len(result.GlobalModules) + len(result.Modules)
	return result, nil
}

// getIISSSLCerts lists all SSL certificate bindings in IIS.
func (c *Collector) getIISSSLCerts() (*types.IISSSLCertsResult, error) {
	result := &types.IISSSLCertsResult{
		Certificates: []types.IISSSLCert{},
		Timestamp:    time.Now(),
	}

	// Use netsh to get SSL cert bindings
	cmd := cmdexec.Command("netsh", "http", "show", "sslcert")
	out, err := cmd.Output()
	if err != nil {
		result.Error = fmt.Sprintf("failed to query SSL certs: %v", err)
		return result, nil
	}

	result.Certificates = parseNetshSSLCerts(string(out))
	result.Count = len(result.Certificates)
	return result, nil
}

// parseNetshSSLCerts parses the output of netsh http show sslcert.
func parseNetshSSLCerts(output string) []types.IISSSLCert {
	var certs []types.IISSSLCert
	var current *types.IISSSLCert

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// New certificate binding starts with IP:port
		if strings.HasPrefix(line, "IP:port") {
			if current != nil {
				certs = append(certs, *current)
			}
			current = &types.IISSSLCert{}
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 3 {
				current.IPPort = strings.TrimSpace(parts[1] + ":" + parts[2])
			}
			continue
		}

		// Hostname:port format
		if strings.HasPrefix(line, "Hostname:port") {
			if current != nil {
				certs = append(certs, *current)
			}
			current = &types.IISSSLCert{}
			parts := strings.SplitN(line, ":", 3)
			if len(parts) >= 3 {
				current.IPPort = strings.TrimSpace(parts[1] + ":" + parts[2])
			}
			continue
		}

		if current == nil {
			continue
		}

		// Parse other fields
		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "Certificate Hash":
					current.CertificateHash = value
				case "Application ID":
					current.ApplicationID = value
				case "Certificate Store Name":
					current.CertificateStoreName = value
				case "Verify Client Certificate Revocation":
					current.VerifyClientCertRevocation = strings.EqualFold(value, "Enabled")
				case "Verify Revocation Using Cached Client Certificate Only":
					current.VerifyRevocationWithCachedClientCertOnly = strings.EqualFold(value, "Enabled")
				case "Usage Check":
					current.UsageCheck = strings.EqualFold(value, "Enabled")
				case "Revocation Freshness Time":
					current.RevocationFreshnessTime, _ = strconv.Atoi(value)
				case "URL Retrieval Timeout":
					current.URLRetrievalTimeout, _ = strconv.Atoi(value)
				case "Ctl Identifier":
					current.CtlIdentifier = value
				case "Ctl Store Name":
					current.CtlStoreName = value
				case "DS Mapper Usage":
					current.DSMapperUsage = strings.EqualFold(value, "Enabled")
				case "Negotiate Client Certificate":
					current.NegotiateClientCert = strings.EqualFold(value, "Enabled")
				case "Reject Connections":
					current.RejectConnections = strings.EqualFold(value, "Enabled")
				case "Disable HTTP2":
					current.DisableHTTP2 = strings.EqualFold(value, "Set")
				case "Disable Legacy TLS Versions":
					current.DisableLegacyTLS = strings.EqualFold(value, "Set")
				case "Disable OCSP Stapling":
					current.DisableOCSPStapling = strings.EqualFold(value, "Set")
				case "Disable QUIC":
					current.DisableQUIC = strings.EqualFold(value, "Set")
				case "Disable TLS1.3 over TCP":
					current.DisableTLS13OverTCP = strings.EqualFold(value, "Set")
				case "Disable Session ID":
					current.DisableSessionID = strings.EqualFold(value, "Set")
				case "Enable Token Binding":
					current.EnableTokenBinding = strings.EqualFold(value, "Enabled")
				}
			}
		}
	}

	if current != nil {
		certs = append(certs, *current)
	}

	return certs
}

// getIISAuthConfig retrieves authentication configuration for all IIS sites.
func (c *Collector) getIISAuthConfig() (*types.IISAuthConfigResult, error) {
	result := &types.IISAuthConfigResult{
		Sites:     []types.IISSiteAuth{},
		Timestamp: time.Now(),
	}

	if !isIISInstalled() {
		result.Error = "IIS is not installed"
		return result, nil
	}

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", `
		Import-Module WebAdministration -ErrorAction SilentlyContinue
		Get-Website | ForEach-Object {
			$siteName = $_.Name
			$siteID = $_.ID
			$auth = @()

			# Anonymous
			$anon = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/anonymousAuthentication -PSPath "IIS:\Sites\$siteName" -Name enabled -ErrorAction SilentlyContinue
			if ($anon -ne $null) { $auth += @{ Type = 'Anonymous'; Enabled = $anon.Value } }

			# Basic
			$basic = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/basicAuthentication -PSPath "IIS:\Sites\$siteName" -Name enabled -ErrorAction SilentlyContinue
			if ($basic -ne $null) { $auth += @{ Type = 'Basic'; Enabled = $basic.Value } }

			# Windows
			$windows = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -PSPath "IIS:\Sites\$siteName" -Name enabled -ErrorAction SilentlyContinue
			if ($windows -ne $null) { $auth += @{ Type = 'Windows'; Enabled = $windows.Value } }

			# Digest
			$digest = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/digestAuthentication -PSPath "IIS:\Sites\$siteName" -Name enabled -ErrorAction SilentlyContinue
			if ($digest -ne $null) { $auth += @{ Type = 'Digest'; Enabled = $digest.Value } }

			@{
				SiteName = $siteName
				SiteID = $siteID
				Path = '/'
				Authentication = $auth
			}
		} | ConvertTo-Json -Depth 4
	`)

	out, err := cmd.Output()
	if err != nil {
		result.Error = fmt.Sprintf("failed to query auth config: %v", err)
		return result, nil
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" || outStr == "null" {
		return result, nil
	}

	type psAuthSetting struct {
		Type    string `json:"Type"`
		Enabled bool   `json:"Enabled"`
	}
	type psSiteAuth struct {
		SiteName       string          `json:"SiteName"`
		SiteID         int             `json:"SiteID"`
		Path           string          `json:"Path"`
		Authentication []psAuthSetting `json:"Authentication"`
	}

	var sites []psSiteAuth
	if strings.HasPrefix(outStr, "[") {
		if err := json.Unmarshal([]byte(outStr), &sites); err != nil {
			result.Error = fmt.Sprintf("failed to parse: %v", err)
			return result, nil
		}
	} else {
		var site psSiteAuth
		if err := json.Unmarshal([]byte(outStr), &site); err != nil {
			result.Error = fmt.Sprintf("failed to parse: %v", err)
			return result, nil
		}
		sites = []psSiteAuth{site}
	}

	for _, s := range sites {
		siteAuth := types.IISSiteAuth{
			SiteName:       s.SiteName,
			SiteID:         s.SiteID,
			Path:           s.Path,
			Authentication: []types.IISAuthSetting{},
		}
		for _, a := range s.Authentication {
			siteAuth.Authentication = append(siteAuth.Authentication, types.IISAuthSetting{
				Type:    a.Type,
				Enabled: a.Enabled,
			})
		}
		result.Sites = append(result.Sites, siteAuth)
	}

	result.Count = len(result.Sites)
	return result, nil
}

// isIISInstalled checks if IIS is installed.
func isIISInstalled() bool {
	// Check for IIS config directory
	winDir := os.Getenv("SystemRoot")
	if winDir == "" {
		winDir = `C:\Windows`
	}
	iisConfigPath := filepath.Join(winDir, "System32", "inetsrv", "config")

	if _, err := os.Stat(iisConfigPath); err == nil {
		return true
	}

	// Also check for IIS service
	cmd := cmdexec.Command("sc", "query", "W3SVC")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// Unused but kept for potential future use
var _ = regexp.MustCompile
