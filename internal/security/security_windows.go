//go:build windows

package security

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/internal/redact"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// macOS stubs - return not supported on Windows
func (c *Collector) getMacOSFileVaultStatus() (*types.MacOSFileVaultStatus, error) {
	return &types.MacOSFileVaultStatus{
		Error:     "FileVault not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSGatekeeperStatus() (*types.MacOSGatekeeperStatus, error) {
	return &types.MacOSGatekeeperStatus{
		Error:     "Gatekeeper not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSSIPStatus() (*types.MacOSSIPStatus, error) {
	return &types.MacOSSIPStatus{
		Error:     "SIP not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSXProtectStatus() (*types.MacOSXProtectStatus, error) {
	return &types.MacOSXProtectStatus{
		Error:     "XProtect not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSPFRules() (*types.MacOSPFRules, error) {
	return &types.MacOSPFRules{
		Error:     "macOS PF not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSMDMProfiles() (*types.MacOSMDMProfiles, error) {
	return &types.MacOSMDMProfiles{
		Error:     "macOS MDM not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSTCCPermissions() (*types.MacOSTCCPermissions, error) {
	return &types.MacOSTCCPermissions{
		Error:     "TCC not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getMacOSSecurityLogEvents() (*types.MacOSSecurityLogEvents, error) {
	return &types.MacOSSecurityLogEvents{
		Error:     "macOS unified logs not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

// Linux stubs - return not supported on Windows
func (c *Collector) getLinuxAuditdStatus() (*types.LinuxAuditdStatus, error) {
	return &types.LinuxAuditdStatus{
		Error:     "auditd not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxKernelLockdown() (*types.LinuxKernelLockdown, error) {
	return &types.LinuxKernelLockdown{
		Error:     "Kernel lockdown not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxSysctlSecurity() (*types.LinuxSysctlSecurity, error) {
	return &types.LinuxSysctlSecurity{
		Error:     "Linux sysctl not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxFirewallBackend() (*types.LinuxFirewallBackend, error) {
	return &types.LinuxFirewallBackend{
		Error:     "Linux firewall backend not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxMACDetailed() (*types.LinuxMACDetailed, error) {
	return &types.LinuxMACDetailed{
		Error:     "SELinux/AppArmor not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxPackageRepos() (*types.LinuxPackageRepos, error) {
	return &types.LinuxPackageRepos{
		Error:     "Linux package repos not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

func (c *Collector) getLinuxAutoUpdates() (*types.LinuxAutoUpdates, error) {
	return &types.LinuxAutoUpdates{
		Error:     "Linux auto-updates not available on Windows",
		Timestamp: time.Now(),
	}, nil
}

// Windows implementations

func (c *Collector) getWindowsDefenderStatus() (*types.WindowsDefenderStatus, error) {
	result := &types.WindowsDefenderStatus{
		Timestamp: time.Now(),
	}

	// Use PowerShell to get Defender status
	script := `Get-MpComputerStatus | ConvertTo-Json -Depth 2`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get Defender status: " + err.Error()
		return result, nil
	}

	var defenderStatus struct {
		RealTimeProtectionEnabled     bool   `json:"RealTimeProtectionEnabled"`
		BehaviorMonitorEnabled        bool   `json:"BehaviorMonitorEnabled"`
		IoavProtectionEnabled         bool   `json:"IoavProtectionEnabled"`
		OnAccessProtectionEnabled     bool   `json:"OnAccessProtectionEnabled"`
		AntivirusEnabled              bool   `json:"AntivirusEnabled"`
		AntispywareEnabled            bool   `json:"AntispywareEnabled"`
		IsTamperProtected             bool   `json:"IsTamperProtected"`
		AntivirusSignatureVersion     string `json:"AntivirusSignatureVersion"`
		AntivirusSignatureLastUpdated string `json:"AntivirusSignatureLastUpdated"`
		AMEngineVersion               string `json:"AMEngineVersion"`
		AMProductVersion              string `json:"AMProductVersion"`
		QuickScanAge                  int    `json:"QuickScanAge"`
		FullScanAge                   int    `json:"FullScanAge"`
	}

	if err := json.Unmarshal(output, &defenderStatus); err != nil {
		result.Error = "failed to parse Defender status: " + err.Error()
		return result, nil
	}

	result.RealTimeProtectionEnabled = defenderStatus.RealTimeProtectionEnabled
	result.BehaviorMonitorEnabled = defenderStatus.BehaviorMonitorEnabled
	result.IoavProtectionEnabled = defenderStatus.IoavProtectionEnabled
	result.OnAccessProtectionEnabled = defenderStatus.OnAccessProtectionEnabled
	result.AntivirusEnabled = defenderStatus.AntivirusEnabled
	result.AntispywareEnabled = defenderStatus.AntispywareEnabled
	result.TamperProtectionEnabled = defenderStatus.IsTamperProtected
	result.SignatureVersion = defenderStatus.AntivirusSignatureVersion
	result.EngineVersion = defenderStatus.AMEngineVersion
	result.ProductVersion = defenderStatus.AMProductVersion
	result.QuickScanAge = defenderStatus.QuickScanAge
	result.FullScanAge = defenderStatus.FullScanAge

	// Parse signature update time
	if defenderStatus.AntivirusSignatureLastUpdated != "" {
		if t, err := time.Parse("1/2/2006 3:04:05 PM", defenderStatus.AntivirusSignatureLastUpdated); err == nil {
			result.SignatureLastUpdated = t
		}
	}

	return result, nil
}

func (c *Collector) getWindowsFirewallProfiles() (*types.WindowsFirewallProfiles, error) {
	result := &types.WindowsFirewallProfiles{
		Timestamp: time.Now(),
	}

	script := `Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules, NotifyOnListen, LogAllowed, LogBlocked, LogFileName | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get firewall profiles: " + err.Error()
		return result, nil
	}

	var profiles []struct {
		Name                    string `json:"Name"`
		Enabled                 int    `json:"Enabled"` // 1 = True, 0 = False
		DefaultInboundAction    int    `json:"DefaultInboundAction"`
		DefaultOutboundAction   int    `json:"DefaultOutboundAction"`
		AllowInboundRules       int    `json:"AllowInboundRules"`
		AllowLocalFirewallRules int    `json:"AllowLocalFirewallRules"`
		AllowLocalIPsecRules    int    `json:"AllowLocalIPsecRules"`
		NotifyOnListen          int    `json:"NotifyOnListen"`
		LogAllowed              int    `json:"LogAllowed"`
		LogBlocked              int    `json:"LogBlocked"`
		LogFileName             string `json:"LogFileName"`
	}

	if err := json.Unmarshal(output, &profiles); err != nil {
		result.Error = "failed to parse firewall profiles: " + err.Error()
		return result, nil
	}

	actionToString := func(action int) string {
		switch action {
		case 2:
			return "Allow"
		case 4:
			return "Block"
		default:
			return "NotConfigured"
		}
	}

	for _, p := range profiles {
		profile := types.FirewallProfile{
			Name:                    p.Name,
			Enabled:                 p.Enabled == 1,
			DefaultInboundAction:    actionToString(p.DefaultInboundAction),
			DefaultOutboundAction:   actionToString(p.DefaultOutboundAction),
			AllowInboundRules:       p.AllowInboundRules == 1,
			AllowLocalFirewallRules: p.AllowLocalFirewallRules == 1,
			AllowLocalIPsecRules:    p.AllowLocalIPsecRules == 1,
			NotifyOnListen:          p.NotifyOnListen == 1,
			LogAllowed:              p.LogAllowed == 1,
			LogBlocked:              p.LogBlocked == 1,
			LogFilePath:             p.LogFileName,
		}

		switch strings.ToLower(p.Name) {
		case "domain":
			result.DomainProfile = profile
		case "private":
			result.PrivateProfile = profile
		case "public":
			result.PublicProfile = profile
		}
	}

	return result, nil
}

func (c *Collector) getBitLockerStatus() (*types.BitLockerStatus, error) {
	result := &types.BitLockerStatus{
		Timestamp: time.Now(),
	}

	script := `Get-BitLockerVolume | Select-Object MountPoint, VolumeType, ProtectionStatus, LockStatus, EncryptionMethod, EncryptionPercentage, KeyProtector | ConvertTo-Json -Depth 3`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get BitLocker status: " + err.Error()
		return result, nil
	}

	var volumes []struct {
		MountPoint           string `json:"MountPoint"`
		VolumeType           int    `json:"VolumeType"`
		ProtectionStatus     int    `json:"ProtectionStatus"`
		LockStatus           int    `json:"LockStatus"`
		EncryptionMethod     int    `json:"EncryptionMethod"`
		EncryptionPercentage int    `json:"EncryptionPercentage"`
		KeyProtector         []struct {
			KeyProtectorType int `json:"KeyProtectorType"`
		} `json:"KeyProtector"`
	}

	if err := json.Unmarshal(output, &volumes); err != nil {
		// Try single object
		var single struct {
			MountPoint           string `json:"MountPoint"`
			VolumeType           int    `json:"VolumeType"`
			ProtectionStatus     int    `json:"ProtectionStatus"`
			LockStatus           int    `json:"LockStatus"`
			EncryptionMethod     int    `json:"EncryptionMethod"`
			EncryptionPercentage int    `json:"EncryptionPercentage"`
			KeyProtector         []struct {
				KeyProtectorType int `json:"KeyProtectorType"`
			} `json:"KeyProtector"`
		}
		if err := json.Unmarshal(output, &single); err != nil {
			result.Error = "failed to parse BitLocker status: " + err.Error()
			return result, nil
		}
		volumes = append(volumes, single)
	}

	volumeTypeToString := func(vt int) string {
		switch vt {
		case 0:
			return "OperatingSystem"
		case 1:
			return "FixedData"
		case 2:
			return "Removable"
		default:
			return "Unknown"
		}
	}

	protectionStatusToString := func(ps int) string {
		switch ps {
		case 0:
			return "Off"
		case 1:
			return "On"
		case 2:
			return "Unknown"
		default:
			return "Unknown"
		}
	}

	lockStatusToString := func(ls int) string {
		switch ls {
		case 0:
			return "Unlocked"
		case 1:
			return "Locked"
		default:
			return "Unknown"
		}
	}

	encryptionMethodToString := func(em int) string {
		switch em {
		case 0:
			return "None"
		case 1:
			return "AES128_DIFFUSER"
		case 2:
			return "AES256_DIFFUSER"
		case 3:
			return "AES128"
		case 4:
			return "AES256"
		case 5:
			return "Hardware"
		case 6:
			return "XTS_AES128"
		case 7:
			return "XTS_AES256"
		default:
			return "Unknown"
		}
	}

	keyProtectorTypeToString := func(kp int) string {
		switch kp {
		case 0:
			return "Unknown"
		case 1:
			return "TPM"
		case 2:
			return "ExternalKey"
		case 3:
			return "NumericPassword"
		case 4:
			return "TPMAndPIN"
		case 5:
			return "TPMAndStartupKey"
		case 6:
			return "TPMAndPINAndStartupKey"
		case 7:
			return "PublicKey"
		case 8:
			return "Password"
		case 9:
			return "TPMNetworkKey"
		case 10:
			return "AdAccountOrGroup"
		default:
			return "Unknown"
		}
	}

	for _, v := range volumes {
		vol := types.BitLockerVolume{
			DriveLetter:       v.MountPoint,
			VolumeType:        volumeTypeToString(v.VolumeType),
			ProtectionStatus:  protectionStatusToString(v.ProtectionStatus),
			LockStatus:        lockStatusToString(v.LockStatus),
			EncryptionMethod:  encryptionMethodToString(v.EncryptionMethod),
			EncryptionPercent: v.EncryptionPercentage,
		}

		for _, kp := range v.KeyProtector {
			vol.KeyProtectors = append(vol.KeyProtectors, keyProtectorTypeToString(kp.KeyProtectorType))
		}

		result.Volumes = append(result.Volumes, vol)
	}

	result.Count = len(result.Volumes)
	return result, nil
}

func (c *Collector) getWindowsSMBShares() (*types.WindowsSMBShares, error) {
	result := &types.WindowsSMBShares{
		Timestamp: time.Now(),
	}

	script := `Get-SmbShare | Select-Object Name, Path, Description, ShareType, CurrentUsers, ConcurrentUserLimit, CachingMode, EncryptData, FolderEnumerationMode | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get SMB shares: " + err.Error()
		return result, nil
	}

	var shares []struct {
		Name                  string `json:"Name"`
		Path                  string `json:"Path"`
		Description           string `json:"Description"`
		ShareType             int    `json:"ShareType"`
		CurrentUsers          int    `json:"CurrentUsers"`
		ConcurrentUserLimit   int    `json:"ConcurrentUserLimit"`
		CachingMode           int    `json:"CachingMode"`
		EncryptData           bool   `json:"EncryptData"`
		FolderEnumerationMode int    `json:"FolderEnumerationMode"`
	}

	if err := json.Unmarshal(output, &shares); err != nil {
		result.Error = "failed to parse SMB shares: " + err.Error()
		return result, nil
	}

	shareTypeToString := func(st int) string {
		switch st {
		case 0:
			return "FileSystemDirectory"
		case 1:
			return "PrintQueue"
		case 2:
			return "Device"
		case 3:
			return "IPC"
		default:
			return "Unknown"
		}
	}

	for _, s := range shares {
		share := types.SMBShare{
			Name:              s.Name,
			Path:              s.Path,
			Description:       s.Description,
			ShareType:         shareTypeToString(s.ShareType),
			CurrentUsers:      s.CurrentUsers,
			ConcurrentUserLimit: s.ConcurrentUserLimit,
			EncryptData:       s.EncryptData,
		}
		result.Shares = append(result.Shares, share)
	}

	result.Count = len(result.Shares)
	return result, nil
}

func (c *Collector) getWindowsRDPConfig() (*types.WindowsRDPConfig, error) {
	result := &types.WindowsRDPConfig{
		Timestamp: time.Now(),
		Port:      3389, // Default RDP port
	}

	// Check if RDP is enabled via registry
	script := `
	$rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue
	$nla = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
	@{
		Enabled = if ($rdp.fDenyTSConnections -eq 0) { $true } else { $false }
		NLARequired = if ($nla.UserAuthentication -eq 1) { $true } else { $false }
		SecurityLayer = $nla.SecurityLayer
		MinEncryptionLevel = $nla.MinEncryptionLevel
		PortNumber = $nla.PortNumber
	} | ConvertTo-Json`

	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get RDP config: " + err.Error()
		return result, nil
	}

	var config struct {
		Enabled            bool `json:"Enabled"`
		NLARequired        bool `json:"NLARequired"`
		SecurityLayer      int  `json:"SecurityLayer"`
		MinEncryptionLevel int  `json:"MinEncryptionLevel"`
		PortNumber         int  `json:"PortNumber"`
	}

	if err := json.Unmarshal(output, &config); err != nil {
		result.Error = "failed to parse RDP config: " + err.Error()
		return result, nil
	}

	result.Enabled = config.Enabled
	result.NLARequired = config.NLARequired
	result.UserAuthenticationRequired = config.NLARequired

	if config.PortNumber > 0 {
		result.Port = config.PortNumber
	}

	switch config.SecurityLayer {
	case 0:
		result.SecurityLayer = "RDP"
	case 1:
		result.SecurityLayer = "Negotiate"
	case 2:
		result.SecurityLayer = "TLS"
	}

	switch config.MinEncryptionLevel {
	case 1:
		result.EncryptionLevel = "Low"
	case 2:
		result.EncryptionLevel = "ClientCompatible"
	case 3:
		result.EncryptionLevel = "High"
	case 4:
		result.EncryptionLevel = "FIPS"
	}

	return result, nil
}

func (c *Collector) getWindowsWinRMConfig() (*types.WindowsWinRMConfig, error) {
	result := &types.WindowsWinRMConfig{
		Timestamp: time.Now(),
		HTTPPort:  5985,
		HTTPSPort: 5986,
	}

	// Check WinRM service status
	script := `(Get-Service WinRM).Status`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil {
		result.ServiceRunning = strings.TrimSpace(string(output)) == "Running"
	}

	// Get WinRM configuration
	script = `
	$config = winrm get winrm/config 2>$null
	$client = winrm get winrm/config/client 2>$null
	$service = winrm get winrm/config/service 2>$null
	$auth = winrm get winrm/config/service/auth 2>$null
	@{
		AllowUnencrypted = $service -match 'AllowUnencrypted = true'
		Basic = $auth -match 'Basic = true'
		Kerberos = $auth -match 'Kerberos = true'
		Negotiate = $auth -match 'Negotiate = true'
		Certificate = $auth -match 'Certificate = true'
		CredSSP = $auth -match 'CredSSP = true'
		TrustedHosts = ($client -replace '.*TrustedHosts = ([^\r\n]*).*','$1').Trim()
	} | ConvertTo-Json`

	output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil {
		var config struct {
			AllowUnencrypted bool   `json:"AllowUnencrypted"`
			Basic            bool   `json:"Basic"`
			Kerberos         bool   `json:"Kerberos"`
			Negotiate        bool   `json:"Negotiate"`
			Certificate      bool   `json:"Certificate"`
			CredSSP          bool   `json:"CredSSP"`
			TrustedHosts     string `json:"TrustedHosts"`
		}
		if json.Unmarshal(output, &config) == nil {
			result.AllowUnencrypted = config.AllowUnencrypted
			result.BasicAuth = config.Basic
			result.KerberosAuth = config.Kerberos
			result.NegotiateAuth = config.Negotiate
			result.CertificateAuth = config.Certificate
			result.CredSSPAuth = config.CredSSP
			result.TrustedHosts = config.TrustedHosts
		}
	}

	// Get listeners
	script = `winrm enumerate winrm/config/listener 2>$null`
	output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil {
		outStr := string(output)
		if strings.Contains(outStr, "Transport = HTTP") {
			result.HTTPEnabled = true
		}
		if strings.Contains(outStr, "Transport = HTTPS") {
			result.HTTPSEnabled = true
		}
	}

	return result, nil
}

func (c *Collector) getWindowsAppLockerPolicy() (*types.WindowsAppLockerPolicy, error) {
	result := &types.WindowsAppLockerPolicy{
		Timestamp: time.Now(),
	}

	script := `Get-AppLockerPolicy -Effective -Xml`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "AppLocker not configured or access denied"
		result.EnforcementMode = "NotConfigured"
		return result, nil
	}

	outStr := string(output)
	result.Configured = len(outStr) > 100 // Has actual policy content

	if result.Configured {
		result.EnforcementMode = "Configured"

		// Count rule collections
		collections := []string{"Exe", "Msi", "Script", "Appx", "Dll"}
		for _, col := range collections {
			if strings.Contains(outStr, col+"Rules") {
				collection := types.AppLockerCollection{
					Type: col,
				}

				if strings.Contains(outStr, `EnforcementMode="Enabled"`) {
					collection.EnforcementMode = "Enabled"
				} else if strings.Contains(outStr, `EnforcementMode="AuditOnly"`) {
					collection.EnforcementMode = "AuditOnly"
				} else {
					collection.EnforcementMode = "NotConfigured"
				}

				// Count rules (approximate)
				collection.RuleCount = strings.Count(outStr, "<FilePathRule") +
					strings.Count(outStr, "<FileHashRule") +
					strings.Count(outStr, "<FilePublisherRule")

				result.RuleCollections = append(result.RuleCollections, collection)
			}
		}
	}

	return result, nil
}

func (c *Collector) getWindowsWDACStatus() (*types.WindowsWDACStatus, error) {
	result := &types.WindowsWDACStatus{
		Timestamp: time.Now(),
	}

	// Check Code Integrity status
	script := `
	$ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
	if ($ci) {
		@{
			VBSRunning = $ci.VirtualizationBasedSecurityStatus -eq 2
			CodeIntegrityPolicyEnforcementStatus = $ci.CodeIntegrityPolicyEnforcementStatus
			UsermodeCodeIntegrityPolicyEnforcementStatus = $ci.UsermodeCodeIntegrityPolicyEnforcementStatus
			HVCIRunning = 2 -in $ci.SecurityServicesRunning
			SecurityServicesRunning = $ci.SecurityServicesRunning
			SecurityServicesConfigured = $ci.SecurityServicesConfigured
		} | ConvertTo-Json
	}`

	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get WDAC status: " + err.Error()
		return result, nil
	}

	if len(output) > 0 {
		var status struct {
			VBSRunning                                   bool  `json:"VBSRunning"`
			CodeIntegrityPolicyEnforcementStatus         int   `json:"CodeIntegrityPolicyEnforcementStatus"`
			UsermodeCodeIntegrityPolicyEnforcementStatus int   `json:"UsermodeCodeIntegrityPolicyEnforcementStatus"`
			HVCIRunning                                  bool  `json:"HVCIRunning"`
			SecurityServicesRunning                      []int `json:"SecurityServicesRunning"`
			SecurityServicesConfigured                   []int `json:"SecurityServicesConfigured"`
		}

		if json.Unmarshal(output, &status) == nil {
			result.Enabled = status.CodeIntegrityPolicyEnforcementStatus > 0
			result.KMCIEnabled = status.CodeIntegrityPolicyEnforcementStatus == 2
			result.UMCIEnabled = status.UsermodeCodeIntegrityPolicyEnforcementStatus == 2
			result.HVCIEnabled = status.HVCIRunning

			if status.CodeIntegrityPolicyEnforcementStatus == 2 {
				result.EnforcementMode = "Enforced"
			} else if status.CodeIntegrityPolicyEnforcementStatus == 1 {
				result.EnforcementMode = "Audit"
			} else {
				result.EnforcementMode = "Off"
			}

			// Map service IDs to names
			serviceMap := map[int]string{
				1: "CredentialGuard",
				2: "HypervisorEnforcedCodeIntegrity",
				3: "SystemGuardSecureLaunch",
				4: "SMMMitigation",
			}

			for _, s := range status.SecurityServicesRunning {
				if name, ok := serviceMap[s]; ok {
					result.ActivePolicies = append(result.ActivePolicies, name)
				}
			}
		}
	}

	return result, nil
}

func (c *Collector) getWindowsLocalSecurityPolicy() (*types.WindowsLocalSecurityPolicy, error) {
	result := &types.WindowsLocalSecurityPolicy{
		Timestamp: time.Now(),
	}

	// Export security policy
	script := `
	$tempFile = [System.IO.Path]::GetTempFileName()
	secedit /export /cfg $tempFile /quiet
	$content = Get-Content $tempFile -Raw
	Remove-Item $tempFile
	$content`

	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to export security policy: " + err.Error()
		return result, nil
	}

	outStr := string(output)

	// Parse password policy
	result.PasswordPolicy = types.PasswordPolicy{}
	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MinimumPasswordLength") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.PasswordPolicy.MinimumLength, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		} else if strings.HasPrefix(line, "PasswordComplexity") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.PasswordPolicy.ComplexityEnabled = strings.TrimSpace(parts[1]) == "1"
			}
		} else if strings.HasPrefix(line, "MaximumPasswordAge") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.PasswordPolicy.MaximumAge, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		} else if strings.HasPrefix(line, "MinimumPasswordAge") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.PasswordPolicy.MinimumAge, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		} else if strings.HasPrefix(line, "PasswordHistorySize") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.PasswordPolicy.HistoryCount, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		} else if strings.HasPrefix(line, "ClearTextPassword") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.PasswordPolicy.ReversibleEncryption = strings.TrimSpace(parts[1]) == "1"
			}
		} else if strings.HasPrefix(line, "LockoutBadCount") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.AccountLockoutPolicy.LockoutThreshold, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		} else if strings.HasPrefix(line, "LockoutDuration") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.AccountLockoutPolicy.LockoutDuration, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		} else if strings.HasPrefix(line, "ResetLockoutCount") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				result.AccountLockoutPolicy.ResetCounterAfter, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
			}
		}
	}

	// Get audit policy
	script = `auditpol /get /category:* /r`
	output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil {
		result.AuditPolicy = parseAuditPolicy(string(output))
	}

	return result, nil
}

func parseAuditPolicy(output string) types.AuditPolicies {
	policy := types.AuditPolicies{}

	for _, line := range strings.Split(output, "\n") {
		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		category := strings.TrimSpace(fields[1])
		setting := strings.TrimSpace(fields[3])

		switch {
		case strings.Contains(category, "Account Logon"):
			policy.AccountLogon = setting
		case strings.Contains(category, "Account Management"):
			policy.AccountManagement = setting
		case strings.Contains(category, "Detailed Tracking"):
			policy.DetailedTracking = setting
		case strings.Contains(category, "DS Access"):
			policy.DSAccess = setting
		case strings.Contains(category, "Logon/Logoff"):
			policy.LogonLogoff = setting
		case strings.Contains(category, "Object Access"):
			policy.ObjectAccess = setting
		case strings.Contains(category, "Policy Change"):
			policy.PolicyChange = setting
		case strings.Contains(category, "Privilege Use"):
			policy.PrivilegeUse = setting
		case strings.Contains(category, "System"):
			policy.System = setting
		}
	}

	return policy
}

func (c *Collector) getWindowsGPOApplied() (*types.WindowsGPOApplied, error) {
	result := &types.WindowsGPOApplied{
		Timestamp: time.Now(),
	}

	// Check if domain joined
	script := `(Get-WmiObject Win32_ComputerSystem).PartOfDomain`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil {
		result.DomainJoined = strings.TrimSpace(string(output)) == "True"
	}

	if result.DomainJoined {
		script = `(Get-WmiObject Win32_ComputerSystem).Domain`
		output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
		if err == nil {
			result.DomainName = strings.TrimSpace(string(output))
		}
	}

	// Get applied GPOs
	script = `gpresult /r /scope:computer`
	output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get GPO list: " + err.Error()
		return result, nil
	}

	outStr := string(output)

	// Parse applied GPOs
	inAppliedSection := false
	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)

		if strings.Contains(line, "Applied Group Policy Objects") {
			inAppliedSection = true
			continue
		}

		if inAppliedSection {
			if line == "" || strings.Contains(line, "following GPOs") {
				inAppliedSection = false
				continue
			}

			if line != "" && !strings.HasPrefix(line, "The") && !strings.HasPrefix(line, "COMPUTER") {
				gpo := types.AppliedGPO{
					Name:    line,
					Enabled: true,
				}
				result.ComputerGPOs = append(result.ComputerGPOs, gpo)
			}
		}

		if strings.Contains(line, "Last time Group Policy was applied") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if t, err := time.Parse("1/2/2006 at 3:04:05 PM", strings.TrimSpace(parts[1])); err == nil {
					result.LastRefresh = t
				}
			}
		}
	}

	return result, nil
}

func (c *Collector) getWindowsCredentialGuard() (*types.WindowsCredentialGuard, error) {
	result := &types.WindowsCredentialGuard{
		Timestamp: time.Now(),
	}

	script := `
	$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
	if ($dg) {
		@{
			VBSStatus = $dg.VirtualizationBasedSecurityStatus
			SecurityServicesRunning = $dg.SecurityServicesRunning
			SecurityServicesConfigured = $dg.SecurityServicesConfigured
			RequiredSecurityProperties = $dg.RequiredSecurityProperties
		} | ConvertTo-Json
	}
	
	# Check LSA protection
	$lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags' -ErrorAction SilentlyContinue
	if ($lsa) { $lsa.LsaCfgFlags } else { 0 }`

	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to get Credential Guard status: " + err.Error()
		return result, nil
	}

	outStr := string(output)
	lines := strings.Split(outStr, "\n")

	// Parse JSON part
	jsonEnd := strings.Index(outStr, "}")
	if jsonEnd > 0 {
		jsonStr := outStr[:jsonEnd+1]
		var status struct {
			VBSStatus                  int   `json:"VBSStatus"`
			SecurityServicesRunning    []int `json:"SecurityServicesRunning"`
			SecurityServicesConfigured []int `json:"SecurityServicesConfigured"`
			RequiredSecurityProperties []int `json:"RequiredSecurityProperties"`
		}

		if json.Unmarshal([]byte(jsonStr), &status) == nil {
			result.VirtualizationBasedSecurity = status.VBSStatus == 2

			serviceMap := map[int]string{
				1: "CredentialGuard",
				2: "HypervisorEnforcedCodeIntegrity",
				3: "SystemGuardSecureLaunch",
				4: "SMMMitigation",
			}

			for _, s := range status.SecurityServicesRunning {
				if name, ok := serviceMap[s]; ok {
					result.SecurityServicesRunning = append(result.SecurityServicesRunning, name)
					if s == 1 {
						result.CredentialGuardEnabled = true
					}
				}
			}

			for _, s := range status.SecurityServicesConfigured {
				if name, ok := serviceMap[s]; ok {
					result.SecurityServicesConfigured = append(result.SecurityServicesConfigured, name)
				}
			}
		}
	}

	// Parse LSA config flags (last line)
	if len(lines) > 0 {
		lastLine := strings.TrimSpace(lines[len(lines)-1])
		if val, err := strconv.Atoi(lastLine); err == nil {
			result.LsaCfgFlags = val
			result.LsaIsoEnabled = val > 0
		}
	}

	return result, nil
}

func (c *Collector) getWindowsUpdateHealth() (*types.WindowsUpdateHealth, error) {
	result := &types.WindowsUpdateHealth{
		Timestamp: time.Now(),
	}

	// Check Windows Update service
	script := `(Get-Service wuauserv).Status`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil {
		result.ServiceRunning = strings.TrimSpace(string(output)) == "Running"
	}

	// Check for pending updates
	script = `
	$session = New-Object -ComObject Microsoft.Update.Session
	$searcher = $session.CreateUpdateSearcher()
	$result = $searcher.Search("IsInstalled=0")
	$result.Updates | Select-Object Title, @{N='KB';E={$_.KBArticleIDs -join ','}}, @{N='Category';E={$_.Categories[0].Name}}, MsrcSeverity, IsDownloaded | ConvertTo-Json`

	output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil && len(output) > 0 {
		var updates []struct {
			Title        string `json:"Title"`
			KB           string `json:"KB"`
			Category     string `json:"Category"`
			MsrcSeverity string `json:"MsrcSeverity"`
			IsDownloaded bool   `json:"IsDownloaded"`
		}

		if json.Unmarshal(output, &updates) == nil {
			for _, u := range updates {
				result.PendingUpdates = append(result.PendingUpdates, types.PendingUpdate{
					Title:        u.Title,
					KB:           u.KB,
					Category:     u.Category,
					Severity:     u.MsrcSeverity,
					IsDownloaded: u.IsDownloaded,
				})
			}
		}
	}
	result.PendingCount = len(result.PendingUpdates)

	// Check reboot required
	script = `Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'`
	output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil {
		result.RebootRequired = strings.TrimSpace(string(output)) == "True"
	}

	// Check update source (WSUS vs Windows Update)
	script = `Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue`
	output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil && strings.Contains(string(output), "WUServer") {
		result.UpdateSource = "WSUS"
		// Extract WSUS server
		for _, line := range strings.Split(string(output), "\n") {
			if strings.Contains(line, "WUServer") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					result.WSUSServer = strings.TrimSpace(parts[1])
				}
			}
		}
	} else {
		result.UpdateSource = "WindowsUpdate"
	}

	// Check deferral settings
	script = `Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue | Select-Object DeferFeatureUpdatesPeriodInDays, DeferQualityUpdatesPeriodInDays | ConvertTo-Json`
	output, err = cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err == nil {
		var deferral struct {
			DeferFeatureUpdatesPeriodInDays int `json:"DeferFeatureUpdatesPeriodInDays"`
			DeferQualityUpdatesPeriodInDays int `json:"DeferQualityUpdatesPeriodInDays"`
		}
		if json.Unmarshal(output, &deferral) == nil {
			result.DeferFeatureUpdates = deferral.DeferFeatureUpdatesPeriodInDays
			result.DeferQualityUpdates = deferral.DeferQualityUpdatesPeriodInDays
		}
	}

	return result, nil
}

func (c *Collector) getVendorServices() (*types.VendorServicesResult, error) {
	result := &types.VendorServicesResult{
		Platform:  "windows",
		Timestamp: time.Now(),
	}

	script := `Get-Service | Where-Object { $_.DisplayName -like '*Microsoft*' -or $_.DisplayName -like '*Windows*' } | Select-Object Name, DisplayName, Status, StartType | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-NoProfile", "-Command", script).Output()
	if err != nil {
		result.Error = "failed to list services: " + err.Error()
		return result, nil
	}

	var services []struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		Status      int    `json:"Status"`
		StartType   int    `json:"StartType"`
	}

	if err := json.Unmarshal(output, &services); err != nil {
		result.Error = "failed to parse services: " + err.Error()
		return result, nil
	}

	statusToString := func(s int) string {
		switch s {
		case 1:
			return "Stopped"
		case 2:
			return "StartPending"
		case 3:
			return "StopPending"
		case 4:
			return "Running"
		case 5:
			return "ContinuePending"
		case 6:
			return "PausePending"
		case 7:
			return "Paused"
		default:
			return "Unknown"
		}
	}

	startTypeToString := func(s int) string {
		switch s {
		case 0:
			return "Boot"
		case 1:
			return "System"
		case 2:
			return "Automatic"
		case 3:
			return "Manual"
		case 4:
			return "Disabled"
		default:
			return "Unknown"
		}
	}

	for _, s := range services {
		service := types.VendorService{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Status:      statusToString(s.Status),
			StartType:   startTypeToString(s.StartType),
			Vendor:      "Microsoft",
		}

		// Categorize
		nameLower := strings.ToLower(s.DisplayName)
		if strings.Contains(nameLower, "defender") || strings.Contains(nameLower, "security") || strings.Contains(nameLower, "firewall") {
			service.Category = "security"
		} else if strings.Contains(nameLower, "network") || strings.Contains(nameLower, "dns") || strings.Contains(nameLower, "dhcp") {
			service.Category = "networking"
		} else if strings.Contains(nameLower, "update") {
			service.Category = "updates"
		} else if strings.Contains(nameLower, "remote") || strings.Contains(nameLower, "terminal") {
			service.Category = "remote_access"
		}

		result.Services = append(result.Services, service)
	}

	result.Count = len(result.Services)
	return result, nil
}

// =============================================================================
// Original Phase 1.2.5 Security Configuration methods (existing functionality)
// =============================================================================

// getEnvVars returns system environment variables on Windows.
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
