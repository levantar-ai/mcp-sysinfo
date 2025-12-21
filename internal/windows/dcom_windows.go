//go:build windows

package windows

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getDCOMApplications lists all registered DCOM applications.
func (c *Collector) getDCOMApplications() (*types.DCOMApplicationsResult, error) {
	result := &types.DCOMApplicationsResult{
		Applications: []types.DCOMApplication{},
		Timestamp:    time.Now(),
	}

	// Open HKCR\AppID
	key, err := registry.OpenKey(registry.CLASSES_ROOT, "AppID", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open AppID key: %v", err)
		return result, nil
	}
	defer key.Close()

	// Enumerate subkeys (each is an AppID GUID or executable name)
	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		result.Error = fmt.Sprintf("failed to enumerate AppID subkeys: %v", err)
		return result, nil
	}

	for _, subKey := range subKeys {
		// Only process GUID-format keys
		if !strings.HasPrefix(subKey, "{") {
			continue
		}

		app := c.readDCOMApplication(subKey)
		if app != nil {
			result.Applications = append(result.Applications, *app)
		}
	}

	result.Count = len(result.Applications)
	return result, nil
}

// readDCOMApplication reads DCOM application info from the registry.
func (c *Collector) readDCOMApplication(appID string) *types.DCOMApplication {
	path := "AppID\\" + appID
	key, err := registry.OpenKey(registry.CLASSES_ROOT, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()

	app := &types.DCOMApplication{
		AppID: appID,
	}

	// Read (Default) value for name
	name, _, err := key.GetStringValue("")
	if err == nil {
		app.Name = name
	}

	// Read LocalService
	localService, _, err := key.GetStringValue("LocalService")
	if err == nil {
		app.LocalService = localService
	}

	// Read ServiceParameters
	serviceParams, _, err := key.GetStringValue("ServiceParameters")
	if err == nil {
		app.ServiceParameters = serviceParams
	}

	// Read DllSurrogate
	dllSurrogate, _, err := key.GetStringValue("DllSurrogate")
	if err == nil {
		app.DllSurrogate = dllSurrogate
	}

	// Read RunAs
	runAs, _, err := key.GetStringValue("RunAs")
	if err == nil {
		app.RunAs = runAs
	}

	// Check for LaunchPermission
	_, _, err = key.GetBinaryValue("LaunchPermission")
	app.LaunchPermission = err == nil

	// Check for AccessPermission
	_, _, err = key.GetBinaryValue("AccessPermission")
	app.AccessPermission = err == nil

	return app
}

// getDCOMPermissions retrieves launch and access permissions for a DCOM application.
func (c *Collector) getDCOMPermissions(appID string) (*types.DCOMPermissionsResult, error) {
	result := &types.DCOMPermissionsResult{
		AppID:             appID,
		LaunchPermissions: []types.DCOMPermissionACE{},
		AccessPermissions: []types.DCOMPermissionACE{},
		Timestamp:         time.Now(),
	}

	// Normalize AppID
	if !strings.HasPrefix(appID, "{") {
		appID = "{" + appID + "}"
	}

	path := "AppID\\" + appID
	key, err := registry.OpenKey(registry.CLASSES_ROOT, path, registry.QUERY_VALUE)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open AppID key: %v", err)
		return result, nil
	}
	defer key.Close()

	// Read name
	name, _, err := key.GetStringValue("")
	if err == nil {
		result.Name = name
	}

	// Read LaunchPermission
	launchPerm, _, err := key.GetBinaryValue("LaunchPermission")
	if err == nil {
		result.LaunchPermissions = parseDCOMSecurityDescriptor(launchPerm, true)
	}

	// Read AccessPermission
	accessPerm, _, err := key.GetBinaryValue("AccessPermission")
	if err == nil {
		result.AccessPermissions = parseDCOMSecurityDescriptor(accessPerm, false)
	}

	return result, nil
}

// parseDCOMSecurityDescriptor parses a DCOM security descriptor binary value.
func parseDCOMSecurityDescriptor(sd []byte, isLaunch bool) []types.DCOMPermissionACE {
	var aces []types.DCOMPermissionACE

	if len(sd) < 20 {
		return aces
	}

	// Parse security descriptor structure
	// The structure is: SECURITY_DESCRIPTOR_RELATIVE
	// We need to find the DACL offset

	// Skip to DACL offset (at offset 16 in the structure)
	if len(sd) < 20 {
		return aces
	}

	daclOffset := binary.LittleEndian.Uint32(sd[16:20])
	if daclOffset == 0 || int(daclOffset) >= len(sd) {
		return aces
	}

	// Parse ACL at the DACL offset
	aclData := sd[daclOffset:]
	if len(aclData) < 8 {
		return aces
	}

	// ACL structure:
	// 0: AclRevision (1 byte)
	// 1: Sbz1 (1 byte)
	// 2-3: AclSize (2 bytes)
	// 4-5: AceCount (2 bytes)
	// 6-7: Sbz2 (2 bytes)

	aceCount := binary.LittleEndian.Uint16(aclData[4:6])
	offset := 8 // Start of first ACE

	for i := uint16(0); i < aceCount && offset < len(aclData); i++ {
		if offset+4 > len(aclData) {
			break
		}

		// ACE header
		aceType := aclData[offset]
		// aceFlags := aclData[offset+1]
		aceSize := binary.LittleEndian.Uint16(aclData[offset+2 : offset+4])

		if offset+int(aceSize) > len(aclData) {
			break
		}

		// Parse ACCESS_ALLOWED_ACE or ACCESS_DENIED_ACE
		if aceType == 0 || aceType == 1 { // ACCESS_ALLOWED or ACCESS_DENIED
			if offset+8 > len(aclData) {
				break
			}

			accessMask := binary.LittleEndian.Uint32(aclData[offset+4 : offset+8])

			// SID starts at offset+8
			sidOffset := offset + 8
			if sidOffset < len(aclData) {
				sid := parseSIDFromBytes(aclData[sidOffset:])
				trustee := lookupSIDString(sid)

				ace := types.DCOMPermissionACE{
					Trustee:    trustee,
					AccessType: "Allow",
				}
				if aceType == 1 {
					ace.AccessType = "Deny"
				}

				if isLaunch {
					// Launch permission flags
					ace.LocalLaunch = (accessMask & 0x01) != 0
					ace.RemoteLaunch = (accessMask & 0x02) != 0
					ace.LocalActivate = (accessMask & 0x04) != 0
					ace.RemoteActivate = (accessMask & 0x08) != 0
				} else {
					// Access permission flags
					ace.LocalAccess = (accessMask & 0x01) != 0
					ace.RemoteAccess = (accessMask & 0x02) != 0
				}

				aces = append(aces, ace)
			}
		}

		offset += int(aceSize)
	}

	return aces
}

// parseSIDFromBytes extracts a SID from a byte slice.
func parseSIDFromBytes(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	revision := data[0]
	subAuthCount := data[1]

	if len(data) < 8+int(subAuthCount)*4 {
		return ""
	}

	// Build SID string
	var identAuth uint64
	for i := 0; i < 6; i++ {
		identAuth = (identAuth << 8) | uint64(data[2+i])
	}

	sidStr := fmt.Sprintf("S-%d-%d", revision, identAuth)

	for i := 0; i < int(subAuthCount); i++ {
		subAuth := binary.LittleEndian.Uint32(data[8+i*4 : 8+(i+1)*4])
		sidStr += fmt.Sprintf("-%d", subAuth)
	}

	return sidStr
}

// lookupSIDString converts a SID string to an account name.
func lookupSIDString(sidStr string) string {
	if sidStr == "" {
		return ""
	}

	sid, err := windows.StringToSid(sidStr)
	if err != nil {
		return sidStr
	}

	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return sidStr
	}

	if domain != "" {
		return domain + "\\" + account
	}
	return account
}

// getDCOMIdentities lists RunAs identities for all DCOM applications.
func (c *Collector) getDCOMIdentities() (*types.DCOMIdentitiesResult, error) {
	result := &types.DCOMIdentitiesResult{
		Identities: []types.DCOMIdentity{},
		Timestamp:  time.Now(),
	}

	// Open HKCR\AppID
	key, err := registry.OpenKey(registry.CLASSES_ROOT, "AppID", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open AppID key: %v", err)
		return result, nil
	}
	defer key.Close()

	// Enumerate subkeys
	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		result.Error = fmt.Sprintf("failed to enumerate AppID subkeys: %v", err)
		return result, nil
	}

	for _, subKey := range subKeys {
		// Only process GUID-format keys
		if !strings.HasPrefix(subKey, "{") {
			continue
		}

		identity := c.readDCOMIdentity(subKey)
		if identity != nil {
			result.Identities = append(result.Identities, *identity)
		}
	}

	result.Count = len(result.Identities)
	return result, nil
}

// readDCOMIdentity reads the RunAs identity for a DCOM application.
func (c *Collector) readDCOMIdentity(appID string) *types.DCOMIdentity {
	path := "AppID\\" + appID
	key, err := registry.OpenKey(registry.CLASSES_ROOT, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()

	// Check for RunAs value
	runAs, _, err := key.GetStringValue("RunAs")
	if err != nil {
		// No RunAs configured - skip
		return nil
	}

	identity := &types.DCOMIdentity{
		AppID: appID,
		RunAs: runAs,
	}

	// Read name
	name, _, err := key.GetStringValue("")
	if err == nil {
		identity.Name = name
	}

	// Read LocalService if present
	localService, _, err := key.GetStringValue("LocalService")
	if err == nil {
		identity.ServiceName = localService
	}

	return identity
}

// getCOMSecurityDefaults retrieves machine-wide COM security settings.
func (c *Collector) getCOMSecurityDefaults() (*types.COMSecurityDefaults, error) {
	result := &types.COMSecurityDefaults{
		DefaultLaunchPermissions: []types.DCOMPermissionACE{},
		DefaultAccessPermissions: []types.DCOMPermissionACE{},
		Timestamp:                time.Now(),
	}

	// Open HKLM\SOFTWARE\Microsoft\Ole
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Ole`, registry.QUERY_VALUE)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open Ole key: %v", err)
		return result, nil
	}
	defer key.Close()

	// Read EnableDCOM
	enableDCOM, _, err := key.GetStringValue("EnableDCOM")
	if err == nil {
		result.EnableDCOM = strings.EqualFold(enableDCOM, "Y")
	}

	// Read EnableRemoteConnect
	enableRemote, _, err := key.GetStringValue("EnableRemoteConnect")
	if err == nil {
		result.EnableRemoteConnect = strings.EqualFold(enableRemote, "Y")
	}

	// Read LegacyAuthenticationLevel
	authLevel, _, err := key.GetIntegerValue("LegacyAuthenticationLevel")
	if err == nil {
		result.LegacyAuthenticationLevel = int(authLevel)
		result.AuthenticationLevel = authLevelToString(int(authLevel))
	}

	// Read LegacyImpersonationLevel
	impLevel, _, err := key.GetIntegerValue("LegacyImpersonationLevel")
	if err == nil {
		result.LegacyImpersonationLevel = int(impLevel)
		result.ImpersonationLevel = impLevelToString(int(impLevel))
	}

	// Read LegacyMutualAuthentication
	mutualAuth, _, err := key.GetIntegerValue("LegacyMutualAuthentication")
	if err == nil {
		result.LegacyMutualAuthentication = mutualAuth != 0
	}

	// Read LegacySecureReferences
	secureRefs, _, err := key.GetIntegerValue("LegacySecureReferences")
	if err == nil {
		result.LegacySecureReferences = secureRefs != 0
	}

	// Read DefaultLaunchPermission
	launchPerm, _, err := key.GetBinaryValue("DefaultLaunchPermission")
	if err == nil {
		result.DefaultLaunchPermissions = parseDCOMSecurityDescriptor(launchPerm, true)
	}

	// Read DefaultAccessPermission
	accessPerm, _, err := key.GetBinaryValue("DefaultAccessPermission")
	if err == nil {
		result.DefaultAccessPermissions = parseDCOMSecurityDescriptor(accessPerm, false)
	}

	// Read MachineLaunchRestriction
	machineLaunch, _, err := key.GetBinaryValue("MachineLaunchRestriction")
	if err == nil {
		result.MachineLaunchRestriction = parseDCOMSecurityDescriptor(machineLaunch, true)
	}

	// Read MachineAccessRestriction
	machineAccess, _, err := key.GetBinaryValue("MachineAccessRestriction")
	if err == nil {
		result.MachineAccessRestriction = parseDCOMSecurityDescriptor(machineAccess, false)
	}

	return result, nil
}

// authLevelToString converts an authentication level to a string.
func authLevelToString(level int) string {
	switch level {
	case 0:
		return "Default"
	case 1:
		return "None"
	case 2:
		return "Connect"
	case 3:
		return "Call"
	case 4:
		return "Packet"
	case 5:
		return "PacketIntegrity"
	case 6:
		return "PacketPrivacy"
	default:
		return fmt.Sprintf("Unknown(%d)", level)
	}
}

// impLevelToString converts an impersonation level to a string.
func impLevelToString(level int) string {
	switch level {
	case 0:
		return "Default"
	case 1:
		return "Anonymous"
	case 2:
		return "Identify"
	case 3:
		return "Impersonate"
	case 4:
		return "Delegate"
	default:
		return fmt.Sprintf("Unknown(%d)", level)
	}
}

// Ensure unused import warning is suppressed
var _ = unsafe.Sizeof(0)
