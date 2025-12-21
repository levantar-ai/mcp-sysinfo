//go:build windows

package windows

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Registry hive name to registry.Key mapping
var hiveMap = map[string]registry.Key{
	"HKLM":                  registry.LOCAL_MACHINE,
	"HKEY_LOCAL_MACHINE":    registry.LOCAL_MACHINE,
	"HKCU":                  registry.CURRENT_USER,
	"HKEY_CURRENT_USER":     registry.CURRENT_USER,
	"HKCR":                  registry.CLASSES_ROOT,
	"HKEY_CLASSES_ROOT":     registry.CLASSES_ROOT,
	"HKU":                   registry.USERS,
	"HKEY_USERS":            registry.USERS,
	"HKCC":                  registry.CURRENT_CONFIG,
	"HKEY_CURRENT_CONFIG":   registry.CURRENT_CONFIG,
	"HKPD":                  registry.PERFORMANCE_DATA,
	"HKEY_PERFORMANCE_DATA": registry.PERFORMANCE_DATA,
}

// Registry value type constants
const (
	REG_NONE                       = 0
	REG_SZ                         = 1
	REG_EXPAND_SZ                  = 2
	REG_BINARY                     = 3
	REG_DWORD                      = 4
	REG_DWORD_BIG_ENDIAN           = 5
	REG_LINK                       = 6
	REG_MULTI_SZ                   = 7
	REG_RESOURCE_LIST              = 8
	REG_FULL_RESOURCE_DESCRIPTOR   = 9
	REG_RESOURCE_REQUIREMENTS_LIST = 10
	REG_QWORD                      = 11
)

// regTypeToString converts a registry value type to a string.
func regTypeToString(valType uint32) string {
	switch valType {
	case REG_NONE:
		return "REG_NONE"
	case REG_SZ:
		return "REG_SZ"
	case REG_EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case REG_BINARY:
		return "REG_BINARY"
	case REG_DWORD:
		return "REG_DWORD"
	case REG_DWORD_BIG_ENDIAN:
		return "REG_DWORD_BIG_ENDIAN"
	case REG_LINK:
		return "REG_LINK"
	case REG_MULTI_SZ:
		return "REG_MULTI_SZ"
	case REG_RESOURCE_LIST:
		return "REG_RESOURCE_LIST"
	case REG_FULL_RESOURCE_DESCRIPTOR:
		return "REG_FULL_RESOURCE_DESCRIPTOR"
	case REG_RESOURCE_REQUIREMENTS_LIST:
		return "REG_RESOURCE_REQUIREMENTS_LIST"
	case REG_QWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_UNKNOWN(%d)", valType)
	}
}

// getHiveKey returns the registry.Key for a hive name.
func getHiveKey(hive string) (registry.Key, error) {
	key, ok := hiveMap[strings.ToUpper(hive)]
	if !ok {
		return 0, fmt.Errorf("unknown registry hive: %s", hive)
	}
	return key, nil
}

// getRegistryKey reads a registry key and its values.
func (c *Collector) getRegistryKey(hive, path string) (*types.RegistryKeyResult, error) {
	result := &types.RegistryKeyResult{
		Hive:      hive,
		Path:      path,
		Values:    []types.RegistryValue{},
		SubKeys:   []string{},
		Timestamp: time.Now(),
	}

	rootKey, err := getHiveKey(hive)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	key, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open key: %v", err)
		return result, nil
	}
	defer key.Close()

	// Get value names
	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		result.Error = fmt.Sprintf("failed to read value names: %v", err)
		return result, nil
	}

	// Read each value
	for _, name := range valueNames {
		val, valType, err := readRegistryValue(key, name)
		if err != nil {
			continue
		}

		dataSize := 0
		switch v := val.(type) {
		case string:
			dataSize = len(v)
		case []string:
			for _, s := range v {
				dataSize += len(s) + 1
			}
		case []byte:
			dataSize = len(v)
		case uint32:
			dataSize = 4
		case uint64:
			dataSize = 8
		}

		result.Values = append(result.Values, types.RegistryValue{
			Name:     name,
			Type:     regTypeToString(valType),
			Data:     val,
			DataSize: dataSize,
		})
	}

	// Get subkey names
	subKeys, err := key.ReadSubKeyNames(-1)
	if err == nil {
		result.SubKeys = subKeys
	}

	return result, nil
}

// readRegistryValue reads a single registry value.
func readRegistryValue(key registry.Key, name string) (interface{}, uint32, error) {
	// First, get the value type and size
	_, valType, err := key.GetValue(name, nil)
	if err != nil {
		return nil, 0, err
	}

	switch valType {
	case REG_SZ, REG_EXPAND_SZ:
		val, _, err := key.GetStringValue(name)
		return val, valType, err

	case REG_MULTI_SZ:
		val, _, err := key.GetStringsValue(name)
		return val, valType, err

	case REG_DWORD:
		val, _, err := key.GetIntegerValue(name)
		return uint32(val), valType, err

	case REG_QWORD:
		val, _, err := key.GetIntegerValue(name)
		return val, valType, err

	case REG_BINARY:
		val, _, err := key.GetBinaryValue(name)
		// Convert to hex string for JSON serialization
		return hex.EncodeToString(val), valType, err

	default:
		// For other types, read as binary
		val, _, err := key.GetBinaryValue(name)
		return hex.EncodeToString(val), valType, err
	}
}

// getRegistryTree enumerates registry keys recursively.
func (c *Collector) getRegistryTree(hive, path string, maxDepth int) (*types.RegistryTreeResult, error) {
	result := &types.RegistryTreeResult{
		Hive:      hive,
		Path:      path,
		MaxDepth:  maxDepth,
		Timestamp: time.Now(),
	}

	if maxDepth <= 0 {
		maxDepth = 3 // Default max depth
	}

	rootKey, err := getHiveKey(hive)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	totalKeys := 0
	root, err := c.enumerateKey(rootKey, path, 0, maxDepth, &totalKeys)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	result.Root = root
	result.TotalKeys = totalKeys

	return result, nil
}

// enumerateKey recursively enumerates a registry key.
func (c *Collector) enumerateKey(rootKey registry.Key, path string, depth, maxDepth int, totalKeys *int) (types.RegistryTreeNode, error) {
	node := types.RegistryTreeNode{
		Name: getKeyName(path),
		Path: path,
	}

	*totalKeys++

	key, err := registry.OpenKey(rootKey, path, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return node, nil // Skip inaccessible keys
	}
	defer key.Close()

	// Read values if at leaf level or always
	valueNames, err := key.ReadValueNames(-1)
	if err == nil {
		for _, name := range valueNames {
			val, valType, err := readRegistryValue(key, name)
			if err != nil {
				continue
			}
			node.Values = append(node.Values, types.RegistryValue{
				Name: name,
				Type: regTypeToString(valType),
				Data: val,
			})
		}
	}

	// Enumerate children if not at max depth
	if depth < maxDepth {
		subKeys, err := key.ReadSubKeyNames(-1)
		if err == nil {
			for _, subKey := range subKeys {
				childPath := path
				if childPath != "" {
					childPath += "\\"
				}
				childPath += subKey

				child, _ := c.enumerateKey(rootKey, childPath, depth+1, maxDepth, totalKeys)
				node.Children = append(node.Children, child)
			}
		}
	}

	return node, nil
}

// getKeyName extracts the key name from a path.
func getKeyName(path string) string {
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "\\")
	return parts[len(parts)-1]
}

// Windows API constants for security descriptors
const (
	OWNER_SECURITY_INFORMATION = 0x00000001
	GROUP_SECURITY_INFORMATION = 0x00000002
	DACL_SECURITY_INFORMATION  = 0x00000004
	SACL_SECURITY_INFORMATION  = 0x00000008

	// Standard access rights
	READ_CONTROL = 0x00020000
)

var (
	advapi32                       = windows.NewLazySystemDLL("advapi32.dll")
	procRegGetKeySecurity          = advapi32.NewProc("RegGetKeySecurity")
	procGetSecurityDescriptorOwner = advapi32.NewProc("GetSecurityDescriptorOwner")
	procGetSecurityDescriptorGroup = advapi32.NewProc("GetSecurityDescriptorGroup")
	procGetSecurityDescriptorDacl  = advapi32.NewProc("GetSecurityDescriptorDacl")
	procLookupAccountSidW          = advapi32.NewProc("LookupAccountSidW")
	procGetAce                     = advapi32.NewProc("GetAce")
	procGetAclInformation          = advapi32.NewProc("GetAclInformation")
)

// ACL_SIZE_INFORMATION structure
type aclSizeInformation struct {
	AceCount      uint32
	AclBytesInUse uint32
	AclBytesFree  uint32
}

// ACCESS_ALLOWED_ACE structure header
type aceHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

// ACCESS_ALLOWED_ACE structure
type accessAllowedAce struct {
	Header   aceHeader
	Mask     uint32
	SidStart uint32
}

// getRegistrySecurity retrieves the security descriptor for a registry key.
func (c *Collector) getRegistrySecurity(hive, path string) (*types.RegistrySecurityResult, error) {
	result := &types.RegistrySecurityResult{
		Hive:      hive,
		Path:      path,
		DACL:      []types.RegistryACE{},
		SACL:      []types.RegistryACE{},
		Timestamp: time.Now(),
	}

	rootKey, err := getHiveKey(hive)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	key, err := registry.OpenKey(rootKey, path, READ_CONTROL)
	if err != nil {
		result.Error = fmt.Sprintf("failed to open key: %v", err)
		return result, nil
	}
	defer key.Close()

	// Get security descriptor size
	var sdSize uint32
	secInfo := uint32(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)

	ret, _, _ := procRegGetKeySecurity.Call(
		uintptr(key),
		uintptr(secInfo),
		0,
		uintptr(unsafe.Pointer(&sdSize)),
	)

	if sdSize == 0 {
		result.Error = "failed to get security descriptor size"
		return result, nil
	}

	// Allocate buffer and get security descriptor
	sd := make([]byte, sdSize)
	ret, _, err = procRegGetKeySecurity.Call(
		uintptr(key),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&sd[0])),
		uintptr(unsafe.Pointer(&sdSize)),
	)

	if ret != 0 {
		result.Error = fmt.Sprintf("failed to get security descriptor: %v", err)
		return result, nil
	}

	// Parse owner
	var ownerSid *windows.SID
	var ownerDefaulted int32
	ret, _, _ = procGetSecurityDescriptorOwner.Call(
		uintptr(unsafe.Pointer(&sd[0])),
		uintptr(unsafe.Pointer(&ownerSid)),
		uintptr(unsafe.Pointer(&ownerDefaulted)),
	)
	if ret != 0 && ownerSid != nil {
		result.Owner = lookupSID(ownerSid)
	}

	// Parse group
	var groupSid *windows.SID
	var groupDefaulted int32
	ret, _, _ = procGetSecurityDescriptorGroup.Call(
		uintptr(unsafe.Pointer(&sd[0])),
		uintptr(unsafe.Pointer(&groupSid)),
		uintptr(unsafe.Pointer(&groupDefaulted)),
	)
	if ret != 0 && groupSid != nil {
		result.Group = lookupSID(groupSid)
	}

	// Parse DACL
	var daclPresent int32
	var dacl uintptr
	var daclDefaulted int32
	ret, _, _ = procGetSecurityDescriptorDacl.Call(
		uintptr(unsafe.Pointer(&sd[0])),
		uintptr(unsafe.Pointer(&daclPresent)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&daclDefaulted)),
	)
	if ret != 0 && daclPresent != 0 && dacl != 0 {
		result.DACL = parseACL(dacl)
	}

	return result, nil
}

// lookupSID converts a SID to an account name.
func lookupSID(sid *windows.SID) string {
	if sid == nil {
		return ""
	}

	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		// Return SID string if lookup fails
		return sid.String()
	}

	if domain != "" {
		return domain + "\\" + account
	}
	return account
}

// parseACL parses an ACL and returns a slice of ACEs.
func parseACL(acl uintptr) []types.RegistryACE {
	var aces []types.RegistryACE

	// Get ACL information
	var aclInfo aclSizeInformation
	ret, _, _ := procGetAclInformation.Call(
		acl,
		uintptr(unsafe.Pointer(&aclInfo)),
		unsafe.Sizeof(aclInfo),
		2, // AclSizeInformation
	)
	if ret == 0 {
		return aces
	}

	// Iterate through ACEs
	for i := uint32(0); i < aclInfo.AceCount; i++ {
		var ace uintptr
		ret, _, _ := procGetAce.Call(acl, uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ret == 0 {
			continue
		}

		header := (*aceHeader)(unsafe.Pointer(ace))
		accessAce := (*accessAllowedAce)(unsafe.Pointer(ace))

		// Get SID from ACE
		sidPtr := (*windows.SID)(unsafe.Pointer(uintptr(ace) + unsafe.Offsetof(accessAce.SidStart)))
		trustee := lookupSID(sidPtr)

		aceType := "Allow"
		if header.AceType == 1 { // ACCESS_DENIED_ACE_TYPE
			aceType = "Deny"
		}

		inherited := (header.AceFlags & 0x10) != 0 // INHERITED_ACE

		aces = append(aces, types.RegistryACE{
			Trustee:     trustee,
			AccessMask:  accessAce.Mask,
			AccessType:  aceType,
			Permissions: formatRegistryPermissions(accessAce.Mask),
			Inherited:   inherited,
		})
	}

	return aces
}

// formatRegistryPermissions converts an access mask to human-readable permissions.
func formatRegistryPermissions(mask uint32) string {
	var perms []string

	// Registry-specific permissions
	if mask&0x0001 != 0 {
		perms = append(perms, "QueryValue")
	}
	if mask&0x0002 != 0 {
		perms = append(perms, "SetValue")
	}
	if mask&0x0004 != 0 {
		perms = append(perms, "CreateSubKey")
	}
	if mask&0x0008 != 0 {
		perms = append(perms, "EnumerateSubKeys")
	}
	if mask&0x0010 != 0 {
		perms = append(perms, "Notify")
	}
	if mask&0x0020 != 0 {
		perms = append(perms, "CreateLink")
	}

	// Standard permissions
	if mask&0x00010000 != 0 {
		perms = append(perms, "Delete")
	}
	if mask&0x00020000 != 0 {
		perms = append(perms, "ReadControl")
	}
	if mask&0x00040000 != 0 {
		perms = append(perms, "WriteDac")
	}
	if mask&0x00080000 != 0 {
		perms = append(perms, "WriteOwner")
	}

	// Full control check
	if mask == 0xF003F {
		return "FullControl"
	}

	if len(perms) == 0 {
		return fmt.Sprintf("0x%08X", mask)
	}

	return strings.Join(perms, ", ")
}
