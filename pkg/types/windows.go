package types

import "time"

// =============================================================================
// Registry Types (Phase 1.10.1)
// =============================================================================

// RegistryValue represents a single registry value.
type RegistryValue struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"` // REG_SZ, REG_DWORD, REG_BINARY, REG_MULTI_SZ, etc.
	Data     interface{} `json:"data"`
	DataSize int         `json:"data_size"`
}

// RegistryKeyResult represents the result of reading a registry key.
type RegistryKeyResult struct {
	Hive      string          `json:"hive"`
	Path      string          `json:"path"`
	Values    []RegistryValue `json:"values"`
	SubKeys   []string        `json:"sub_keys"`
	Error     string          `json:"error,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// RegistryTreeNode represents a node in the registry tree.
type RegistryTreeNode struct {
	Name     string             `json:"name"`
	Path     string             `json:"path"`
	Values   []RegistryValue    `json:"values,omitempty"`
	Children []RegistryTreeNode `json:"children,omitempty"`
}

// RegistryTreeResult represents a recursive enumeration of registry keys.
type RegistryTreeResult struct {
	Hive      string           `json:"hive"`
	Path      string           `json:"path"`
	Root      RegistryTreeNode `json:"root"`
	TotalKeys int              `json:"total_keys"`
	MaxDepth  int              `json:"max_depth"`
	Error     string           `json:"error,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// RegistryACE represents an Access Control Entry for a registry key.
type RegistryACE struct {
	Trustee     string `json:"trustee"`
	AccessMask  uint32 `json:"access_mask"`
	AccessType  string `json:"access_type"` // Allow, Deny
	Permissions string `json:"permissions"` // Human-readable
	Inherited   bool   `json:"inherited"`
}

// RegistrySecurityResult represents the security descriptor of a registry key.
type RegistrySecurityResult struct {
	Hive      string        `json:"hive"`
	Path      string        `json:"path"`
	Owner     string        `json:"owner"`
	Group     string        `json:"group"`
	DACL      []RegistryACE `json:"dacl"`
	SACL      []RegistryACE `json:"sacl,omitempty"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// =============================================================================
// DCOM/COM Types (Phase 1.10.2)
// =============================================================================

// DCOMApplication represents a registered DCOM application.
type DCOMApplication struct {
	AppID             string `json:"app_id"`
	Name              string `json:"name"`
	LocalService      string `json:"local_service,omitempty"`
	ServiceParameters string `json:"service_parameters,omitempty"`
	DllSurrogate      string `json:"dll_surrogate,omitempty"`
	RunAs             string `json:"run_as,omitempty"`
	LaunchPermission  bool   `json:"has_launch_permission"`
	AccessPermission  bool   `json:"has_access_permission"`
}

// DCOMApplicationsResult represents the list of registered DCOM applications.
type DCOMApplicationsResult struct {
	Applications []DCOMApplication `json:"applications"`
	Count        int               `json:"count"`
	Error        string            `json:"error,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
}

// DCOMPermissionACE represents a permission entry for DCOM.
type DCOMPermissionACE struct {
	Trustee        string `json:"trustee"`
	AccessType     string `json:"access_type"` // Allow, Deny
	LocalLaunch    bool   `json:"local_launch,omitempty"`
	RemoteLaunch   bool   `json:"remote_launch,omitempty"`
	LocalActivate  bool   `json:"local_activate,omitempty"`
	RemoteActivate bool   `json:"remote_activate,omitempty"`
	LocalAccess    bool   `json:"local_access,omitempty"`
	RemoteAccess   bool   `json:"remote_access,omitempty"`
}

// DCOMPermissionsResult represents the permissions for a DCOM application.
type DCOMPermissionsResult struct {
	AppID             string              `json:"app_id"`
	Name              string              `json:"name"`
	LaunchPermissions []DCOMPermissionACE `json:"launch_permissions"`
	AccessPermissions []DCOMPermissionACE `json:"access_permissions"`
	Error             string              `json:"error,omitempty"`
	Timestamp         time.Time           `json:"timestamp"`
}

// DCOMIdentity represents the RunAs identity for a DCOM application.
type DCOMIdentity struct {
	AppID       string `json:"app_id"`
	Name        string `json:"name"`
	RunAs       string `json:"run_as"` // Interactive User, Launching User, account name
	ServiceName string `json:"service_name,omitempty"`
}

// DCOMIdentitiesResult represents all DCOM application identities.
type DCOMIdentitiesResult struct {
	Identities []DCOMIdentity `json:"identities"`
	Count      int            `json:"count"`
	Error      string         `json:"error,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
}

// COMSecurityDefaults represents machine-wide COM security settings.
type COMSecurityDefaults struct {
	AuthenticationLevel            string              `json:"authentication_level"`
	ImpersonationLevel             string              `json:"impersonation_level"`
	EnableDCOM                     bool                `json:"enable_dcom"`
	EnableRemoteConnect            bool                `json:"enable_remote_connect"`
	DefaultLaunchPermissions       []DCOMPermissionACE `json:"default_launch_permissions"`
	DefaultAccessPermissions       []DCOMPermissionACE `json:"default_access_permissions"`
	MachineAccessRestriction       []DCOMPermissionACE `json:"machine_access_restriction,omitempty"`
	MachineLaunchRestriction       []DCOMPermissionACE `json:"machine_launch_restriction,omitempty"`
	LegacyAuthenticationLevel      int                 `json:"legacy_authentication_level"`
	LegacyImpersonationLevel       int                 `json:"legacy_impersonation_level"`
	LegacyMutualAuthentication     bool                `json:"legacy_mutual_authentication"`
	LegacySecureReferences         bool                `json:"legacy_secure_references"`
	EnableSecurityTrackingOverride bool                `json:"enable_security_tracking_override"`
	Error                          string              `json:"error,omitempty"`
	Timestamp                      time.Time           `json:"timestamp"`
}

// =============================================================================
// IIS Types (Phase 1.10.3)
// =============================================================================

// IISBinding represents a site binding (protocol, IP, port, hostname).
type IISBinding struct {
	Protocol           string `json:"protocol"` // http, https, net.tcp, etc.
	BindingInformation string `json:"binding_information"`
	IPAddress          string `json:"ip_address"`
	Port               int    `json:"port"`
	HostName           string `json:"host_name,omitempty"`
	CertificateHash    string `json:"certificate_hash,omitempty"`
	CertificateStore   string `json:"certificate_store,omitempty"`
	SSLFlags           int    `json:"ssl_flags,omitempty"`
}

// IISApplication represents an IIS application within a site.
type IISApplication struct {
	Path                    string `json:"path"`
	ApplicationPool         string `json:"application_pool"`
	PhysicalPath            string `json:"physical_path"`
	EnabledProtocols        string `json:"enabled_protocols"`
	PreloadEnabled          bool   `json:"preload_enabled"`
	ServiceAutoStartEnabled bool   `json:"service_auto_start_enabled"`
}

// IISSite represents an IIS website.
type IISSite struct {
	ID               int              `json:"id"`
	Name             string           `json:"name"`
	State            string           `json:"state"` // Started, Stopped
	PhysicalPath     string           `json:"physical_path"`
	Bindings         []IISBinding     `json:"bindings"`
	Applications     []IISApplication `json:"applications,omitempty"`
	LogFileDirectory string           `json:"log_file_directory,omitempty"`
	ServerAutoStart  bool             `json:"server_auto_start"`
	Limits           *IISSiteLimits   `json:"limits,omitempty"`
}

// IISSiteLimits represents site limits configuration.
type IISSiteLimits struct {
	MaxBandwidth      int64 `json:"max_bandwidth"`
	MaxConnections    int64 `json:"max_connections"`
	ConnectionTimeout int   `json:"connection_timeout"`
	MaxURLSegments    int   `json:"max_url_segments"`
}

// IISSitesResult represents the list of IIS websites.
type IISSitesResult struct {
	Sites     []IISSite `json:"sites"`
	Count     int       `json:"count"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// IISAppPool represents an IIS application pool.
type IISAppPool struct {
	Name                  string           `json:"name"`
	State                 string           `json:"state"` // Started, Stopped
	ManagedRuntimeVersion string           `json:"managed_runtime_version"`
	ManagedPipelineMode   string           `json:"managed_pipeline_mode"` // Integrated, Classic
	Enable32BitAppOnWin64 bool             `json:"enable_32bit_app_on_win64"`
	StartMode             string           `json:"start_mode"` // OnDemand, AlwaysRunning
	ProcessModel          *IISProcessModel `json:"process_model,omitempty"`
	Recycling             *IISRecycling    `json:"recycling,omitempty"`
	CPU                   *IISCPUSettings  `json:"cpu,omitempty"`
	AutoStart             bool             `json:"auto_start"`
	QueueLength           int              `json:"queue_length"`
}

// IISProcessModel represents app pool process model settings.
type IISProcessModel struct {
	IdentityType      string `json:"identity_type"` // LocalSystem, LocalService, NetworkService, ApplicationPoolIdentity, SpecificUser
	UserName          string `json:"user_name,omitempty"`
	IdleTimeout       int    `json:"idle_timeout"` // minutes
	MaxProcesses      int    `json:"max_processes"`
	PingingEnabled    bool   `json:"pinging_enabled"`
	PingInterval      int    `json:"ping_interval"` // seconds
	PingResponseTime  int    `json:"ping_response_time"`
	ShutdownTimeLimit int    `json:"shutdown_time_limit"`
	StartupTimeLimit  int    `json:"startup_time_limit"`
	LoadUserProfile   bool   `json:"load_user_profile"`
}

// IISRecycling represents app pool recycling settings.
type IISRecycling struct {
	DisallowOverlappingRotation    bool     `json:"disallow_overlapping_rotation"`
	DisallowRotationOnConfigChange bool     `json:"disallow_rotation_on_config_change"`
	PeriodicRestartMemory          int64    `json:"periodic_restart_memory"` // KB
	PeriodicRestartPrivateMemory   int64    `json:"periodic_restart_private_memory"`
	PeriodicRestartRequests        int64    `json:"periodic_restart_requests"`
	PeriodicRestartTime            int      `json:"periodic_restart_time"` // minutes
	PeriodicRestartSchedule        []string `json:"periodic_restart_schedule,omitempty"`
}

// IISCPUSettings represents app pool CPU settings.
type IISCPUSettings struct {
	Limit                    int    `json:"limit"`          // percentage * 1000
	Action                   string `json:"action"`         // NoAction, KillW3wp, Throttle, ThrottleUnderLoad
	ResetInterval            int    `json:"reset_interval"` // minutes
	SmpAffinitized           bool   `json:"smp_affinitized"`
	SmpProcessorAffinityMask int64  `json:"smp_processor_affinity_mask"`
}

// IISAppPoolsResult represents the list of IIS application pools.
type IISAppPoolsResult struct {
	AppPools  []IISAppPool `json:"app_pools"`
	Count     int          `json:"count"`
	Error     string       `json:"error,omitempty"`
	Timestamp time.Time    `json:"timestamp"`
}

// IISBindingsResult represents all bindings across all sites.
type IISBindingsResult struct {
	Bindings  []IISSiteBinding `json:"bindings"`
	Count     int              `json:"count"`
	Error     string           `json:"error,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// IISSiteBinding represents a binding with its associated site.
type IISSiteBinding struct {
	SiteName string     `json:"site_name"`
	SiteID   int        `json:"site_id"`
	Binding  IISBinding `json:"binding"`
}

// IISVirtualDirectory represents a virtual directory.
type IISVirtualDirectory struct {
	Path              string `json:"path"`
	PhysicalPath      string `json:"physical_path"`
	LogonMethod       string `json:"logon_method,omitempty"`
	AllowSubDirConfig bool   `json:"allow_sub_dir_config"`
}

// IISSiteVirtualDirs represents virtual directories for a site.
type IISSiteVirtualDirs struct {
	SiteName           string                `json:"site_name"`
	SiteID             int                   `json:"site_id"`
	VirtualDirectories []IISVirtualDirectory `json:"virtual_directories"`
}

// IISVirtualDirsResult represents all virtual directories.
type IISVirtualDirsResult struct {
	Sites     []IISSiteVirtualDirs `json:"sites"`
	Count     int                  `json:"count"`
	Error     string               `json:"error,omitempty"`
	Timestamp time.Time            `json:"timestamp"`
}

// IISHandler represents an IIS handler mapping.
type IISHandler struct {
	Name                string `json:"name"`
	Path                string `json:"path"` // *.aspx, *.php, etc.
	Verb                string `json:"verb"` // GET, POST, *, etc.
	Type                string `json:"type,omitempty"`
	Modules             string `json:"modules,omitempty"`
	ScriptProcessor     string `json:"script_processor,omitempty"`
	ResourceType        string `json:"resource_type,omitempty"`
	RequireAccess       string `json:"require_access,omitempty"`
	AllowPathInfo       bool   `json:"allow_path_info"`
	PreCondition        string `json:"pre_condition,omitempty"`
	ResponseBufferLimit int    `json:"response_buffer_limit,omitempty"`
}

// IISHandlersResult represents all handler mappings.
type IISHandlersResult struct {
	Handlers  []IISHandler `json:"handlers"`
	Count     int          `json:"count"`
	Error     string       `json:"error,omitempty"`
	Timestamp time.Time    `json:"timestamp"`
}

// IISModule represents an IIS module.
type IISModule struct {
	Name         string `json:"name"`
	Type         string `json:"type,omitempty"`  // Managed or Native
	Image        string `json:"image,omitempty"` // DLL path for native
	PreCondition string `json:"pre_condition,omitempty"`
	LockItem     bool   `json:"lock_item"`
}

// IISModulesResult represents all IIS modules.
type IISModulesResult struct {
	GlobalModules []IISModule `json:"global_modules"`
	Modules       []IISModule `json:"modules"`
	Count         int         `json:"count"`
	Error         string      `json:"error,omitempty"`
	Timestamp     time.Time   `json:"timestamp"`
}

// IISSSLCert represents an SSL certificate binding.
type IISSSLCert struct {
	IPPort                                   string `json:"ip_port"`
	CertificateHash                          string `json:"certificate_hash"`
	ApplicationID                            string `json:"application_id"`
	CertificateStoreName                     string `json:"certificate_store_name"`
	VerifyClientCertRevocation               bool   `json:"verify_client_cert_revocation"`
	VerifyRevocationWithCachedClientCertOnly bool   `json:"verify_revocation_with_cached_client_cert_only"`
	UsageCheck                               bool   `json:"usage_check"`
	RevocationFreshnessTime                  int    `json:"revocation_freshness_time"`
	URLRetrievalTimeout                      int    `json:"url_retrieval_timeout"`
	CtlIdentifier                            string `json:"ctl_identifier,omitempty"`
	CtlStoreName                             string `json:"ctl_store_name,omitempty"`
	DSMapperUsage                            bool   `json:"ds_mapper_usage"`
	NegotiateClientCert                      bool   `json:"negotiate_client_cert"`
	RejectConnections                        bool   `json:"reject_connections"`
	DisableHTTP2                             bool   `json:"disable_http2"`
	DisableLegacyTLS                         bool   `json:"disable_legacy_tls"`
	DisableOCSPStapling                      bool   `json:"disable_ocsp_stapling"`
	DisableQUIC                              bool   `json:"disable_quic"`
	DisableTLS13OverTCP                      bool   `json:"disable_tls13_over_tcp"`
	DisableSessionID                         bool   `json:"disable_session_id"`
	EnableTokenBinding                       bool   `json:"enable_token_binding"`
}

// IISSSLCertsResult represents all SSL certificate bindings.
type IISSSLCertsResult struct {
	Certificates []IISSSLCert `json:"certificates"`
	Count        int          `json:"count"`
	Error        string       `json:"error,omitempty"`
	Timestamp    time.Time    `json:"timestamp"`
}

// IISAuthSetting represents authentication settings for a location.
type IISAuthSetting struct {
	Type               string `json:"type"` // Anonymous, Basic, Windows, Digest, etc.
	Enabled            bool   `json:"enabled"`
	DefaultLogonDomain string `json:"default_logon_domain,omitempty"`
	Realm              string `json:"realm,omitempty"`
	LogonMethod        string `json:"logon_method,omitempty"`
}

// IISSiteAuth represents authentication settings for a site.
type IISSiteAuth struct {
	SiteName       string           `json:"site_name"`
	SiteID         int              `json:"site_id"`
	Path           string           `json:"path"` // / for root, or specific path
	Authentication []IISAuthSetting `json:"authentication"`
}

// IISAuthConfigResult represents authentication configuration across all sites.
type IISAuthConfigResult struct {
	Sites     []IISSiteAuth `json:"sites"`
	Count     int           `json:"count"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}
