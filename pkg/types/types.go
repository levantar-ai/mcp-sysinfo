// Package types defines common types used across the mcp-sysinfo project.
package types

import "time"

// CPUInfo represents CPU metrics.
type CPUInfo struct {
	Percent       float64        `json:"percent"`
	PerCPU        []float64      `json:"per_cpu,omitempty"`
	Count         int            `json:"count"`
	PhysicalCount int            `json:"physical_count"`
	Frequency     *FrequencyInfo `json:"frequency,omitempty"`
	LoadAverage   *LoadAverage   `json:"load_average,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
}

// FrequencyInfo represents CPU frequency.
type FrequencyInfo struct {
	Current float64 `json:"current"`
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
}

// LoadAverage represents system load (Unix-like systems).
type LoadAverage struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// MemoryInfo represents memory metrics.
type MemoryInfo struct {
	Total         uint64    `json:"total"`
	Available     uint64    `json:"available"`
	Used          uint64    `json:"used"`
	UsedPercent   float64   `json:"used_percent"`
	Free          uint64    `json:"free"`
	Active        uint64    `json:"active,omitempty"`         // Linux/macOS
	Inactive      uint64    `json:"inactive,omitempty"`       // Linux/macOS
	Wired         uint64    `json:"wired,omitempty"`          // macOS only
	Compressed    uint64    `json:"compressed,omitempty"`     // macOS only
	Buffers       uint64    `json:"buffers,omitempty"`        // Linux only
	Cached        uint64    `json:"cached,omitempty"`         // Linux/Windows
	Shared        uint64    `json:"shared,omitempty"`         // Linux only
	Slab          uint64    `json:"slab,omitempty"`           // Linux only
	SReclaimable  uint64    `json:"sreclaimable,omitempty"`   // Linux only
	SUReClaimable uint64    `json:"sunreclaimable,omitempty"` // Linux only
	PageTables    uint64    `json:"page_tables,omitempty"`    // Linux only
	SwapCached    uint64    `json:"swap_cached,omitempty"`    // Linux only
	Swap          *SwapInfo `json:"swap,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// SwapInfo represents swap memory metrics.
type SwapInfo struct {
	Total       uint64    `json:"total"`
	Used        uint64    `json:"used"`
	Free        uint64    `json:"free"`
	UsedPercent float64   `json:"used_percent"`
	Sin         uint64    `json:"sin,omitempty"`  // Pages swapped in (Linux)
	Sout        uint64    `json:"sout,omitempty"` // Pages swapped out (Linux)
	Timestamp   time.Time `json:"timestamp"`
}

// DiskInfo represents disk metrics.
type DiskInfo struct {
	Partitions []PartitionInfo `json:"partitions"`
	Timestamp  time.Time       `json:"timestamp"`
}

// PartitionInfo represents a single disk partition.
type PartitionInfo struct {
	Device      string  `json:"device"`
	Mountpoint  string  `json:"mountpoint"`
	Fstype      string  `json:"fstype"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

// DiskIOCounters represents disk I/O statistics.
type DiskIOCounters struct {
	ReadCount      uint64 `json:"read_count"`
	WriteCount     uint64 `json:"write_count"`
	ReadBytes      uint64 `json:"read_bytes"`
	WriteBytes     uint64 `json:"write_bytes"`
	ReadTime       uint64 `json:"read_time"`
	WriteTime      uint64 `json:"write_time"`
	ReadMerged     uint64 `json:"read_merged,omitempty"`
	WriteMerged    uint64 `json:"write_merged,omitempty"`
	IopsInProgress uint64 `json:"iops_in_progress,omitempty"`
	IoTime         uint64 `json:"io_time,omitempty"`
	WeightedIoTime uint64 `json:"weighted_io_time,omitempty"`
}

// NetworkInfo represents network metrics.
type NetworkInfo struct {
	Interfaces []InterfaceInfo `json:"interfaces"`
	Timestamp  time.Time       `json:"timestamp"`
}

// InterfaceInfo represents a single network interface.
type InterfaceInfo struct {
	Name        string   `json:"name"`
	BytesSent   uint64   `json:"bytes_sent,omitempty"`
	BytesRecv   uint64   `json:"bytes_recv,omitempty"`
	PacketsSent uint64   `json:"packets_sent,omitempty"`
	PacketsRecv uint64   `json:"packets_recv,omitempty"`
	Addrs       []string `json:"addrs,omitempty"`
	MTU         int      `json:"mtu"`
	IsUp        bool     `json:"is_up"`
	MAC         string   `json:"mac,omitempty"`
}

// NetworkIOCounters represents network I/O statistics for an interface.
type NetworkIOCounters struct {
	BytesSent   uint64 `json:"bytes_sent"`
	BytesRecv   uint64 `json:"bytes_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	ErrIn       uint64 `json:"err_in"`
	ErrOut      uint64 `json:"err_out"`
	DropIn      uint64 `json:"drop_in"`
	DropOut     uint64 `json:"drop_out"`
}

// ConnectionInfo represents a network connection.
type ConnectionInfo struct {
	Type       string `json:"type"` // tcp, udp, tcp6, udp6
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	Status     string `json:"status"`
	PID        int32  `json:"pid,omitempty"`
}

// ProcessInfo represents a single process.
type ProcessInfo struct {
	PID        int32     `json:"pid"`
	Name       string    `json:"name"`
	Username   string    `json:"username,omitempty"`
	CPUPercent float64   `json:"cpu_percent"`
	MemPercent float32   `json:"mem_percent"`
	MemRSS     uint64    `json:"mem_rss"`
	Status     string    `json:"status"`
	CreateTime time.Time `json:"create_time"`
	Cmdline    string    `json:"cmdline,omitempty"`
}

// ProcessList represents a list of processes.
type ProcessList struct {
	Processes []ProcessInfo `json:"processes"`
	Total     int           `json:"total"`
	Timestamp time.Time     `json:"timestamp"`
}

// UptimeInfo represents system uptime.
type UptimeInfo struct {
	BootTime  time.Time     `json:"boot_time"`
	Uptime    time.Duration `json:"uptime"`
	UptimeStr string        `json:"uptime_str"`
	Timestamp time.Time     `json:"timestamp"`
}

// TemperatureInfo represents temperature sensor data.
type TemperatureInfo struct {
	Sensors   []SensorInfo `json:"sensors"`
	Timestamp time.Time    `json:"timestamp"`
}

// SensorInfo represents a single temperature sensor.
type SensorInfo struct {
	Name        string  `json:"name"`
	Temperature float64 `json:"temperature"`
	High        float64 `json:"high,omitempty"`
	Critical    float64 `json:"critical,omitempty"`
}

// GPUInfo represents GPU metrics.
type GPUInfo struct {
	GPUs      []GPU     `json:"gpus"`
	Timestamp time.Time `json:"timestamp"`
}

// GPU represents a single GPU.
type GPU struct {
	Index       int     `json:"index"`
	Name        string  `json:"name"`
	Vendor      string  `json:"vendor"`
	MemoryTotal uint64  `json:"memory_total"`
	MemoryUsed  uint64  `json:"memory_used"`
	MemoryFree  uint64  `json:"memory_free"`
	Utilization float64 `json:"utilization"`
	Temperature float64 `json:"temperature,omitempty"`
}

// ContainerInfo represents container metrics.
type ContainerInfo struct {
	Containers []Container `json:"containers"`
	Timestamp  time.Time   `json:"timestamp"`
}

// Container represents a single container.
type Container struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Image       string  `json:"image"`
	Status      string  `json:"status"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemoryUsed  uint64  `json:"memory_used"`
	MemoryLimit uint64  `json:"memory_limit"`
	NetworkRx   uint64  `json:"network_rx"`
	NetworkTx   uint64  `json:"network_tx"`
}

// HealthScore represents overall system health.
type HealthScore struct {
	Score      int            `json:"score"` // 0-100
	Categories map[string]int `json:"categories"`
	Issues     []Issue        `json:"issues"`
	Timestamp  time.Time      `json:"timestamp"`
}

// Issue represents a detected system issue.
type Issue struct {
	Severity   string `json:"severity"` // critical, warning, info
	Category   string `json:"category"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

// Alert represents an alert configuration.
type Alert struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Condition string                 `json:"condition"`
	Threshold float64                `json:"threshold"`
	Duration  time.Duration          `json:"duration"`
	Severity  string                 `json:"severity"`
	Actions   []string               `json:"actions"`
	Enabled   bool                   `json:"enabled"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// Platform represents the current platform.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformWindows Platform = "windows"
	PlatformUnknown Platform = "unknown"
)

// LogEntry represents a single log entry.
type LogEntry struct {
	Timestamp time.Time         `json:"timestamp"`
	Source    string            `json:"source"`          // e.g., "kernel", "sshd", "nginx"
	Level     string            `json:"level,omitempty"` // e.g., "info", "warning", "error"
	Message   string            `json:"message"`
	PID       int32             `json:"pid,omitempty"`
	Unit      string            `json:"unit,omitempty"`   // systemd unit name
	Fields    map[string]string `json:"fields,omitempty"` // additional structured fields
}

// LogResult represents the result of a log query.
type LogResult struct {
	Entries   []LogEntry `json:"entries"`
	Source    string     `json:"source"` // e.g., "journald", "syslog", "eventlog"
	Count     int        `json:"count"`
	Truncated bool       `json:"truncated"` // true if results were limited
	Timestamp time.Time  `json:"timestamp"`
}

// LogQuery represents parameters for querying logs.
type LogQuery struct {
	Lines    int       `json:"lines,omitempty"`    // max lines to return (default 100)
	Since    time.Time `json:"since,omitempty"`    // start time filter
	Until    time.Time `json:"until,omitempty"`    // end time filter
	Unit     string    `json:"unit,omitempty"`     // systemd unit filter
	Priority int       `json:"priority,omitempty"` // syslog priority (0-7)
	Grep     string    `json:"grep,omitempty"`     // text filter
	Source   string    `json:"source,omitempty"`   // source filter (e.g., "sshd")
	Level    string    `json:"level,omitempty"`    // level filter
	Follow   bool      `json:"follow,omitempty"`   // tail -f mode (not implemented)
}

// JournalLogResult represents systemd journal query results.
type JournalLogResult struct {
	LogResult
	Boots []BootInfo `json:"boots,omitempty"` // available boot IDs
}

// BootInfo represents a system boot entry.
type BootInfo struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Current   bool      `json:"current"`
}

// EventLogResult represents Windows Event Log query results.
type EventLogResult struct {
	LogResult
	Channel string `json:"channel"` // e.g., "System", "Application", "Security"
}

// EventLogQuery extends LogQuery for Windows Event Log.
type EventLogQuery struct {
	LogQuery
	Channel  string `json:"channel,omitempty"`  // System, Application, Security, etc.
	Provider string `json:"provider,omitempty"` // Event provider filter
	EventID  int    `json:"event_id,omitempty"` // Specific event ID
	Level    int    `json:"level,omitempty"`    // 1=Critical, 2=Error, 3=Warning, 4=Info
}

// KernelLogResult represents kernel/dmesg log results.
type KernelLogResult struct {
	LogResult
	BootTime time.Time `json:"boot_time,omitempty"`
}

// AuthLogResult represents authentication log results.
type AuthLogResult struct {
	LogResult
	FailedLogins     int `json:"failed_logins,omitempty"`
	SuccessfulLogins int `json:"successful_logins,omitempty"`
}

// AppLogQuery represents parameters for application log queries.
type AppLogQuery struct {
	LogQuery
	Path    string   `json:"path,omitempty"`    // specific log file path
	Paths   []string `json:"paths,omitempty"`   // multiple paths
	Pattern string   `json:"pattern,omitempty"` // glob pattern for log files
}

// ScheduledTasksResult represents scheduled tasks query results.
type ScheduledTasksResult struct {
	Tasks     []ScheduledTask `json:"tasks"`
	Count     int             `json:"count"`
	Source    string          `json:"source"` // "taskscheduler", "at", "cron", "launchd"
	Timestamp time.Time       `json:"timestamp"`
}

// ScheduledTask represents a single scheduled task.
type ScheduledTask struct {
	Name        string    `json:"name"`
	Path        string    `json:"path,omitempty"` // Task path/location
	Status      string    `json:"status"`         // Enabled, Disabled, Running, Ready
	NextRun     time.Time `json:"next_run,omitempty"`
	LastRun     time.Time `json:"last_run,omitempty"`
	LastResult  int       `json:"last_result,omitempty"` // Exit code
	Author      string    `json:"author,omitempty"`
	Description string    `json:"description,omitempty"`
	Command     string    `json:"command,omitempty"` // Command/action to run
	Arguments   string    `json:"arguments,omitempty"`
	RunAsUser   string    `json:"run_as_user,omitempty"`
	Schedule    string    `json:"schedule,omitempty"`     // Human-readable schedule
	TriggerType string    `json:"trigger_type,omitempty"` // Daily, Weekly, OnBoot, etc.
}

// CronJobsResult represents cron jobs query results.
type CronJobsResult struct {
	Jobs      []CronJob `json:"jobs"`
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

// CronJob represents a single cron job entry.
type CronJob struct {
	Schedule    string `json:"schedule"` // "0 * * * *" or "@daily"
	Command     string `json:"command"`
	User        string `json:"user,omitempty"`
	Source      string `json:"source"` // "/etc/crontab", "user", "/etc/cron.d/name"
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"` // Comment above the entry
}

// StartupItemsResult represents startup items query results.
type StartupItemsResult struct {
	Items     []StartupItem `json:"items"`
	Count     int           `json:"count"`
	Timestamp time.Time     `json:"timestamp"`
}

// StartupItem represents a startup program or service.
type StartupItem struct {
	Name        string `json:"name"`
	Command     string `json:"command"`
	Location    string `json:"location"` // Registry key, plist path, etc.
	Type        string `json:"type"`     // "registry", "startup_folder", "launchagent", "systemd"
	Enabled     bool   `json:"enabled"`
	User        string `json:"user,omitempty"` // User scope or "system"
	Description string `json:"description,omitempty"`
}

// SystemdServicesResult represents systemd services query results.
type SystemdServicesResult struct {
	Services  []SystemdService `json:"services"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// SystemdService represents a systemd service unit.
type SystemdService struct {
	Name        string `json:"name"`         // e.g., "nginx.service"
	LoadState   string `json:"load_state"`   // loaded, not-found, masked
	ActiveState string `json:"active_state"` // active, inactive, failed
	SubState    string `json:"sub_state"`    // running, exited, dead, etc.
	Description string `json:"description,omitempty"`
	MainPID     int32  `json:"main_pid,omitempty"`
	StartTime   string `json:"start_time,omitempty"`
	Type        string `json:"type,omitempty"`    // simple, forking, oneshot, etc.
	Enabled     string `json:"enabled,omitempty"` // enabled, disabled, static, masked
}

// KernelModulesResult represents kernel modules query results.
type KernelModulesResult struct {
	Modules   []KernelModule `json:"modules"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// KernelModule represents a loaded kernel module.
type KernelModule struct {
	Name       string   `json:"name"`
	Size       int64    `json:"size"`                   // Size in bytes
	UsedBy     int      `json:"used_by"`                // Reference count
	UsedByMods []string `json:"used_by_mods,omitempty"` // Modules using this one
	State      string   `json:"state,omitempty"`        // Live, Loading, Unloading
	Address    string   `json:"address,omitempty"`      // Memory address
}

// LoadedDriversResult represents loaded drivers query results.
type LoadedDriversResult struct {
	Drivers   []LoadedDriver `json:"drivers"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// LoadedDriver represents a loaded device driver.
type LoadedDriver struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	DeviceClass string `json:"device_class,omitempty"` // e.g., "network", "storage", "usb"
	Vendor      string `json:"vendor,omitempty"`
	Version     string `json:"version,omitempty"`
	Path        string `json:"path,omitempty"`   // Driver path or module
	Status      string `json:"status,omitempty"` // Running, Stopped
}

// DNSServersResult represents DNS configuration query results.
type DNSServersResult struct {
	Servers   []DNSServer `json:"servers"`
	Count     int         `json:"count"`
	Timestamp time.Time   `json:"timestamp"`
}

// DNSServer represents a configured DNS server.
type DNSServer struct {
	Address   string `json:"address"`
	Interface string `json:"interface,omitempty"` // Interface this is configured for
	Type      string `json:"type,omitempty"`      // system, interface, dhcp
	Priority  int    `json:"priority,omitempty"`
}

// RoutesResult represents routing table query results.
type RoutesResult struct {
	Routes    []Route   `json:"routes"`
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

// Route represents a network route.
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface"`
	Mask        string `json:"mask,omitempty"`
	Metric      int    `json:"metric,omitempty"`
	Flags       string `json:"flags,omitempty"`
	Type        string `json:"type,omitempty"` // local, unicast, broadcast
}

// FirewallRulesResult represents firewall rules query results.
type FirewallRulesResult struct {
	Rules     []FirewallRule `json:"rules"`
	Count     int            `json:"count"`
	Source    string         `json:"source"` // iptables, nftables, pf, windows
	Enabled   bool           `json:"enabled"`
	Timestamp time.Time      `json:"timestamp"`
}

// FirewallRule represents a firewall rule.
type FirewallRule struct {
	Chain       string `json:"chain,omitempty"`    // INPUT, OUTPUT, FORWARD
	Table       string `json:"table,omitempty"`    // filter, nat, mangle
	Protocol    string `json:"protocol,omitempty"` // tcp, udp, icmp
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Port        string `json:"port,omitempty"`
	Action      string `json:"action"` // ACCEPT, DROP, REJECT
	Interface   string `json:"interface,omitempty"`
	Direction   string `json:"direction,omitempty"` // in, out
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// ListeningPortsResult represents listening ports query results.
type ListeningPortsResult struct {
	Ports     []ListeningPort `json:"ports"`
	Count     int             `json:"count"`
	Timestamp time.Time       `json:"timestamp"`
}

// ListeningPort represents a listening network port.
type ListeningPort struct {
	Protocol    string `json:"protocol"` // tcp, udp
	Address     string `json:"address"`
	Port        uint16 `json:"port"`
	PID         int32  `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	State       string `json:"state,omitempty"` // LISTEN
	User        string `json:"user,omitempty"`
}

// ARPTableResult represents ARP table query results.
type ARPTableResult struct {
	Entries   []ARPEntry `json:"entries"`
	Count     int        `json:"count"`
	Timestamp time.Time  `json:"timestamp"`
}

// ARPEntry represents an ARP table entry.
type ARPEntry struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	Interface  string `json:"interface"`
	Type       string `json:"type,omitempty"`  // static, dynamic
	State      string `json:"state,omitempty"` // reachable, stale, permanent
}

// NetworkStatsResult represents network statistics query results.
type NetworkStatsResult struct {
	Stats     NetworkStats `json:"stats"`
	Timestamp time.Time    `json:"timestamp"`
}

// NetworkStats represents network stack statistics.
type NetworkStats struct {
	TCPConnections  int    `json:"tcp_connections"`
	TCPEstablished  int    `json:"tcp_established"`
	TCPTimeWait     int    `json:"tcp_time_wait"`
	TCPCloseWait    int    `json:"tcp_close_wait"`
	UDPConnections  int    `json:"udp_connections"`
	PacketsReceived uint64 `json:"packets_received"`
	PacketsSent     uint64 `json:"packets_sent"`
	BytesReceived   uint64 `json:"bytes_received"`
	BytesSent       uint64 `json:"bytes_sent"`
	Errors          uint64 `json:"errors"`
	Drops           uint64 `json:"drops"`
}

// MountsResult represents mounted filesystems query results.
type MountsResult struct {
	Mounts    []MountInfo `json:"mounts"`
	Count     int         `json:"count"`
	Timestamp time.Time   `json:"timestamp"`
}

// MountInfo represents a mounted filesystem.
type MountInfo struct {
	Device     string   `json:"device"`
	Mountpoint string   `json:"mountpoint"`
	Fstype     string   `json:"fstype"`
	Options    []string `json:"options,omitempty"`
	Total      uint64   `json:"total,omitempty"`
	Used       uint64   `json:"used,omitempty"`
	Free       uint64   `json:"free,omitempty"`
	UsedPct    float64  `json:"used_percent,omitempty"`
}

// DiskIOResult represents disk I/O statistics query results.
type DiskIOResult struct {
	Devices   []DiskIOStats `json:"devices"`
	Count     int           `json:"count"`
	Timestamp time.Time     `json:"timestamp"`
}

// DiskIOStats represents I/O statistics for a disk device.
type DiskIOStats struct {
	Device         string  `json:"device"`
	ReadCount      uint64  `json:"read_count"`
	WriteCount     uint64  `json:"write_count"`
	ReadBytes      uint64  `json:"read_bytes"`
	WriteBytes     uint64  `json:"write_bytes"`
	ReadTime       uint64  `json:"read_time_ms"`
	WriteTime      uint64  `json:"write_time_ms"`
	IOTime         uint64  `json:"io_time_ms,omitempty"`
	WeightedIOTime uint64  `json:"weighted_io_time_ms,omitempty"`
	IOInProgress   uint64  `json:"io_in_progress,omitempty"`
	ReadMerged     uint64  `json:"read_merged,omitempty"`
	WriteMerged    uint64  `json:"write_merged,omitempty"`
	Utilization    float64 `json:"utilization_percent,omitempty"`
}

// OpenFilesResult represents open files query results.
type OpenFilesResult struct {
	Files     []OpenFile `json:"files"`
	Count     int        `json:"count"`
	Limit     int        `json:"limit,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}

// OpenFile represents an open file descriptor.
type OpenFile struct {
	PID         int32  `json:"pid"`
	ProcessName string `json:"process_name,omitempty"`
	FD          int    `json:"fd"`
	Path        string `json:"path"`
	Type        string `json:"type,omitempty"` // file, socket, pipe, device
	Mode        string `json:"mode,omitempty"` // r, w, rw
}

// InodeUsageResult represents inode usage query results.
type InodeUsageResult struct {
	Filesystems []InodeUsage `json:"filesystems"`
	Count       int          `json:"count"`
	Timestamp   time.Time    `json:"timestamp"`
}

// InodeUsage represents inode usage for a filesystem.
type InodeUsage struct {
	Filesystem string  `json:"filesystem"`
	Mountpoint string  `json:"mountpoint"`
	Total      uint64  `json:"total"`
	Used       uint64  `json:"used"`
	Free       uint64  `json:"free"`
	UsedPct    float64 `json:"used_percent"`
}

// EnvVarsResult represents environment variables query results.
type EnvVarsResult struct {
	Variables []EnvVar  `json:"variables"`
	Count     int       `json:"count"`
	Source    string    `json:"source"` // system, process, user
	Timestamp time.Time `json:"timestamp"`
}

// EnvVar represents an environment variable.
type EnvVar struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source,omitempty"` // system, user, process
}

// UserAccountsResult represents user accounts query results.
type UserAccountsResult struct {
	Users     []UserAccount `json:"users"`
	Groups    []UserGroup   `json:"groups"`
	UserCount int           `json:"user_count"`
	Timestamp time.Time     `json:"timestamp"`
}

// UserAccount represents a local user account.
type UserAccount struct {
	Username    string   `json:"username"`
	UID         int      `json:"uid"`
	GID         int      `json:"gid"`
	DisplayName string   `json:"display_name,omitempty"`
	HomeDir     string   `json:"home_dir,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	IsSystem    bool     `json:"is_system"` // System account (UID < 1000 on Linux)
	IsLocked    bool     `json:"is_locked"` // Account is locked
	LastLogin   string   `json:"last_login,omitempty"`
}

// UserGroup represents a local group.
type UserGroup struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members,omitempty"`
}

// SudoConfigResult represents sudo configuration query results.
type SudoConfigResult struct {
	Rules       []SudoRule `json:"rules"`
	Count       int        `json:"count"`
	SudoersPath string     `json:"sudoers_path"`
	Timestamp   time.Time  `json:"timestamp"`
}

// SudoRule represents a sudoers rule.
type SudoRule struct {
	User     string   `json:"user,omitempty"`     // User or %group
	Host     string   `json:"host,omitempty"`     // Hostname or ALL
	RunAs    string   `json:"run_as,omitempty"`   // User to run as
	Commands []string `json:"commands,omitempty"` // Allowed commands
	NoPasswd bool     `json:"no_passwd"`          // NOPASSWD flag
	Raw      string   `json:"raw,omitempty"`      // Raw rule line
}

// SSHConfigResult represents SSH configuration query results.
type SSHConfigResult struct {
	ServerConfig   map[string]string  `json:"server_config,omitempty"`
	ClientConfig   map[string]string  `json:"client_config,omitempty"`
	AuthorizedKeys []SSHAuthorizedKey `json:"authorized_keys,omitempty"`
	ServerRunning  bool               `json:"server_running"`
	SSHDPath       string             `json:"sshd_path,omitempty"`
	Timestamp      time.Time          `json:"timestamp"`
}

// SSHAuthorizedKey represents an SSH authorized key.
type SSHAuthorizedKey struct {
	KeyType     string `json:"key_type"` // ssh-rsa, ssh-ed25519, etc.
	Fingerprint string `json:"fingerprint,omitempty"`
	Comment     string `json:"comment,omitempty"`
	Options     string `json:"options,omitempty"` // Key options like no-agent-forwarding
	User        string `json:"user,omitempty"`    // User this key is for
}

// MACStatusResult represents Mandatory Access Control status.
type MACStatusResult struct {
	Type      string       `json:"type"` // selinux, apparmor, sip, none
	Enabled   bool         `json:"enabled"`
	Mode      string       `json:"mode,omitempty"` // enforcing, permissive, complaining
	Profiles  []MACProfile `json:"profiles,omitempty"`
	Timestamp time.Time    `json:"timestamp"`
}

// MACProfile represents a MAC policy profile.
type MACProfile struct {
	Name   string `json:"name"`
	Status string `json:"status"` // enforce, complain, unconfined
	Domain string `json:"domain,omitempty"`
}

// CertificatesResult represents SSL/TLS certificates query results.
type CertificatesResult struct {
	Certificates []Certificate `json:"certificates"`
	Count        int           `json:"count"`
	StorePath    string        `json:"store_path,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
}

// Certificate represents an SSL/TLS certificate.
type Certificate struct {
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	SerialNumber    string    `json:"serial_number,omitempty"`
	Fingerprint     string    `json:"fingerprint,omitempty"` // SHA256 fingerprint
	IsCA            bool      `json:"is_ca"`
	IsExpired       bool      `json:"is_expired"`
	DaysUntilExpiry int       `json:"days_until_expiry"`
}

// HardwareInfoResult represents system hardware information query results.
type HardwareInfoResult struct {
	System    SystemInfo    `json:"system"`
	BIOS      BIOSInfo      `json:"bios"`
	Baseboard BaseboardInfo `json:"baseboard"`
	Chassis   ChassisInfo   `json:"chassis,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// SystemInfo represents system/product information from DMI.
type SystemInfo struct {
	Manufacturer string `json:"manufacturer"`
	ProductName  string `json:"product_name"`
	Version      string `json:"version,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	Family       string `json:"family,omitempty"`
	SKU          string `json:"sku,omitempty"`
}

// BIOSInfo represents BIOS/UEFI information.
type BIOSInfo struct {
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
	Date    string `json:"date,omitempty"`
	Release string `json:"release,omitempty"`
}

// BaseboardInfo represents motherboard information.
type BaseboardInfo struct {
	Manufacturer string `json:"manufacturer"`
	ProductName  string `json:"product_name"`
	Version      string `json:"version,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
}

// ChassisInfo represents chassis/enclosure information.
type ChassisInfo struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	Type         string `json:"type,omitempty"`
	Version      string `json:"version,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	AssetTag     string `json:"asset_tag,omitempty"`
}

// USBDevicesResult represents USB devices query results.
type USBDevicesResult struct {
	Devices   []USBDevice `json:"devices"`
	Count     int         `json:"count"`
	Timestamp time.Time   `json:"timestamp"`
}

// USBDevice represents a USB device.
type USBDevice struct {
	BusNum       int    `json:"bus_num"`
	DevNum       int    `json:"dev_num"`
	VendorID     string `json:"vendor_id"`
	ProductID    string `json:"product_id"`
	Vendor       string `json:"vendor,omitempty"`
	Product      string `json:"product,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	DeviceClass  string `json:"device_class,omitempty"`
	Speed        string `json:"speed,omitempty"`
	MaxPower     string `json:"max_power,omitempty"`
	Driver       string `json:"driver,omitempty"`
	Path         string `json:"path,omitempty"`
}

// PCIDevicesResult represents PCI devices query results.
type PCIDevicesResult struct {
	Devices   []PCIDevice `json:"devices"`
	Count     int         `json:"count"`
	Timestamp time.Time   `json:"timestamp"`
}

// PCIDevice represents a PCI device.
type PCIDevice struct {
	Slot       string `json:"slot"`
	VendorID   string `json:"vendor_id"`
	DeviceID   string `json:"device_id"`
	Vendor     string `json:"vendor,omitempty"`
	Device     string `json:"device,omitempty"`
	SVendorID  string `json:"subsystem_vendor_id,omitempty"`
	SDeviceID  string `json:"subsystem_device_id,omitempty"`
	Class      string `json:"class,omitempty"`
	ClassID    string `json:"class_id,omitempty"`
	Revision   string `json:"revision,omitempty"`
	Driver     string `json:"driver,omitempty"`
	Module     string `json:"module,omitempty"`
	IRQ        int    `json:"irq,omitempty"`
	NumaNode   int    `json:"numa_node,omitempty"`
	IOMMUGroup string `json:"iommu_group,omitempty"`
}

// BlockDevicesResult represents block devices query results.
type BlockDevicesResult struct {
	Devices   []BlockDevice `json:"devices"`
	Count     int           `json:"count"`
	Timestamp time.Time     `json:"timestamp"`
}

// BlockDevice represents a block device.
type BlockDevice struct {
	Name       string        `json:"name"`
	MajMin     string        `json:"maj_min,omitempty"`
	Size       uint64        `json:"size"`
	Type       string        `json:"type"` // disk, part, lvm, loop, rom
	Model      string        `json:"model,omitempty"`
	Vendor     string        `json:"vendor,omitempty"`
	Serial     string        `json:"serial,omitempty"`
	Mountpoint string        `json:"mountpoint,omitempty"`
	Fstype     string        `json:"fstype,omitempty"`
	UUID       string        `json:"uuid,omitempty"`
	Label      string        `json:"label,omitempty"`
	RotType    string        `json:"rotational,omitempty"` // SSD or HDD
	ReadOnly   bool          `json:"read_only"`
	Removable  bool          `json:"removable"`
	Children   []BlockDevice `json:"children,omitempty"`
}

// ProcessEnvironResult represents process environment variables query results.
type ProcessEnvironResult struct {
	PID       int32             `json:"pid"`
	Name      string            `json:"name"`
	Environ   map[string]string `json:"environ"`
	Timestamp time.Time         `json:"timestamp"`
}

// IPCResourcesResult represents System V IPC resources query results.
type IPCResourcesResult struct {
	SharedMemory  []SharedMemorySegment `json:"shared_memory"`
	Semaphores    []SemaphoreSet        `json:"semaphores"`
	MessageQueues []MessageQueue        `json:"message_queues"`
	Timestamp     time.Time             `json:"timestamp"`
}

// SharedMemorySegment represents a System V shared memory segment.
type SharedMemorySegment struct {
	ID          int    `json:"id"`
	Key         string `json:"key"`
	Owner       string `json:"owner"`
	Permissions string `json:"permissions"`
	Bytes       uint64 `json:"bytes"`
	AttachCount int    `json:"attach_count"`
	Status      string `json:"status,omitempty"`
	CreateTime  string `json:"create_time,omitempty"`
}

// SemaphoreSet represents a System V semaphore set.
type SemaphoreSet struct {
	ID          int    `json:"id"`
	Key         string `json:"key"`
	Owner       string `json:"owner"`
	Permissions string `json:"permissions"`
	NumSems     int    `json:"num_sems"`
}

// MessageQueue represents a System V message queue.
type MessageQueue struct {
	ID          int    `json:"id"`
	Key         string `json:"key"`
	Owner       string `json:"owner"`
	Permissions string `json:"permissions"`
	Messages    int    `json:"messages"`
	Bytes       uint64 `json:"bytes"`
}

// NamespacesResult represents namespaces query results.
type NamespacesResult struct {
	Namespaces []Namespace `json:"namespaces"`
	Count      int         `json:"count"`
	Timestamp  time.Time   `json:"timestamp"`
}

// Namespace represents a Linux namespace.
type Namespace struct {
	Type    string `json:"type"` // mnt, uts, ipc, pid, net, user, cgroup
	ID      uint64 `json:"id"`
	PID     int32  `json:"pid,omitempty"`
	Command string `json:"command,omitempty"`
	User    string `json:"user,omitempty"`
	NSPath  string `json:"ns_path,omitempty"`
}

// CgroupsResult represents cgroup information query results.
type CgroupsResult struct {
	Version   int          `json:"version"` // 1 or 2
	Groups    []CgroupInfo `json:"groups"`
	Timestamp time.Time    `json:"timestamp"`
}

// CgroupInfo represents a cgroup and its limits.
type CgroupInfo struct {
	Name       string            `json:"name"`
	Path       string            `json:"path"`
	Controller string            `json:"controller,omitempty"` // v1 only
	Limits     map[string]string `json:"limits,omitempty"`
	Usage      map[string]string `json:"usage,omitempty"`
}

// CapabilitiesResult represents process capabilities query results.
type CapabilitiesResult struct {
	PID         int32     `json:"pid"`
	Name        string    `json:"name"`
	Effective   []string  `json:"effective"`
	Permitted   []string  `json:"permitted"`
	Inheritable []string  `json:"inheritable"`
	Bounding    []string  `json:"bounding,omitempty"`
	Ambient     []string  `json:"ambient,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// VMInfoResult represents virtualization detection query results.
type VMInfoResult struct {
	IsVM            bool      `json:"is_vm"`
	Hypervisor      string    `json:"hypervisor,omitempty"`     // kvm, vmware, virtualbox, xen, hyper-v, etc.
	VMType          string    `json:"vm_type,omitempty"`        // container, vm, none
	ContainerType   string    `json:"container_type,omitempty"` // docker, lxc, podman, etc.
	ProductName     string    `json:"product_name,omitempty"`
	Manufacturer    string    `json:"manufacturer,omitempty"`
	DetectionMethod string    `json:"detection_method,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// TimezoneInfoResult represents timezone and locale query results.
type TimezoneInfoResult struct {
	Timezone     string    `json:"timezone"`     // e.g., "America/New_York"
	Abbreviation string    `json:"abbreviation"` // e.g., "EST"
	UTCOffset    string    `json:"utc_offset"`   // e.g., "-05:00"
	DSTActive    bool      `json:"dst_active"`
	LocalTime    time.Time `json:"local_time"`
	Locale       string    `json:"locale,omitempty"` // e.g., "en_US.UTF-8"
	Timestamp    time.Time `json:"timestamp"`
}

// NTPStatusResult represents NTP synchronization query results.
type NTPStatusResult struct {
	Synchronized  bool      `json:"synchronized"`
	NTPService    string    `json:"ntp_service,omitempty"` // systemd-timesyncd, ntpd, chrony
	CurrentServer string    `json:"current_server,omitempty"`
	Stratum       int       `json:"stratum,omitempty"`
	Offset        string    `json:"offset,omitempty"` // Time offset
	Delay         string    `json:"delay,omitempty"`  // Round trip delay
	Jitter        string    `json:"jitter,omitempty"`
	ReferenceTime time.Time `json:"reference_time,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// CoreDumpsResult represents core dump detection query results.
type CoreDumpsResult struct {
	CoreDumps []CoreDump `json:"core_dumps"`
	Count     int        `json:"count"`
	TotalSize uint64     `json:"total_size"`
	DumpPath  string     `json:"dump_path,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}

// CoreDump represents a core dump file.
type CoreDump struct {
	Path        string    `json:"path"`
	ProcessName string    `json:"process_name,omitempty"`
	PID         int32     `json:"pid,omitempty"`
	Signal      int       `json:"signal,omitempty"`
	Size        uint64    `json:"size"`
	Time        time.Time `json:"time"`
}

// PowerStateResult represents power/battery state query results.
type PowerStateResult struct {
	OnACPower    bool          `json:"on_ac_power"`
	Batteries    []BatteryInfo `json:"batteries,omitempty"`
	PowerProfile string        `json:"power_profile,omitempty"` // performance, balanced, powersave
	Timestamp    time.Time     `json:"timestamp"`
}

// BatteryInfo represents battery status.
type BatteryInfo struct {
	Name         string  `json:"name"`
	Status       string  `json:"status"` // Charging, Discharging, Full, Not charging
	Percent      float64 `json:"percent"`
	Capacity     uint64  `json:"capacity,omitempty"`      // mWh
	CapacityFull uint64  `json:"capacity_full,omitempty"` // mWh
	Voltage      float64 `json:"voltage,omitempty"`       // V
	CurrentNow   float64 `json:"current_now,omitempty"`   // A
	TimeToEmpty  string  `json:"time_to_empty,omitempty"`
	TimeToFull   string  `json:"time_to_full,omitempty"`
	Technology   string  `json:"technology,omitempty"` // Li-ion, Li-poly
	Manufacturer string  `json:"manufacturer,omitempty"`
	Model        string  `json:"model,omitempty"`
	Serial       string  `json:"serial,omitempty"`
	CycleCount   int     `json:"cycle_count,omitempty"`
}

// NUMATopologyResult represents NUMA topology query results.
type NUMATopologyResult struct {
	Nodes     []NUMANode `json:"nodes"`
	Count     int        `json:"count"`
	Timestamp time.Time  `json:"timestamp"`
}

// NUMANode represents a NUMA node.
type NUMANode struct {
	ID          int    `json:"id"`
	CPUs        []int  `json:"cpus"`
	MemoryTotal uint64 `json:"memory_total"`
	MemoryFree  uint64 `json:"memory_free"`
	MemoryUsed  uint64 `json:"memory_used"`
	Distances   []int  `json:"distances,omitempty"` // Distance to other nodes
}

// ============================================================================
// Phase 1.7: SBOM & Software Inventory Types
// ============================================================================

// PathExecutablesResult represents PATH executables query results.
type PathExecutablesResult struct {
	Executables []PathExecutable `json:"executables"`
	Count       int              `json:"count"`
	PathDirs    []string         `json:"path_dirs"`
	Timestamp   time.Time        `json:"timestamp"`
}

// PathExecutable represents an executable found in PATH.
type PathExecutable struct {
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	Mode      string    `json:"mode"`
	ModTime   time.Time `json:"mod_time"`
	IsSymlink bool      `json:"is_symlink"`
	Target    string    `json:"target,omitempty"` // Symlink target
	Version   string    `json:"version,omitempty"`
}

// SystemPackagesResult represents system packages query results.
type SystemPackagesResult struct {
	PackageManager string          `json:"package_manager"` // dpkg, rpm, apk, pacman, brew, chocolatey
	Packages       []SystemPackage `json:"packages"`
	Count          int             `json:"count"`
	Timestamp      time.Time       `json:"timestamp"`
}

// SystemPackage represents an installed system package.
type SystemPackage struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture,omitempty"`
	Description  string `json:"description,omitempty"`
	InstallDate  string `json:"install_date,omitempty"`
	Size         int64  `json:"size,omitempty"`
	Status       string `json:"status,omitempty"` // installed, config-files, etc.
	Source       string `json:"source,omitempty"` // Repository/source
}

// LanguagePackagesResult represents language package manager query results.
type LanguagePackagesResult struct {
	Language       string            `json:"language"`        // python, nodejs, go, rust, ruby, java, php, dotnet
	PackageManager string            `json:"package_manager"` // pip, npm, go, cargo, gem, maven, composer, nuget
	Packages       []LanguagePackage `json:"packages"`
	Count          int               `json:"count"`
	Location       string            `json:"location,omitempty"` // Path scanned (e.g., site-packages dir, go.sum path)
	Timestamp      time.Time         `json:"timestamp"`
}

// LanguagePackage represents a language-specific package.
type LanguagePackage struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	License      string   `json:"license,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	Author       string   `json:"author,omitempty"`
	Homepage     string   `json:"homepage,omitempty"`
	Location     string   `json:"location,omitempty"`     // Installation path
	Dependencies []string `json:"dependencies,omitempty"` // Direct dependencies
	DevDep       bool     `json:"dev_dependency,omitempty"`
}

// ============================================================================
// Phase 1.9: Triage & Summary Query Types
// ============================================================================

// OSInfoResult represents OS information query results.
type OSInfoResult struct {
	Name            string    `json:"name"`               // e.g., "Ubuntu", "macOS", "Windows"
	Version         string    `json:"version"`            // e.g., "22.04", "14.0", "10"
	Build           string    `json:"build,omitempty"`    // Build number
	Codename        string    `json:"codename,omitempty"` // e.g., "jammy", "Sonoma"
	KernelVersion   string    `json:"kernel_version"`     // e.g., "6.5.0-44-generic"
	KernelArch      string    `json:"kernel_arch"`        // e.g., "x86_64", "arm64"
	Platform        string    `json:"platform"`           // linux, darwin, windows
	PlatformFamily  string    `json:"platform_family"`    // debian, rhel, darwin, windows
	PlatformVersion string    `json:"platform_version"`   // Full version string
	Hostname        string    `json:"hostname"`
	BootMode        string    `json:"boot_mode,omitempty"` // UEFI or BIOS
	Timestamp       time.Time `json:"timestamp"`
}

// SystemProfileResult represents system profile (hardware summary) query results.
type SystemProfileResult struct {
	OS        OSInfoResult   `json:"os"`
	CPU       CPUSummary     `json:"cpu"`
	Memory    MemorySummary  `json:"memory"`
	Disk      DiskSummary    `json:"disk"`
	Network   NetworkSummary `json:"network"`
	Timestamp time.Time      `json:"timestamp"`
}

// CPUSummary represents CPU summary for system profile.
type CPUSummary struct {
	Model        string  `json:"model"`
	Cores        int     `json:"cores"`
	LogicalCores int     `json:"logical_cores"`
	UsagePercent float64 `json:"usage_percent"`
	FrequencyMHz float64 `json:"frequency_mhz,omitempty"`
}

// MemorySummary represents memory summary for system profile.
type MemorySummary struct {
	TotalGB      float64 `json:"total_gb"`
	UsedGB       float64 `json:"used_gb"`
	AvailableGB  float64 `json:"available_gb"`
	UsagePercent float64 `json:"usage_percent"`
	SwapTotalGB  float64 `json:"swap_total_gb,omitempty"`
	SwapUsedGB   float64 `json:"swap_used_gb,omitempty"`
}

// DiskSummary represents disk summary for system profile.
type DiskSummary struct {
	TotalGB      float64 `json:"total_gb"`
	UsedGB       float64 `json:"used_gb"`
	FreeGB       float64 `json:"free_gb"`
	UsagePercent float64 `json:"usage_percent"`
	Partitions   int     `json:"partitions"`
}

// NetworkSummary represents network summary for system profile.
type NetworkSummary struct {
	Interfaces int      `json:"interfaces"`
	ActiveIPs  []string `json:"active_ips"`
	PrimaryIP  string   `json:"primary_ip,omitempty"`
	Hostname   string   `json:"hostname"`
}

// ServiceManagerInfoResult represents service manager information query results.
type ServiceManagerInfoResult struct {
	Type          string    `json:"type"` // systemd, launchd, scm
	Version       string    `json:"version,omitempty"`
	Running       bool      `json:"running"`
	PID           int32     `json:"pid,omitempty"`
	BootTarget    string    `json:"boot_target,omitempty"`    // multi-user.target, graphical.target
	DefaultTarget string    `json:"default_target,omitempty"` // Default boot target
	TotalUnits    int       `json:"total_units,omitempty"`
	ActiveUnits   int       `json:"active_units,omitempty"`
	FailedUnits   int       `json:"failed_units,omitempty"`
	LoadedUnits   int       `json:"loaded_units,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// CloudEnvironmentResult represents cloud environment detection query results.
type CloudEnvironmentResult struct {
	IsCloud         bool              `json:"is_cloud"`
	Provider        string            `json:"provider,omitempty"` // aws, gcp, azure, digitalocean, etc.
	Region          string            `json:"region,omitempty"`
	Zone            string            `json:"zone,omitempty"`
	InstanceID      string            `json:"instance_id,omitempty"`
	InstanceType    string            `json:"instance_type,omitempty"`
	ImageID         string            `json:"image_id,omitempty"`
	AccountID       string            `json:"account_id,omitempty"`
	VPC             string            `json:"vpc,omitempty"`
	Subnet          string            `json:"subnet,omitempty"`
	PrivateIP       string            `json:"private_ip,omitempty"`
	PublicIP        string            `json:"public_ip,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	DetectionMethod string            `json:"detection_method,omitempty"`
	Timestamp       time.Time         `json:"timestamp"`
}

// LanguageRuntimesResult represents language runtime versions query results.
type LanguageRuntimesResult struct {
	Runtimes  []LanguageRuntime `json:"runtimes"`
	Count     int               `json:"count"`
	Timestamp time.Time         `json:"timestamp"`
}

// LanguageRuntime represents a detected language runtime.
type LanguageRuntime struct {
	Name        string `json:"name"` // python, node, go, ruby, java, php, rust, dotnet
	Version     string `json:"version"`
	Path        string `json:"path"`              // Path to the executable
	Manager     string `json:"manager,omitempty"` // Package manager (pip, npm, etc.)
	ManagerVer  string `json:"manager_version,omitempty"`
	DefaultPkg  string `json:"default_package,omitempty"` // Default package dir
	Environment string `json:"environment,omitempty"`     // virtualenv, nvm, rbenv, etc.
}

// ContainerImagesResult represents Docker/Podman images query results.
type ContainerImagesResult struct {
	Images    []ContainerImage `json:"images"`
	Count     int              `json:"count"`
	Error     string           `json:"error,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// ContainerImage represents a container image.
type ContainerImage struct {
	ID         string            `json:"id"`
	Repository string            `json:"repository,omitempty"`
	Tag        string            `json:"tag,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Digests    []string          `json:"digests,omitempty"`
	Created    time.Time         `json:"created"`
	Size       int64             `json:"size"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// DockerContainersResult represents Docker/Podman containers query results.
type DockerContainersResult struct {
	Containers []DockerContainer `json:"containers"`
	Count      int               `json:"count"`
	Running    int               `json:"running"`
	Paused     int               `json:"paused"`
	Stopped    int               `json:"stopped"`
	Error      string            `json:"error,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
}

// DockerContainer represents a Docker/Podman container instance.
type DockerContainer struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Names   []string          `json:"names,omitempty"`
	Image   string            `json:"image"`
	ImageID string            `json:"image_id"`
	Command string            `json:"command,omitempty"`
	Created time.Time         `json:"created"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Ports   []DockerPort      `json:"ports,omitempty"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// DockerPort represents a Docker container port mapping.
type DockerPort struct {
	PrivatePort int    `json:"private_port"`
	PublicPort  int    `json:"public_port,omitempty"`
	Type        string `json:"type"`
	IP          string `json:"ip,omitempty"`
}

// ImageHistoryResult represents Docker image history query results.
type ImageHistoryResult struct {
	ImageID    string       `json:"image_id"`
	Layers     []ImageLayer `json:"layers"`
	LayerCount int          `json:"layer_count"`
	TotalSize  int64        `json:"total_size"`
	Error      string       `json:"error,omitempty"`
	Timestamp  time.Time    `json:"timestamp"`
}

// ImageLayer represents a layer in a container image.
type ImageLayer struct {
	ID        string    `json:"id,omitempty"`
	Created   time.Time `json:"created"`
	CreatedBy string    `json:"created_by"`
	Size      int64     `json:"size"`
	Comment   string    `json:"comment,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
}

// SBOMResult represents a Software Bill of Materials.
type SBOMResult struct {
	Format     string          `json:"format"` // cyclonedx, spdx
	Version    string          `json:"version"`
	Timestamp  time.Time       `json:"timestamp"`
	Components []SBOMComponent `json:"components"`
	Count      int             `json:"count"`
	Raw        string          `json:"raw,omitempty"` // Raw SBOM in requested format
}

// SBOMComponent represents a component in the SBOM.
type SBOMComponent struct {
	Type        string   `json:"type"` // library, application, framework, etc.
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	PURL        string   `json:"purl,omitempty"` // Package URL
	CPE         string   `json:"cpe,omitempty"`
	License     string   `json:"license,omitempty"`
	Description string   `json:"description,omitempty"`
	Supplier    string   `json:"supplier,omitempty"`
	Hashes      []string `json:"hashes,omitempty"`
}

// SnapPackagesResult represents Snap packages query results.
type SnapPackagesResult struct {
	Packages  []SnapPackage `json:"packages"`
	Count     int           `json:"count"`
	Timestamp time.Time     `json:"timestamp"`
}

// SnapPackage represents a Snap package.
type SnapPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Revision    string `json:"revision,omitempty"`
	Channel     string `json:"channel,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	Description string `json:"description,omitempty"`
	DevMode     bool   `json:"dev_mode,omitempty"`
	Confinement string `json:"confinement,omitempty"`
}

// FlatpakPackagesResult represents Flatpak packages query results.
type FlatpakPackagesResult struct {
	Packages  []FlatpakPackage `json:"packages"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// FlatpakPackage represents a Flatpak package.
type FlatpakPackage struct {
	Name       string `json:"name"`
	AppID      string `json:"app_id"`
	Version    string `json:"version,omitempty"`
	Branch     string `json:"branch,omitempty"`
	Origin     string `json:"origin,omitempty"`
	Arch       string `json:"arch,omitempty"`
	InstallDir string `json:"install_dir,omitempty"`
}

// HomebrewCasksResult represents Homebrew Casks query results.
type HomebrewCasksResult struct {
	Casks     []HomebrewCask `json:"casks"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// HomebrewCask represents a Homebrew Cask (macOS GUI app).
type HomebrewCask struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	AppNames    []string `json:"app_names,omitempty"`
	Description string   `json:"description,omitempty"`
	Homepage    string   `json:"homepage,omitempty"`
	Outdated    bool     `json:"outdated,omitempty"`
}

// ScoopPackagesResult represents Scoop packages query results (Windows).
type ScoopPackagesResult struct {
	Packages  []ScoopPackage `json:"packages"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// ScoopPackage represents a Scoop package.
type ScoopPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Bucket      string `json:"bucket,omitempty"`
	Updated     string `json:"updated,omitempty"`
	Description string `json:"description,omitempty"`
}

// WindowsProgramsResult represents Windows installed programs query results.
type WindowsProgramsResult struct {
	Programs  []WindowsProgram `json:"programs"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// WindowsProgram represents a Windows installed program from registry.
type WindowsProgram struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	Publisher       string `json:"publisher,omitempty"`
	InstallDate     string `json:"install_date,omitempty"`
	InstallLocation string `json:"install_location,omitempty"`
	UninstallString string `json:"uninstall_string,omitempty"`
	EstimatedSize   int64  `json:"estimated_size,omitempty"`
	SystemComponent bool   `json:"system_component,omitempty"`
}

// WindowsFeaturesResult represents Windows features query results.
type WindowsFeaturesResult struct {
	Features  []WindowsFeature `json:"features"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// WindowsFeature represents a Windows feature/role.
type WindowsFeature struct {
	Name        string `json:"name"`
	State       string `json:"state"` // Enabled, Disabled
	Description string `json:"description,omitempty"`
}

// LockFileResult represents lock file parsing results.
type LockFileResult struct {
	LockFile     string           `json:"lock_file"`    // package-lock.json, requirements.txt, etc.
	PackageType  string           `json:"package_type"` // npm, pip, cargo, go, gem, composer
	Dependencies []LockDependency `json:"dependencies"`
	Count        int              `json:"count"`
	Timestamp    time.Time        `json:"timestamp"`
}

// LockDependency represents a dependency from a lock file.
type LockDependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Resolved  string `json:"resolved,omitempty"`  // Resolved URL/registry
	Integrity string `json:"integrity,omitempty"` // Hash/checksum
	Dev       bool   `json:"dev,omitempty"`
}

// VulnerabilityResult represents vulnerability lookup results.
type VulnerabilityResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Count           int             `json:"count"`
	Critical        int             `json:"critical"`
	High            int             `json:"high"`
	Medium          int             `json:"medium"`
	Low             int             `json:"low"`
	Source          string          `json:"source"` // osv, nvd, github
	Timestamp       time.Time       `json:"timestamp"`
	Error           string          `json:"error,omitempty"`
}

// Vulnerability represents a security vulnerability.
type Vulnerability struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases,omitempty"` // CVE, GHSA, etc.
	Summary    string   `json:"summary"`
	Details    string   `json:"details,omitempty"`
	Severity   string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	CVSS       float64  `json:"cvss,omitempty"`
	Package    string   `json:"package"`
	Version    string   `json:"version"`
	FixedIn    string   `json:"fixed_in,omitempty"`
	References []string `json:"references,omitempty"`
	Published  string   `json:"published,omitempty"`
	Modified   string   `json:"modified,omitempty"`
}

// ============================================================================
// Phase 1.8: Application Discovery & Configuration Types
// ============================================================================

// ApplicationsResult represents application discovery query results.
type ApplicationsResult struct {
	Applications []Application `json:"applications"`
	Count        int           `json:"count"`
	Timestamp    time.Time     `json:"timestamp"`
}

// Application represents a discovered application.
type Application struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // web_server, database, message_queue, runtime, cache, mail, directory, container, security
	Version     string   `json:"version,omitempty"`
	Service     string   `json:"service,omitempty"`      // Service/daemon name
	Status      string   `json:"status,omitempty"`       // running, stopped, enabled, disabled
	Port        int      `json:"port,omitempty"`         // Primary listening port
	Ports       []int    `json:"ports,omitempty"`        // All listening ports
	PID         int32    `json:"pid,omitempty"`          // Main process PID
	User        string   `json:"user,omitempty"`         // Running as user
	ConfigPaths []string `json:"config_paths,omitempty"` // Known config file paths
	LogPaths    []string `json:"log_paths,omitempty"`    // Known log file paths
	DataDir     string   `json:"data_dir,omitempty"`     // Data directory
	BinaryPath  string   `json:"binary_path,omitempty"`  // Path to executable
	Detected    string   `json:"detected"`               // Detection method: service, process, port, config, package
}

// AppConfigResult represents application configuration read results.
type AppConfigResult struct {
	Path             string           `json:"path"`
	Format           string           `json:"format"`  // ini, xml, json, yaml, toml, nginx, apache, env, unknown
	Content          string           `json:"content"` // Redacted content
	RedactionSummary RedactionSummary `json:"redaction_summary"`
	ParsedKeys       []string         `json:"parsed_keys,omitempty"` // Top-level keys if parseable
	Sections         []string         `json:"sections,omitempty"`    // Sections/blocks if applicable
	FileSize         int64            `json:"file_size"`
	ModTime          time.Time        `json:"mod_time"`
	Readable         bool             `json:"readable"`
	Error            string           `json:"error,omitempty"`
	Timestamp        time.Time        `json:"timestamp"`
}

// RedactionSummary summarizes what was redacted from a config file.
type RedactionSummary struct {
	TotalRedactions int            `json:"total_redactions"`
	ByType          map[string]int `json:"by_type"`                 // password: 3, api_key: 1, etc.
	EnvVarRefs      int            `json:"env_var_refs"`            // Environment variable references found (not redacted but flagged)
	TemplateRefs    int            `json:"template_refs"`           // Template references found (not redacted but flagged)
	RedactedKeys    []string       `json:"redacted_keys,omitempty"` // List of keys that were redacted
}

// ============================================================================
// Phase 1.9: Triage & Summary Query Types
// ============================================================================

// RecentRebootsResult represents recent system reboot information.
type RecentRebootsResult struct {
	Reboots   []RebootEvent `json:"reboots"`
	Count     int           `json:"count"`
	Timestamp time.Time     `json:"timestamp"`
}

// RebootEvent represents a single reboot event.
type RebootEvent struct {
	Time     time.Time `json:"time"`
	Type     string    `json:"type,omitempty"`     // reboot, shutdown, crash
	User     string    `json:"user,omitempty"`     // User who initiated
	Duration string    `json:"duration,omitempty"` // Uptime before reboot
	Reason   string    `json:"reason,omitempty"`   // Reason if available
}

// RecentServiceFailuresResult represents recent service failures.
type RecentServiceFailuresResult struct {
	Failures  []ServiceFailure `json:"failures"`
	Count     int              `json:"count"`
	Timestamp time.Time        `json:"timestamp"`
}

// ServiceFailure represents a failed service event.
type ServiceFailure struct {
	Service   string    `json:"service"`
	Time      time.Time `json:"time"`
	Status    string    `json:"status"`              // failed, crashed, timeout
	ExitCode  int       `json:"exit_code,omitempty"` // Exit code if available
	Message   string    `json:"message,omitempty"`   // Error message
	Restarts  int       `json:"restarts,omitempty"`  // Number of restart attempts
	LastStart time.Time `json:"last_start,omitempty"`
}

// RecentKernelEventsResult represents recent kernel events.
type RecentKernelEventsResult struct {
	Events    []KernelEvent `json:"events"`
	Count     int           `json:"count"`
	Errors    int           `json:"errors"`
	Warnings  int           `json:"warnings"`
	Timestamp time.Time     `json:"timestamp"`
}

// KernelEvent represents a kernel log event.
type KernelEvent struct {
	Time     time.Time `json:"time"`
	Level    string    `json:"level"` // error, warning, info
	Facility string    `json:"facility,omitempty"`
	Message  string    `json:"message"`
}

// RecentResourceIncidentsResult represents recent resource-related incidents.
type RecentResourceIncidentsResult struct {
	Incidents []ResourceIncident `json:"incidents"`
	Count     int                `json:"count"`
	OOMKills  int                `json:"oom_kills"`
	Throttles int                `json:"throttles"`
	Timestamp time.Time          `json:"timestamp"`
}

// ResourceIncident represents a resource incident event.
type ResourceIncident struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`              // oom, cpu_throttle, io_throttle, memory_pressure
	Process string    `json:"process,omitempty"` // Affected process
	PID     int32     `json:"pid,omitempty"`
	Details string    `json:"details,omitempty"`
}

// RecentConfigChangesResult represents recent configuration changes.
type RecentConfigChangesResult struct {
	Changes   []ConfigChange `json:"changes"`
	Count     int            `json:"count"`
	Timestamp time.Time      `json:"timestamp"`
}

// ConfigChange represents a configuration change event.
type ConfigChange struct {
	Time    time.Time `json:"time"`
	Type    string    `json:"type"` // package_install, package_update, package_remove, config_change
	Package string    `json:"package,omitempty"`
	Version string    `json:"version,omitempty"`
	OldVer  string    `json:"old_version,omitempty"`
	Path    string    `json:"path,omitempty"` // Config file path if applicable
	User    string    `json:"user,omitempty"`
}

// RecentCriticalEventsResult represents recent critical log events.
type RecentCriticalEventsResult struct {
	Events    []CriticalEvent `json:"events"`
	Count     int             `json:"count"`
	Timestamp time.Time       `json:"timestamp"`
}

// CriticalEvent represents a critical log entry.
type CriticalEvent struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`   // Service/facility that logged
	Priority string    `json:"priority"` // critical, emergency, alert
	Message  string    `json:"message"`
}

// FailedUnitsResult represents failed system services/units.
type FailedUnitsResult struct {
	Units     []FailedUnit `json:"units"`
	Count     int          `json:"count"`
	Timestamp time.Time    `json:"timestamp"`
}

// FailedUnit represents a failed service unit.
type FailedUnit struct {
	Name        string    `json:"name"`
	LoadState   string    `json:"load_state,omitempty"`
	ActiveState string    `json:"active_state"`
	SubState    string    `json:"sub_state,omitempty"`
	Description string    `json:"description,omitempty"`
	FailedAt    time.Time `json:"failed_at,omitempty"`
	Result      string    `json:"result,omitempty"` // exit-code, signal, timeout
}

// TimerJobsResult represents scheduled timer jobs.
type TimerJobsResult struct {
	Timers    []TimerJob `json:"timers"`
	Count     int        `json:"count"`
	Timestamp time.Time  `json:"timestamp"`
}

// TimerJob represents a scheduled timer/job.
type TimerJob struct {
	Name        string    `json:"name"`
	Schedule    string    `json:"schedule,omitempty"` // Cron expression or description
	NextRun     time.Time `json:"next_run,omitempty"`
	LastRun     time.Time `json:"last_run,omitempty"`
	LastResult  string    `json:"last_result,omitempty"` // success, failed
	Unit        string    `json:"unit,omitempty"`        // Associated service/unit
	Description string    `json:"description,omitempty"`
}

// ServiceLogViewResult represents service-specific log entries.
type ServiceLogViewResult struct {
	Service   string       `json:"service"`
	Logs      []ServiceLog `json:"logs"`
	Count     int          `json:"count"`
	Timestamp time.Time    `json:"timestamp"`
}

// ServiceLog represents a single service log entry.
type ServiceLog struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level,omitempty"` // info, warning, error
	Message string    `json:"message"`
	PID     int32     `json:"pid,omitempty"`
}

// DeploymentEventsResult represents recent deployment/package events.
type DeploymentEventsResult struct {
	Events    []DeploymentEvent `json:"events"`
	Count     int               `json:"count"`
	Installs  int               `json:"installs"`
	Updates   int               `json:"updates"`
	Removes   int               `json:"removes"`
	Timestamp time.Time         `json:"timestamp"`
}

// DeploymentEvent represents a package deployment event.
type DeploymentEvent struct {
	Time    time.Time `json:"time"`
	Action  string    `json:"action"` // install, update, remove, configure
	Package string    `json:"package"`
	Version string    `json:"version,omitempty"`
	OldVer  string    `json:"old_version,omitempty"`
	Status  string    `json:"status,omitempty"` // success, failed
}

// AuthFailureSummaryResult represents authentication failure summary.
type AuthFailureSummaryResult struct {
	Failures   []AuthFailure `json:"failures"`
	TotalCount int           `json:"total_count"`
	UniqueIPs  int           `json:"unique_ips"`
	UniqueUser int           `json:"unique_users"`
	TopIPs     []IPCount     `json:"top_ips,omitempty"`
	TopUsers   []UserCount   `json:"top_users,omitempty"`
	Timestamp  time.Time     `json:"timestamp"`
}

// AuthFailure represents an authentication failure event.
type AuthFailure struct {
	Time    time.Time `json:"time"`
	User    string    `json:"user"`
	Source  string    `json:"source,omitempty"` // IP address
	Service string    `json:"service"`          // sshd, sudo, login
	Method  string    `json:"method,omitempty"` // password, publickey
	Reason  string    `json:"reason,omitempty"`
}

// IPCount represents IP address with count.
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// UserCount represents username with count.
type UserCount struct {
	User  string `json:"user"`
	Count int    `json:"count"`
}

// SecurityBasicsResult represents basic security status.
type SecurityBasicsResult struct {
	Firewall   FirewallStatus   `json:"firewall"`
	SELinux    SELinuxStatus    `json:"selinux,omitempty"`    // Linux only
	AppArmor   AppArmorStatus   `json:"apparmor,omitempty"`   // Linux only
	Gatekeeper GatekeeperStatus `json:"gatekeeper,omitempty"` // macOS only
	Defender   DefenderStatus   `json:"defender,omitempty"`   // Windows only
	Updates    UpdateStatus     `json:"updates,omitempty"`
	Timestamp  time.Time        `json:"timestamp"`
}

// FirewallStatus represents firewall status.
type FirewallStatus struct {
	Enabled    bool   `json:"enabled"`
	Type       string `json:"type,omitempty"` // iptables, nftables, ufw, pf, windows
	RuleCount  int    `json:"rule_count,omitempty"`
	DefaultIn  string `json:"default_in,omitempty"`  // accept, drop, reject
	DefaultOut string `json:"default_out,omitempty"` // accept, drop, reject
}

// SELinuxStatus represents SELinux status.
type SELinuxStatus struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode,omitempty"` // enforcing, permissive, disabled
	Policy  string `json:"policy,omitempty"`
	Denials int    `json:"denials,omitempty"` // Recent denial count
}

// AppArmorStatus represents AppArmor status.
type AppArmorStatus struct {
	Enabled  bool `json:"enabled"`
	Profiles int  `json:"profiles,omitempty"`
	Enforce  int  `json:"enforce,omitempty"`
	Complain int  `json:"complain,omitempty"`
}

// GatekeeperStatus represents macOS Gatekeeper status.
type GatekeeperStatus struct {
	Enabled    bool   `json:"enabled"`
	Assessment string `json:"assessment,omitempty"`
}

// DefenderStatus represents Windows Defender status.
type DefenderStatus struct {
	Enabled       bool   `json:"enabled"`
	RealTime      bool   `json:"real_time"`
	LastScan      string `json:"last_scan,omitempty"`
	DefinitionVer string `json:"definition_version,omitempty"`
	DefinitionAge int    `json:"definition_age_days,omitempty"`
}

// UpdateStatus represents system update status.
type UpdateStatus struct {
	AutoUpdate      bool   `json:"auto_update"`
	PendingUpdates  int    `json:"pending_updates,omitempty"`
	LastCheck       string `json:"last_check,omitempty"`
	SecurityUpdates int    `json:"security_updates,omitempty"`
}

// SSHSecuritySummaryResult represents SSH configuration security analysis.
type SSHSecuritySummaryResult struct {
	Installed       bool        `json:"installed"`
	Running         bool        `json:"running"`
	Port            int         `json:"port,omitempty"`
	Settings        SSHSettings `json:"settings"`
	Warnings        []string    `json:"warnings,omitempty"`
	Recommendations []string    `json:"recommendations,omitempty"`
	Timestamp       time.Time   `json:"timestamp"`
}

// SSHSettings represents SSH server settings.
type SSHSettings struct {
	PermitRootLogin      string `json:"permit_root_login"`
	PasswordAuth         bool   `json:"password_auth"`
	PubkeyAuth           bool   `json:"pubkey_auth"`
	PermitEmptyPasswords bool   `json:"permit_empty_passwords"`
	X11Forwarding        bool   `json:"x11_forwarding"`
	MaxAuthTries         int    `json:"max_auth_tries,omitempty"`
	LoginGraceTime       int    `json:"login_grace_time,omitempty"`
	AllowUsers           string `json:"allow_users,omitempty"`
	AllowGroups          string `json:"allow_groups,omitempty"`
}

// AdminAccountSummaryResult represents admin/sudo user summary.
type AdminAccountSummaryResult struct {
	Admins    []AdminAccount `json:"admins"`
	Count     int            `json:"count"`
	RootLogin bool           `json:"root_login_enabled"`
	Timestamp time.Time      `json:"timestamp"`
}

// AdminAccount represents an admin/privileged account.
type AdminAccount struct {
	User       string   `json:"user"`
	UID        int      `json:"uid"`
	Groups     []string `json:"groups,omitempty"`
	Shell      string   `json:"shell,omitempty"`
	LastLogin  string   `json:"last_login,omitempty"`
	Locked     bool     `json:"locked"`
	NoPassword bool     `json:"no_password,omitempty"`
}

// ExposedServicesSummaryResult represents exposed/listening services summary.
type ExposedServicesSummaryResult struct {
	Services  []ExposedService `json:"services"`
	Count     int              `json:"count"`
	External  int              `json:"external"` // Services listening on 0.0.0.0 or public IP
	Internal  int              `json:"internal"` // Services listening on localhost only
	Timestamp time.Time        `json:"timestamp"`
}

// ExposedService represents an exposed network service.
type ExposedService struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp, udp
	Address  string `json:"address"`  // Listening address
	Process  string `json:"process,omitempty"`
	PID      int32  `json:"pid,omitempty"`
	User     string `json:"user,omitempty"`
	External bool   `json:"external"` // True if exposed externally
}

// ResourceLimitsResult represents system resource limits.
type ResourceLimitsResult struct {
	Limits    []ResourceLimit `json:"limits"`
	Warnings  []string        `json:"warnings,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// ResourceLimit represents a resource limit setting.
type ResourceLimit struct {
	Type    string `json:"type"` // open_files, max_processes, stack_size, etc.
	Soft    int64  `json:"soft"`
	Hard    int64  `json:"hard"`
	Current int64  `json:"current,omitempty"` // Current usage if available
	Unit    string `json:"unit,omitempty"`    // bytes, count, etc.
}

// RecentlyInstalledSoftwareResult represents recently installed software.
type RecentlyInstalledSoftwareResult struct {
	Packages  []InstalledPackage `json:"packages"`
	Count     int                `json:"count"`
	Since     time.Time          `json:"since"`
	Timestamp time.Time          `json:"timestamp"`
}

// InstalledPackage represents a recently installed package.
type InstalledPackage struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Manager   string    `json:"manager"` // apt, yum, brew, choco, etc.
	Installed time.Time `json:"installed"`
	Size      int64     `json:"size,omitempty"` // Installed size in bytes
}

// FSHealthSummaryResult represents filesystem health summary.
type FSHealthSummaryResult struct {
	Filesystems []FSHealth `json:"filesystems"`
	Warnings    []string   `json:"warnings,omitempty"`
	Timestamp   time.Time  `json:"timestamp"`
}

// FSHealth represents filesystem health status.
type FSHealth struct {
	Mount     string  `json:"mount"`
	Device    string  `json:"device"`
	Type      string  `json:"type"`
	Size      int64   `json:"size"`
	Used      int64   `json:"used"`
	Available int64   `json:"available"`
	UsedPct   float64 `json:"used_pct"`
	InodePct  float64 `json:"inode_pct,omitempty"`
	ReadOnly  bool    `json:"read_only"`
	Errors    int     `json:"errors,omitempty"`
	Status    string  `json:"status"` // healthy, warning, critical
}

// IncidentTriageSnapshotResult represents full incident triage context.
type IncidentTriageSnapshotResult struct {
	System          *OSInfoResult                  `json:"system"`
	RecentReboots   *RecentRebootsResult           `json:"recent_reboots,omitempty"`
	ServiceFailures *RecentServiceFailuresResult   `json:"service_failures,omitempty"`
	KernelEvents    *RecentKernelEventsResult      `json:"kernel_events,omitempty"`
	ResourceIssues  *RecentResourceIncidentsResult `json:"resource_issues,omitempty"`
	CriticalEvents  *RecentCriticalEventsResult    `json:"critical_events,omitempty"`
	FailedUnits     *FailedUnitsResult             `json:"failed_units,omitempty"`
	Timestamp       time.Time                      `json:"timestamp"`
}

// SecurityPostureSnapshotResult represents security posture overview.
type SecurityPostureSnapshotResult struct {
	SecurityBasics  *SecurityBasicsResult         `json:"security_basics"`
	SSHSecurity     *SSHSecuritySummaryResult     `json:"ssh_security,omitempty"`
	AdminAccounts   *AdminAccountSummaryResult    `json:"admin_accounts,omitempty"`
	ExposedServices *ExposedServicesSummaryResult `json:"exposed_services,omitempty"`
	AuthFailures    *AuthFailureSummaryResult     `json:"auth_failures,omitempty"`
	OverallScore    int                           `json:"overall_score"` // 0-100
	RiskLevel       string                        `json:"risk_level"`    // low, medium, high, critical
	Recommendations []string                      `json:"recommendations,omitempty"`
	Timestamp       time.Time                     `json:"timestamp"`
}

// ============================================================================
// Phase 2: Enhanced Diagnostics Types
// ============================================================================

// GPUInfoResult represents GPU diagnostics query results.
type GPUInfoResult struct {
	GPUs      []GPUDevice `json:"gpus"`
	Count     int         `json:"count"`
	Error     string      `json:"error,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// GPUDevice represents detailed GPU information.
type GPUDevice struct {
	Index           int          `json:"index"`
	Name            string       `json:"name"`
	Vendor          string       `json:"vendor"`                     // nvidia, amd, intel, apple
	Driver          string       `json:"driver,omitempty"`           // Driver version
	VBIOS           string       `json:"vbios,omitempty"`            // Video BIOS version
	PCIBusID        string       `json:"pci_bus_id,omitempty"`       // PCI bus ID
	MemoryTotal     uint64       `json:"memory_total"`               // Total memory in bytes
	MemoryUsed      uint64       `json:"memory_used"`                // Used memory in bytes
	MemoryFree      uint64       `json:"memory_free"`                // Free memory in bytes
	Utilization     float64      `json:"utilization"`                // GPU utilization percentage
	MemoryUtil      float64      `json:"memory_utilization"`         // Memory utilization percentage
	Temperature     float64      `json:"temperature,omitempty"`      // Temperature in Celsius
	TemperatureMax  float64      `json:"temperature_max,omitempty"`  // Max safe temperature
	FanSpeed        int          `json:"fan_speed,omitempty"`        // Fan speed percentage
	PowerDraw       float64      `json:"power_draw,omitempty"`       // Power draw in watts
	PowerLimit      float64      `json:"power_limit,omitempty"`      // Power limit in watts
	ClockGraphics   int          `json:"clock_graphics,omitempty"`   // Graphics clock in MHz
	ClockMemory     int          `json:"clock_memory,omitempty"`     // Memory clock in MHz
	ClockSM         int          `json:"clock_sm,omitempty"`         // SM clock in MHz
	ComputeMode     string       `json:"compute_mode,omitempty"`     // Compute mode
	PersistenceMode bool         `json:"persistence_mode,omitempty"` // Persistence mode enabled
	UUID            string       `json:"uuid,omitempty"`             // GPU UUID
	Serial          string       `json:"serial,omitempty"`           // Serial number
	Architecture    string       `json:"architecture,omitempty"`     // GPU architecture
	CUDACores       int          `json:"cuda_cores,omitempty"`       // NVIDIA CUDA cores
	ComputeUnits    int          `json:"compute_units,omitempty"`    // AMD compute units
	TensorCores     int          `json:"tensor_cores,omitempty"`     // Tensor cores
	ProcessCount    int          `json:"process_count,omitempty"`    // Running GPU processes
	EccErrors       int          `json:"ecc_errors,omitempty"`       // ECC memory errors
	Processes       []GPUProcess `json:"processes,omitempty"`        // Processes using GPU
}

// GPUProcess represents a process using the GPU.
type GPUProcess struct {
	PID        int32  `json:"pid"`
	Name       string `json:"name,omitempty"`
	MemoryUsed uint64 `json:"memory_used"`    // GPU memory used by process
	Type       string `json:"type,omitempty"` // C (compute), G (graphics)
}

// ContainerStatsResult represents container runtime statistics.
type ContainerStatsResult struct {
	Stats     []ContainerStats `json:"stats"`
	Count     int              `json:"count"`
	Error     string           `json:"error,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
}

// ContainerStats represents real-time stats for a container.
type ContainerStats struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	CPUPercent       float64   `json:"cpu_percent"`
	CPUSystemNanos   uint64    `json:"cpu_system_nanos,omitempty"`
	CPUUserNanos     uint64    `json:"cpu_user_nanos,omitempty"`
	MemoryUsage      uint64    `json:"memory_usage"`
	MemoryLimit      uint64    `json:"memory_limit"`
	MemoryPercent    float64   `json:"memory_percent"`
	MemoryCache      uint64    `json:"memory_cache,omitempty"`
	NetworkRxBytes   uint64    `json:"network_rx_bytes"`
	NetworkTxBytes   uint64    `json:"network_tx_bytes"`
	NetworkRxPackets uint64    `json:"network_rx_packets,omitempty"`
	NetworkTxPackets uint64    `json:"network_tx_packets,omitempty"`
	BlockReadBytes   uint64    `json:"block_read_bytes,omitempty"`
	BlockWriteBytes  uint64    `json:"block_write_bytes,omitempty"`
	PIDs             int       `json:"pids,omitempty"`
	ReadTime         time.Time `json:"read_time"`
}

// ContainerLogsResult represents container log output.
type ContainerLogsResult struct {
	ContainerID string         `json:"container_id"`
	Name        string         `json:"name"`
	Logs        []ContainerLog `json:"logs"`
	Count       int            `json:"count"`
	Truncated   bool           `json:"truncated"`
	Error       string         `json:"error,omitempty"`
	Timestamp   time.Time      `json:"timestamp"`
}

// ContainerLog represents a single container log entry.
type ContainerLog struct {
	Timestamp time.Time `json:"timestamp"`
	Stream    string    `json:"stream"` // stdout, stderr
	Message   string    `json:"message"`
}

// =============================================================================
// Phase 3: Storage Deep Dive Types
// =============================================================================

// SMARTHealthResult contains SMART disk health information.
type SMARTHealthResult struct {
	Disks     []SMARTDisk `json:"disks"`
	Count     int         `json:"count"`
	Timestamp time.Time   `json:"timestamp"`
}

// SMARTDisk represents SMART health data for a single disk.
type SMARTDisk struct {
	Device       string           `json:"device"`
	Model        string           `json:"model,omitempty"`
	Serial       string           `json:"serial,omitempty"`
	Firmware     string           `json:"firmware,omitempty"`
	Type         string           `json:"type"` // HDD, SSD, NVMe
	Healthy      bool             `json:"healthy"`
	Temperature  int              `json:"temperature_celsius,omitempty"`
	PowerOnHours uint64           `json:"power_on_hours,omitempty"`
	PowerCycles  uint64           `json:"power_cycles,omitempty"`
	Attributes   []SMARTAttribute `json:"attributes,omitempty"`
	NVMeHealth   *NVMeHealthInfo  `json:"nvme_health,omitempty"`
	Warnings     []string         `json:"warnings,omitempty"`
	Error        string           `json:"error,omitempty"`
}

// SMARTAttribute represents a single SMART attribute.
type SMARTAttribute struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Value     int    `json:"value"`
	Worst     int    `json:"worst"`
	Threshold int    `json:"threshold"`
	RawValue  uint64 `json:"raw_value"`
	Status    string `json:"status"` // ok, warning, critical
}

// NVMeHealthInfo contains NVMe-specific health information.
type NVMeHealthInfo struct {
	PercentageUsed   int    `json:"percentage_used"`
	AvailableSpare   int    `json:"available_spare"`
	SpareThreshold   int    `json:"spare_threshold"`
	DataUnitsRead    uint64 `json:"data_units_read"`
	DataUnitsWritten uint64 `json:"data_units_written"`
	MediaErrors      uint64 `json:"media_errors"`
	CriticalWarning  int    `json:"critical_warning"`
}

// IOLatencyResult contains disk I/O latency information.
type IOLatencyResult struct {
	Devices   []IOLatencyDevice `json:"devices"`
	Count     int               `json:"count"`
	Timestamp time.Time         `json:"timestamp"`
}

// IOLatencyDevice represents I/O latency stats for a device.
type IOLatencyDevice struct {
	Device          string  `json:"device"`
	ReadLatencyMs   float64 `json:"read_latency_ms"`
	WriteLatencyMs  float64 `json:"write_latency_ms"`
	ReadIOPS        float64 `json:"read_iops"`
	WriteIOPS       float64 `json:"write_iops"`
	ReadThroughput  uint64  `json:"read_throughput_bytes"`
	WriteThroughput uint64  `json:"write_throughput_bytes"`
	QueueDepth      uint64  `json:"queue_depth"`
	Utilization     float64 `json:"utilization_percent"`
}

// VolumeStatusResult contains volume manager status information.
type VolumeStatusResult struct {
	ZFSPools     []ZFSPool     `json:"zfs_pools,omitempty"`
	LVMGroups    []LVMGroup    `json:"lvm_groups,omitempty"`
	RAIDArrays   []RAIDArray   `json:"raid_arrays,omitempty"`
	StoragePools []StoragePool `json:"storage_pools,omitempty"` // Windows Storage Spaces
	Count        int           `json:"count"`
	Timestamp    time.Time     `json:"timestamp"`
}

// ZFSPool represents a ZFS pool.
type ZFSPool struct {
	Name          string    `json:"name"`
	State         string    `json:"state"` // ONLINE, DEGRADED, FAULTED, etc.
	Size          uint64    `json:"size_bytes"`
	Allocated     uint64    `json:"allocated_bytes"`
	Free          uint64    `json:"free_bytes"`
	Fragmentation int       `json:"fragmentation_percent"`
	Health        string    `json:"health"`
	VDevs         []ZFSVDev `json:"vdevs,omitempty"`
	Errors        string    `json:"errors,omitempty"`
}

// ZFSVDev represents a ZFS virtual device.
type ZFSVDev struct {
	Name  string `json:"name"`
	Type  string `json:"type"` // disk, mirror, raidz, etc.
	State string `json:"state"`
	Read  uint64 `json:"read_errors"`
	Write uint64 `json:"write_errors"`
	Cksum uint64 `json:"checksum_errors"`
}

// LVMGroup represents an LVM volume group.
type LVMGroup struct {
	Name    string      `json:"name"`
	Size    uint64      `json:"size_bytes"`
	Free    uint64      `json:"free_bytes"`
	PVCount int         `json:"pv_count"`
	LVCount int         `json:"lv_count"`
	Volumes []LVMVolume `json:"volumes,omitempty"`
}

// LVMVolume represents an LVM logical volume.
type LVMVolume struct {
	Name   string `json:"name"`
	Size   uint64 `json:"size_bytes"`
	Active bool   `json:"active"`
	Type   string `json:"type"` // linear, striped, mirror, raid
}

// RAIDArray represents a software RAID array.
type RAIDArray struct {
	Device       string       `json:"device"`
	Level        string       `json:"level"` // raid0, raid1, raid5, etc.
	State        string       `json:"state"` // clean, degraded, rebuilding
	Size         uint64       `json:"size_bytes"`
	Disks        int          `json:"disk_count"`
	ActiveDisks  int          `json:"active_disks"`
	SpareDisks   int          `json:"spare_disks"`
	SyncProgress string       `json:"sync_progress,omitempty"`
	Members      []RAIDMember `json:"members,omitempty"`
}

// RAIDMember represents a member disk in a RAID array.
type RAIDMember struct {
	Device string `json:"device"`
	Role   string `json:"role"` // active, spare, faulty
	State  string `json:"state"`
}

// StoragePool represents a Windows Storage Space pool.
type StoragePool struct {
	Name              string `json:"name"`
	FriendlyName      string `json:"friendly_name"`
	HealthStatus      string `json:"health_status"`
	OperationalStatus string `json:"operational_status"`
	Size              uint64 `json:"size_bytes"`
	AllocatedSize     uint64 `json:"allocated_bytes"`
	ResiliencyType    string `json:"resiliency_type"`
}

// MountChangesResult contains mount point change information.
type MountChangesResult struct {
	CurrentMounts []MountInfo   `json:"current_mounts"`
	RecentChanges []MountChange `json:"recent_changes,omitempty"`
	Count         int           `json:"count"`
	Timestamp     time.Time     `json:"timestamp"`
}

// MountChange represents a mount/unmount event.
type MountChange struct {
	Device     string    `json:"device"`
	Mountpoint string    `json:"mountpoint"`
	Fstype     string    `json:"fstype"`
	Action     string    `json:"action"` // mounted, unmounted
	Timestamp  time.Time `json:"timestamp"`
}

// FSEventsResult contains filesystem event information.
type FSEventsResult struct {
	Supported  bool      `json:"supported"`
	WatchPaths []string  `json:"watch_paths,omitempty"`
	Events     []FSEvent `json:"events,omitempty"`
	Count      int       `json:"count"`
	Message    string    `json:"message,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// FSEvent represents a filesystem event.
type FSEvent struct {
	Path      string    `json:"path"`
	Operation string    `json:"operation"` // create, modify, delete, rename
	IsDir     bool      `json:"is_dir"`
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// Phase 1.9: Platform Security Controls
// =============================================================================

// WindowsDefenderStatus represents Windows Defender status.
type WindowsDefenderStatus struct {
	RealTimeProtectionEnabled bool      `json:"real_time_protection_enabled"`
	BehaviorMonitorEnabled    bool      `json:"behavior_monitor_enabled"`
	IoavProtectionEnabled     bool      `json:"ioav_protection_enabled"`
	OnAccessProtectionEnabled bool      `json:"on_access_protection_enabled"`
	AntivirusEnabled          bool      `json:"antivirus_enabled"`
	AntispywareEnabled        bool      `json:"antispyware_enabled"`
	TamperProtectionEnabled   bool      `json:"tamper_protection_enabled"`
	SignatureVersion          string    `json:"signature_version"`
	SignatureLastUpdated      time.Time `json:"signature_last_updated"`
	EngineVersion             string    `json:"engine_version"`
	ProductVersion            string    `json:"product_version"`
	QuickScanAge              int       `json:"quick_scan_age_days"`
	FullScanAge               int       `json:"full_scan_age_days"`
	Error                     string    `json:"error,omitempty"`
	Timestamp                 time.Time `json:"timestamp"`
}

// WindowsFirewallProfiles represents Windows Firewall profile states.
type WindowsFirewallProfiles struct {
	DomainProfile  FirewallProfile `json:"domain_profile"`
	PrivateProfile FirewallProfile `json:"private_profile"`
	PublicProfile  FirewallProfile `json:"public_profile"`
	Error          string          `json:"error,omitempty"`
	Timestamp      time.Time       `json:"timestamp"`
}

// FirewallProfile represents a single Windows Firewall profile.
type FirewallProfile struct {
	Name                    string `json:"name"`
	Enabled                 bool   `json:"enabled"`
	DefaultInboundAction    string `json:"default_inbound_action"`
	DefaultOutboundAction   string `json:"default_outbound_action"`
	AllowInboundRules       bool   `json:"allow_inbound_rules"`
	AllowLocalFirewallRules bool   `json:"allow_local_firewall_rules"`
	AllowLocalIPsecRules    bool   `json:"allow_local_ipsec_rules"`
	NotifyOnListen          bool   `json:"notify_on_listen"`
	LogAllowed              bool   `json:"log_allowed"`
	LogBlocked              bool   `json:"log_blocked"`
	LogFilePath             string `json:"log_file_path,omitempty"`
}

// BitLockerStatus represents BitLocker encryption status.
type BitLockerStatus struct {
	Volumes   []BitLockerVolume `json:"volumes"`
	Count     int               `json:"count"`
	Error     string            `json:"error,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// BitLockerVolume represents a single volume's BitLocker status.
type BitLockerVolume struct {
	DriveLetter       string   `json:"drive_letter"`
	VolumeType        string   `json:"volume_type"` // OperatingSystem, FixedData, Removable
	ProtectionStatus  string   `json:"protection_status"`
	LockStatus        string   `json:"lock_status"`
	EncryptionMethod  string   `json:"encryption_method,omitempty"`
	EncryptionPercent int      `json:"encryption_percent"`
	KeyProtectors     []string `json:"key_protectors,omitempty"`
}

// WindowsSMBShares represents SMB shares on Windows.
type WindowsSMBShares struct {
	Shares    []SMBShare `json:"shares"`
	Count     int        `json:"count"`
	Error     string     `json:"error,omitempty"`
	Timestamp time.Time  `json:"timestamp"`
}

// SMBShare represents a single SMB share.
type SMBShare struct {
	Name                string   `json:"name"`
	Path                string   `json:"path"`
	Description         string   `json:"description,omitempty"`
	ShareType           string   `json:"share_type"`
	CurrentUsers        int      `json:"current_users"`
	ConcurrentUserLimit int      `json:"concurrent_user_limit"`
	CachingMode         string   `json:"caching_mode,omitempty"`
	EncryptData         bool     `json:"encrypt_data"`
	FolderEnumMode      string   `json:"folder_enum_mode,omitempty"`
	Permissions         []string `json:"permissions,omitempty"`
}

// WindowsRDPConfig represents RDP configuration.
type WindowsRDPConfig struct {
	Enabled                    bool      `json:"enabled"`
	Port                       int       `json:"port"`
	NLARequired                bool      `json:"nla_required"`
	SecurityLayer              string    `json:"security_layer"`
	UserAuthenticationRequired bool      `json:"user_authentication_required"`
	EncryptionLevel            string    `json:"encryption_level"`
	MaxConnections             int       `json:"max_connections"`
	AllowedUsers               []string  `json:"allowed_users,omitempty"`
	Error                      string    `json:"error,omitempty"`
	Timestamp                  time.Time `json:"timestamp"`
}

// WindowsWinRMConfig represents WinRM configuration.
type WindowsWinRMConfig struct {
	ServiceRunning   bool            `json:"service_running"`
	HTTPEnabled      bool            `json:"http_enabled"`
	HTTPSEnabled     bool            `json:"https_enabled"`
	HTTPPort         int             `json:"http_port"`
	HTTPSPort        int             `json:"https_port"`
	AllowUnencrypted bool            `json:"allow_unencrypted"`
	BasicAuth        bool            `json:"basic_auth"`
	KerberosAuth     bool            `json:"kerberos_auth"`
	NegotiateAuth    bool            `json:"negotiate_auth"`
	CertificateAuth  bool            `json:"certificate_auth"`
	CredSSPAuth      bool            `json:"credssp_auth"`
	Listeners        []WinRMListener `json:"listeners,omitempty"`
	TrustedHosts     string          `json:"trusted_hosts,omitempty"`
	Error            string          `json:"error,omitempty"`
	Timestamp        time.Time       `json:"timestamp"`
}

// WinRMListener represents a WinRM listener.
type WinRMListener struct {
	Address   string `json:"address"`
	Transport string `json:"transport"`
	Port      int    `json:"port"`
	Hostname  string `json:"hostname,omitempty"`
	Enabled   bool   `json:"enabled"`
	URLPrefix string `json:"url_prefix,omitempty"`
}

// WindowsAppLockerPolicy represents AppLocker policy.
type WindowsAppLockerPolicy struct {
	Configured      bool                  `json:"configured"`
	EnforcementMode string                `json:"enforcement_mode"` // NotConfigured, AuditOnly, Enabled
	RuleCollections []AppLockerCollection `json:"rule_collections,omitempty"`
	Error           string                `json:"error,omitempty"`
	Timestamp       time.Time             `json:"timestamp"`
}

// AppLockerCollection represents an AppLocker rule collection.
type AppLockerCollection struct {
	Type            string `json:"type"` // Exe, Msi, Script, Appx, Dll
	EnforcementMode string `json:"enforcement_mode"`
	RuleCount       int    `json:"rule_count"`
}

// WindowsWDACStatus represents WDAC/Code Integrity status.
type WindowsWDACStatus struct {
	Enabled         bool      `json:"enabled"`
	EnforcementMode string    `json:"enforcement_mode"` // Audit, Enforced
	UMCIEnabled     bool      `json:"umci_enabled"`     // User Mode Code Integrity
	KMCIEnabled     bool      `json:"kmci_enabled"`     // Kernel Mode Code Integrity
	PolicyID        string    `json:"policy_id,omitempty"`
	PolicyVersion   string    `json:"policy_version,omitempty"`
	ActivePolicies  []string  `json:"active_policies,omitempty"`
	HVCIEnabled     bool      `json:"hvci_enabled"` // Hypervisor-protected Code Integrity
	Error           string    `json:"error,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
}

// WindowsLocalSecurityPolicy represents local security policy summary.
type WindowsLocalSecurityPolicy struct {
	PasswordPolicy        PasswordPolicy      `json:"password_policy"`
	AccountLockoutPolicy  LockoutPolicy       `json:"account_lockout_policy"`
	AuditPolicy           AuditPolicies       `json:"audit_policy"`
	UserRightsAssignments map[string][]string `json:"user_rights_assignments,omitempty"`
	Error                 string              `json:"error,omitempty"`
	Timestamp             time.Time           `json:"timestamp"`
}

// PasswordPolicy represents password policy settings.
type PasswordPolicy struct {
	MinimumLength        int  `json:"minimum_length"`
	ComplexityEnabled    bool `json:"complexity_enabled"`
	MaximumAge           int  `json:"maximum_age_days"`
	MinimumAge           int  `json:"minimum_age_days"`
	HistoryCount         int  `json:"history_count"`
	ReversibleEncryption bool `json:"reversible_encryption"`
}

// LockoutPolicy represents account lockout settings.
type LockoutPolicy struct {
	LockoutThreshold  int `json:"lockout_threshold"`
	LockoutDuration   int `json:"lockout_duration_minutes"`
	ResetCounterAfter int `json:"reset_counter_after_minutes"`
}

// AuditPolicies represents audit policy settings.
type AuditPolicies struct {
	AccountLogon      string `json:"account_logon"`
	AccountManagement string `json:"account_management"`
	DetailedTracking  string `json:"detailed_tracking"`
	DSAccess          string `json:"ds_access"`
	LogonLogoff       string `json:"logon_logoff"`
	ObjectAccess      string `json:"object_access"`
	PolicyChange      string `json:"policy_change"`
	PrivilegeUse      string `json:"privilege_use"`
	System            string `json:"system"`
}

// WindowsGPOApplied represents applied Group Policy Objects.
type WindowsGPOApplied struct {
	ComputerGPOs []AppliedGPO `json:"computer_gpos"`
	UserGPOs     []AppliedGPO `json:"user_gpos,omitempty"`
	LastRefresh  time.Time    `json:"last_refresh"`
	DomainJoined bool         `json:"domain_joined"`
	DomainName   string       `json:"domain_name,omitempty"`
	Error        string       `json:"error,omitempty"`
	Timestamp    time.Time    `json:"timestamp"`
}

// AppliedGPO represents a single applied GPO.
type AppliedGPO struct {
	Name          string   `json:"name"`
	GUID          string   `json:"guid,omitempty"`
	Link          string   `json:"link,omitempty"`
	Enabled       bool     `json:"enabled"`
	AccessDenied  bool     `json:"access_denied"`
	FilterAllowed bool     `json:"filter_allowed"`
	Revision      int      `json:"revision"`
	Extensions    []string `json:"extensions,omitempty"`
}

// WindowsCredentialGuard represents Credential Guard status.
type WindowsCredentialGuard struct {
	CredentialGuardEnabled          bool      `json:"credential_guard_enabled"`
	LsaCfgFlags                     int       `json:"lsa_cfg_flags"`
	SecurityServicesRunning         []string  `json:"security_services_running,omitempty"`
	SecurityServicesConfigured      []string  `json:"security_services_configured,omitempty"`
	VirtualizationBasedSecurity     bool      `json:"virtualization_based_security"`
	RequirePlatformSecurityFeatures string    `json:"require_platform_security_features,omitempty"`
	LsaIsoEnabled                   bool      `json:"lsa_iso_enabled"`
	Error                           string    `json:"error,omitempty"`
	Timestamp                       time.Time `json:"timestamp"`
}

// WindowsUpdateHealth represents Windows Update status.
type WindowsUpdateHealth struct {
	ServiceRunning      bool            `json:"service_running"`
	LastCheckTime       time.Time       `json:"last_check_time"`
	LastInstallTime     time.Time       `json:"last_install_time"`
	PendingUpdates      []PendingUpdate `json:"pending_updates,omitempty"`
	PendingCount        int             `json:"pending_count"`
	RebootRequired      bool            `json:"reboot_required"`
	UpdateSource        string          `json:"update_source"` // WindowsUpdate, WSUS, WUfB
	WSUSServer          string          `json:"wsus_server,omitempty"`
	DeferFeatureUpdates int             `json:"defer_feature_updates_days"`
	DeferQualityUpdates int             `json:"defer_quality_updates_days"`
	Error               string          `json:"error,omitempty"`
	Timestamp           time.Time       `json:"timestamp"`
}

// PendingUpdate represents a pending Windows update.
type PendingUpdate struct {
	Title        string `json:"title"`
	KB           string `json:"kb,omitempty"`
	Category     string `json:"category"`
	Severity     string `json:"severity,omitempty"`
	IsDownloaded bool   `json:"is_downloaded"`
}

// MacOSFileVaultStatus represents FileVault status.
type MacOSFileVaultStatus struct {
	Enabled             bool      `json:"enabled"`
	Status              string    `json:"status"` // On, Off, Encrypting, Decrypting
	EncryptionPercent   int       `json:"encryption_percent,omitempty"`
	EncryptionType      string    `json:"encryption_type,omitempty"`
	HasRecoveryKey      bool      `json:"has_recovery_key"`
	HasInstitutionalKey bool      `json:"has_institutional_key"`
	DeferredEnablement  bool      `json:"deferred_enablement"`
	Users               []string  `json:"users,omitempty"`
	Error               string    `json:"error,omitempty"`
	Timestamp           time.Time `json:"timestamp"`
}

// MacOSGatekeeperStatus represents Gatekeeper status.
type MacOSGatekeeperStatus struct {
	Enabled              bool      `json:"enabled"`
	AssessmentEnabled    bool      `json:"assessment_enabled"`
	DevIDEnabled         bool      `json:"developer_id_enabled"`
	NotarizationRequired bool      `json:"notarization_required"`
	Status               string    `json:"status"` // App Store, App Store and identified developers, Anywhere
	Error                string    `json:"error,omitempty"`
	Timestamp            time.Time `json:"timestamp"`
}

// MacOSSIPStatus represents System Integrity Protection status.
type MacOSSIPStatus struct {
	Enabled            bool      `json:"enabled"`
	Status             string    `json:"status"`
	ConfigurationFlags []string  `json:"configuration_flags,omitempty"`
	Error              string    `json:"error,omitempty"`
	Timestamp          time.Time `json:"timestamp"`
}

// MacOSXProtectStatus represents XProtect status.
type MacOSXProtectStatus struct {
	XProtectVersion       string    `json:"xprotect_version"`
	XProtectBundleVersion string    `json:"xprotect_bundle_version,omitempty"`
	MRTVersion            string    `json:"mrt_version,omitempty"`
	GatekeeperConfigData  string    `json:"gatekeeper_config_data,omitempty"`
	LastUpdate            time.Time `json:"last_update"`
	Error                 string    `json:"error,omitempty"`
	Timestamp             time.Time `json:"timestamp"`
}

// MacOSPFRules represents Packet Filter rules.
type MacOSPFRules struct {
	Enabled   bool      `json:"enabled"`
	Status    string    `json:"status"`
	RuleCount int       `json:"rule_count"`
	Rules     []PFRule  `json:"rules,omitempty"`
	Anchors   []string  `json:"anchors,omitempty"`
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// PFRule represents a PF rule.
type PFRule struct {
	Number      int    `json:"number"`
	Action      string `json:"action"`
	Direction   string `json:"direction"`
	Protocol    string `json:"protocol,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	Port        string `json:"port,omitempty"`
	States      int    `json:"states,omitempty"`
}

// MacOSMDMProfiles represents MDM profiles.
type MacOSMDMProfiles struct {
	Profiles    []MDMProfile `json:"profiles"`
	Count       int          `json:"count"`
	MDMEnrolled bool         `json:"mdm_enrolled"`
	Error       string       `json:"error,omitempty"`
	Timestamp   time.Time    `json:"timestamp"`
}

// MDMProfile represents an MDM configuration profile.
type MDMProfile struct {
	Name              string   `json:"name"`
	Identifier        string   `json:"identifier"`
	Organization      string   `json:"organization,omitempty"`
	InstallDate       string   `json:"install_date,omitempty"`
	VerificationState string   `json:"verification_state,omitempty"`
	ProfileType       string   `json:"profile_type"` // Configuration, Provisioning
	PayloadTypes      []string `json:"payload_types,omitempty"`
}

// MacOSTCCPermissions represents TCC permissions.
type MacOSTCCPermissions struct {
	Permissions []TCCPermission `json:"permissions"`
	Count       int             `json:"count"`
	Error       string          `json:"error,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
}

// TCCPermission represents a TCC permission entry.
type TCCPermission struct {
	Service      string `json:"service"`
	Client       string `json:"client"`
	ClientType   string `json:"client_type"` // bundle, path
	Allowed      bool   `json:"allowed"`
	Reason       string `json:"reason,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

// MacOSSecurityLogEvents represents security-related log events.
type MacOSSecurityLogEvents struct {
	Events    []SecurityLogEvent `json:"events"`
	Count     int                `json:"count"`
	Error     string             `json:"error,omitempty"`
	Timestamp time.Time          `json:"timestamp"`
}

// SecurityLogEvent represents a security log event.
type SecurityLogEvent struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	Process   string    `json:"process,omitempty"`
	Message   string    `json:"message"`
	Subsystem string    `json:"subsystem,omitempty"`
	Category  string    `json:"category,omitempty"`
}

// LinuxAuditdStatus represents auditd status.
type LinuxAuditdStatus struct {
	Running         bool        `json:"running"`
	Enabled         bool        `json:"enabled"`
	PID             int         `json:"pid,omitempty"`
	RuleCount       int         `json:"rule_count"`
	Rules           []AuditRule `json:"rules,omitempty"`
	BacklogLimit    int         `json:"backlog_limit"`
	BacklogWaitTime int         `json:"backlog_wait_time"`
	Failure         string      `json:"failure_mode"`
	RateLimit       int         `json:"rate_limit"`
	LostEvents      int         `json:"lost_events"`
	Error           string      `json:"error,omitempty"`
	Timestamp       time.Time   `json:"timestamp"`
}

// AuditRule represents an audit rule.
type AuditRule struct {
	Type        string `json:"type"` // syscall, file, exclude
	Key         string `json:"key,omitempty"`
	Rule        string `json:"rule"`
	Permissions string `json:"permissions,omitempty"`
}

// LinuxKernelLockdown represents kernel lockdown mode.
type LinuxKernelLockdown struct {
	Mode       string    `json:"mode"` // none, integrity, confidentiality
	Supported  bool      `json:"supported"`
	SecureBoot bool      `json:"secure_boot"`
	Error      string    `json:"error,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// LinuxSysctlSecurity represents security-related sysctl values.
type LinuxSysctlSecurity struct {
	Values    map[string]string `json:"values"`
	Hardened  []SysctlCheck     `json:"hardened_checks"`
	Score     int               `json:"score"` // Percentage of checks passed
	Error     string            `json:"error,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

// SysctlCheck represents a sysctl security check.
type SysctlCheck struct {
	Key              string `json:"key"`
	CurrentValue     string `json:"current_value"`
	RecommendedValue string `json:"recommended_value"`
	Passed           bool   `json:"passed"`
	Description      string `json:"description"`
}

// LinuxFirewallBackend represents the active firewall backend.
type LinuxFirewallBackend struct {
	Backend       string    `json:"backend"` // nftables, iptables, firewalld, ufw, none
	Active        bool      `json:"active"`
	Version       string    `json:"version,omitempty"`
	DefaultPolicy string    `json:"default_policy,omitempty"`
	Zones         []string  `json:"zones,omitempty"` // For firewalld
	RuleCount     int       `json:"rule_count"`
	Error         string    `json:"error,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// LinuxMACDetailed represents detailed MAC status (SELinux/AppArmor).
type LinuxMACDetailed struct {
	Type           string           `json:"type"` // selinux, apparmor, none
	Enabled        bool             `json:"enabled"`
	Mode           string           `json:"mode"` // enforcing, permissive, disabled / enforce, complain
	PolicyVersion  string           `json:"policy_version,omitempty"`
	PolicyType     string           `json:"policy_type,omitempty"` // SELinux: targeted, mls, etc
	SELinuxStatus  *SELinuxDetails  `json:"selinux_status,omitempty"`
	AppArmorStatus *AppArmorDetails `json:"apparmor_status,omitempty"`
	Error          string           `json:"error,omitempty"`
	Timestamp      time.Time        `json:"timestamp"`
}

// SELinuxDetails represents SELinux-specific details.
type SELinuxDetails struct {
	CurrentMode      string          `json:"current_mode"`
	ConfigMode       string          `json:"config_mode"`
	MLS              bool            `json:"mls_enabled"`
	LoadedPolicyName string          `json:"loaded_policy_name"`
	Booleans         map[string]bool `json:"booleans,omitempty"`
	DenialCount      int             `json:"denial_count"`
}

// AppArmorDetails represents AppArmor-specific details.
type AppArmorDetails struct {
	ProfilesLoaded      int               `json:"profiles_loaded"`
	ProfilesEnforce     int               `json:"profiles_enforce"`
	ProfilesComplain    int               `json:"profiles_complain"`
	ProcessesConfined   int               `json:"processes_confined"`
	ProcessesUnconfined int               `json:"processes_unconfined"`
	Profiles            []AppArmorProfile `json:"profiles,omitempty"`
}

// AppArmorProfile represents an AppArmor profile.
type AppArmorProfile struct {
	Name string `json:"name"`
	Mode string `json:"mode"` // enforce, complain, unconfined
}

// LinuxPackageRepos represents package repository summary.
type LinuxPackageRepos struct {
	PackageManager string        `json:"package_manager"` // apt, dnf, yum, zypper, pacman
	Repos          []PackageRepo `json:"repos"`
	Count          int           `json:"count"`
	Error          string        `json:"error,omitempty"`
	Timestamp      time.Time     `json:"timestamp"`
}

// PackageRepo represents a package repository.
type PackageRepo struct {
	Name       string   `json:"name"`
	URL        string   `json:"url,omitempty"`
	Enabled    bool     `json:"enabled"`
	GPGCheck   bool     `json:"gpg_check"`
	Type       string   `json:"type,omitempty"`       // deb, rpm, etc
	Components []string `json:"components,omitempty"` // For apt: main, universe, etc
}

// LinuxAutoUpdates represents automatic update configuration.
type LinuxAutoUpdates struct {
	Enabled        bool      `json:"enabled"`
	Service        string    `json:"service"` // unattended-upgrades, dnf-automatic, etc
	AutoReboot     bool      `json:"auto_reboot"`
	RebootTime     string    `json:"reboot_time,omitempty"`
	SecurityOnly   bool      `json:"security_only"`
	MailOnError    bool      `json:"mail_on_error"`
	MailTo         string    `json:"mail_to,omitempty"`
	UpdateInterval string    `json:"update_interval,omitempty"`
	LastRun        time.Time `json:"last_run"`
	Error          string    `json:"error,omitempty"`
	Timestamp      time.Time `json:"timestamp"`
}

// VendorServicesResult represents OS vendor services inventory.
type VendorServicesResult struct {
	Services  []VendorService `json:"services"`
	Count     int             `json:"count"`
	Platform  string          `json:"platform"`
	Error     string          `json:"error,omitempty"`
	Timestamp time.Time       `json:"timestamp"`
}

// VendorService represents an OS vendor service.
type VendorService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status"` // running, stopped, etc
	StartType   string `json:"start_type,omitempty"`
	Vendor      string `json:"vendor"`             // Microsoft, Apple, Linux distro
	Category    string `json:"category,omitempty"` // security, networking, system, etc
}

// ============================================================================
// Phase 4: Network Intelligence Types
// ============================================================================

// ConnectionTrackingResult represents detailed connection tracking.
type ConnectionTrackingResult struct {
	Connections []TrackedConnection `json:"connections"`
	Summary     ConnectionSummary   `json:"summary"`
	Count       int                 `json:"count"`
	Timestamp   time.Time           `json:"timestamp"`
}

// TrackedConnection represents a tracked network connection with process info.
type TrackedConnection struct {
	Protocol    string    `json:"protocol"` // tcp, udp, tcp6, udp6
	LocalAddr   string    `json:"local_addr"`
	LocalPort   uint16    `json:"local_port"`
	RemoteAddr  string    `json:"remote_addr"`
	RemotePort  uint16    `json:"remote_port"`
	State       string    `json:"state"`
	PID         int32     `json:"pid,omitempty"`
	ProcessName string    `json:"process_name,omitempty"`
	Username    string    `json:"username,omitempty"`
	BytesSent   uint64    `json:"bytes_sent,omitempty"`
	BytesRecv   uint64    `json:"bytes_recv,omitempty"`
	Duration    float64   `json:"duration_seconds,omitempty"`
	StartTime   time.Time `json:"start_time,omitempty"`
}

// ConnectionSummary provides aggregated connection statistics.
type ConnectionSummary struct {
	TotalConnections int            `json:"total_connections"`
	ByState          map[string]int `json:"by_state"`
	ByProtocol       map[string]int `json:"by_protocol"`
	ByProcess        map[string]int `json:"by_process,omitempty"`
	UniqueRemoteIPs  int            `json:"unique_remote_ips"`
}

// DNSStatsResult represents DNS resolution statistics.
type DNSStatsResult struct {
	Servers       []DNSServerStats `json:"servers"`
	Cache         *DNSCache        `json:"cache,omitempty"`
	QueryStats    DNSQueryStats    `json:"query_stats"`
	ResolvConf    string           `json:"resolv_conf,omitempty"`
	SearchDomains []string         `json:"search_domains,omitempty"`
	Timestamp     time.Time        `json:"timestamp"`
}

// DNSServerStats represents statistics for a DNS server.
type DNSServerStats struct {
	Address      string  `json:"address"`
	Interface    string  `json:"interface,omitempty"`
	Type         string  `json:"type"` // system, resolved, dhcp
	Priority     int     `json:"priority,omitempty"`
	Reachable    bool    `json:"reachable"`
	LatencyMs    float64 `json:"latency_ms,omitempty"`
	QueriesSent  uint64  `json:"queries_sent,omitempty"`
	QuerySuccess uint64  `json:"query_success,omitempty"`
	QueryFailed  uint64  `json:"query_failed,omitempty"`
}

// DNSCache represents DNS cache information.
type DNSCache struct {
	Entries    int     `json:"entries"`
	HitRate    float64 `json:"hit_rate,omitempty"`
	MissRate   float64 `json:"miss_rate,omitempty"`
	Size       uint64  `json:"size_bytes,omitempty"`
	MaxSize    uint64  `json:"max_size_bytes,omitempty"`
	TTLSeconds int     `json:"ttl_seconds,omitempty"`
}

// DNSQueryStats represents DNS query statistics.
type DNSQueryStats struct {
	TotalQueries   uint64 `json:"total_queries"`
	SuccessQueries uint64 `json:"success_queries"`
	FailedQueries  uint64 `json:"failed_queries"`
	CacheHits      uint64 `json:"cache_hits"`
	CacheMisses    uint64 `json:"cache_misses"`
}

// FirewallDeepResult represents comprehensive firewall analysis.
type FirewallDeepResult struct {
	Backend        string             `json:"backend"` // iptables, nftables, pf, netfilter
	Enabled        bool               `json:"enabled"`
	DefaultInput   string             `json:"default_input,omitempty"` // accept, drop, reject
	DefaultOutput  string             `json:"default_output,omitempty"`
	DefaultForward string             `json:"default_forward,omitempty"`
	Tables         []FirewallTable    `json:"tables,omitempty"`
	Zones          []FirewallZone     `json:"zones,omitempty"`
	Statistics     FirewallStatistics `json:"statistics"`
	Warnings       []string           `json:"warnings,omitempty"`
	Timestamp      time.Time          `json:"timestamp"`
}

// FirewallTable represents a firewall table (iptables/nftables).
type FirewallTable struct {
	Name   string          `json:"name"`
	Family string          `json:"family,omitempty"` // inet, ip, ip6
	Chains []FirewallChain `json:"chains"`
}

// FirewallChain represents a firewall chain.
type FirewallChain struct {
	Name    string             `json:"name"`
	Policy  string             `json:"policy,omitempty"`
	Type    string             `json:"type,omitempty"` // filter, nat, mangle
	Rules   []FirewallRuleDeep `json:"rules"`
	Packets uint64             `json:"packets,omitempty"`
	Bytes   uint64             `json:"bytes,omitempty"`
}

// FirewallRuleDeep represents a detailed firewall rule.
type FirewallRuleDeep struct {
	Number      int    `json:"number"`
	Action      string `json:"action"`
	Protocol    string `json:"protocol,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	SrcPort     string `json:"src_port,omitempty"`
	DstPort     string `json:"dst_port,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Direction   string `json:"direction,omitempty"` // in, out
	State       string `json:"state,omitempty"`     // new, established, related
	Comment     string `json:"comment,omitempty"`
	Packets     uint64 `json:"packets,omitempty"`
	Bytes       uint64 `json:"bytes,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// FirewallZone represents a firewall zone (firewalld/ufw).
type FirewallZone struct {
	Name       string   `json:"name"`
	Active     bool     `json:"active"`
	Interfaces []string `json:"interfaces"`
	Services   []string `json:"services"`
	Ports      []string `json:"ports"`
	Target     string   `json:"target,omitempty"`
}

// FirewallStatistics provides firewall statistics.
type FirewallStatistics struct {
	TotalRules      int    `json:"total_rules"`
	AcceptRules     int    `json:"accept_rules"`
	DropRules       int    `json:"drop_rules"`
	RejectRules     int    `json:"reject_rules"`
	LogRules        int    `json:"log_rules"`
	TotalPackets    uint64 `json:"total_packets,omitempty"`
	TotalBytes      uint64 `json:"total_bytes,omitempty"`
	DroppedPackets  uint64 `json:"dropped_packets,omitempty"`
	RejectedPackets uint64 `json:"rejected_packets,omitempty"`
}

// WiFiMetricsResult represents WiFi signal and quality metrics.
type WiFiMetricsResult struct {
	Interfaces []WiFiInterface `json:"interfaces"`
	Available  bool            `json:"available"`
	Timestamp  time.Time       `json:"timestamp"`
}

// WiFiInterface represents a WiFi network interface.
type WiFiInterface struct {
	Name          string  `json:"name"`
	SSID          string  `json:"ssid,omitempty"`
	BSSID         string  `json:"bssid,omitempty"`
	Frequency     float64 `json:"frequency_mhz,omitempty"`
	Channel       int     `json:"channel,omitempty"`
	SignalLevel   int     `json:"signal_level_dbm,omitempty"`
	SignalQuality int     `json:"signal_quality_percent,omitempty"`
	NoiseLevel    int     `json:"noise_level_dbm,omitempty"`
	BitRate       float64 `json:"bit_rate_mbps,omitempty"`
	TxPower       int     `json:"tx_power_dbm,omitempty"`
	LinkQuality   string  `json:"link_quality,omitempty"`
	Mode          string  `json:"mode,omitempty"`     // managed, ad-hoc, monitor
	Security      string  `json:"security,omitempty"` // WPA2, WPA3, etc
	Connected     bool    `json:"connected"`
}

// NetworkLatencyResult represents network latency probe results.
type NetworkLatencyResult struct {
	Probes    []LatencyProbe `json:"probes"`
	Summary   LatencySummary `json:"summary"`
	Timestamp time.Time      `json:"timestamp"`
}

// LatencyProbe represents a single latency probe result.
type LatencyProbe struct {
	Target      string  `json:"target"`
	Type        string  `json:"type"` // icmp, tcp, http
	Port        int     `json:"port,omitempty"`
	Success     bool    `json:"success"`
	LatencyMs   float64 `json:"latency_ms,omitempty"`
	MinMs       float64 `json:"min_ms,omitempty"`
	MaxMs       float64 `json:"max_ms,omitempty"`
	AvgMs       float64 `json:"avg_ms,omitempty"`
	StdDevMs    float64 `json:"stddev_ms,omitempty"`
	PacketsSent int     `json:"packets_sent"`
	PacketsRecv int     `json:"packets_recv"`
	PacketLoss  float64 `json:"packet_loss_percent"`
	Error       string  `json:"error,omitempty"`
}

// LatencySummary provides overall latency statistics.
type LatencySummary struct {
	TotalProbes   int     `json:"total_probes"`
	SuccessProbes int     `json:"success_probes"`
	FailedProbes  int     `json:"failed_probes"`
	AvgLatencyMs  float64 `json:"avg_latency_ms"`
	MinLatencyMs  float64 `json:"min_latency_ms"`
	MaxLatencyMs  float64 `json:"max_latency_ms"`
}

// ============================================================================
// Phase 5: Analytics & Trends Types
// ============================================================================

// HistoricalMetricsResult represents historical system metrics.
type HistoricalMetricsResult struct {
	TimeRange  TimeRange         `json:"time_range"`
	CPU        []MetricDataPoint `json:"cpu,omitempty"`
	Memory     []MetricDataPoint `json:"memory,omitempty"`
	Disk       []MetricDataPoint `json:"disk,omitempty"`
	Network    []MetricDataPoint `json:"network,omitempty"`
	DataSource string            `json:"data_source"` // sar, journal, wtmp, etc
	Timestamp  time.Time         `json:"timestamp"`
}

// TimeRange represents a time range for historical data.
type TimeRange struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Duration string    `json:"duration"`
}

// MetricDataPoint represents a single metric data point.
type MetricDataPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label,omitempty"`
}

// AnomalyDetectionResult represents detected anomalies.
type AnomalyDetectionResult struct {
	Anomalies  []Anomaly          `json:"anomalies"`
	Count      int                `json:"count"`
	TimeRange  TimeRange          `json:"time_range"`
	Thresholds map[string]float64 `json:"thresholds"`
	Timestamp  time.Time          `json:"timestamp"`
}

// Anomaly represents a detected anomaly.
type Anomaly struct {
	Metric      string    `json:"metric"`
	Value       float64   `json:"value"`
	Expected    float64   `json:"expected"`
	Deviation   float64   `json:"deviation_percent"`
	Severity    string    `json:"severity"` // low, medium, high, critical
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

// CapacityForecastResult represents capacity planning forecasts.
type CapacityForecastResult struct {
	Forecasts []CapacityForecast `json:"forecasts"`
	Timestamp time.Time          `json:"timestamp"`
}

// CapacityForecast represents a capacity forecast for a resource.
type CapacityForecast struct {
	Resource       string    `json:"resource"` // disk, memory, inodes
	CurrentUsage   float64   `json:"current_usage_percent"`
	GrowthRate     float64   `json:"growth_rate_per_day"`
	DaysToFull     int       `json:"days_to_full,omitempty"`
	EstimatedFull  time.Time `json:"estimated_full,omitempty"`
	Recommendation string    `json:"recommendation,omitempty"`
	Confidence     float64   `json:"confidence_percent"`
}

// TrendAnalysisResult represents performance trend analysis.
type TrendAnalysisResult struct {
	Trends    []Trend   `json:"trends"`
	Period    string    `json:"period"` // 1h, 24h, 7d, 30d
	Timestamp time.Time `json:"timestamp"`
}

// Trend represents a performance trend.
type Trend struct {
	Metric     string  `json:"metric"`
	Direction  string  `json:"direction"` // up, down, stable
	ChangeRate float64 `json:"change_rate_percent"`
	StartValue float64 `json:"start_value"`
	EndValue   float64 `json:"end_value"`
	Slope      float64 `json:"slope"`
	Analysis   string  `json:"analysis,omitempty"`
}

// ============================================================================
// Phase 6: Automation & Alerting Types (Read-only)
// ============================================================================

// AlertStatusResult represents current system alert status.
type AlertStatusResult struct {
	Alerts    []SystemAlert `json:"alerts"`
	Count     int           `json:"count"`
	Critical  int           `json:"critical_count"`
	Warning   int           `json:"warning_count"`
	Info      int           `json:"info_count"`
	Timestamp time.Time     `json:"timestamp"`
}

// SystemAlert represents a system alert.
type SystemAlert struct {
	ID           string    `json:"id"`
	Severity     string    `json:"severity"` // critical, warning, info
	Category     string    `json:"category"` // cpu, memory, disk, network, security
	Message      string    `json:"message"`
	Source       string    `json:"source"`
	Value        float64   `json:"value,omitempty"`
	Threshold    float64   `json:"threshold,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Count        int       `json:"count"`
	Acknowledged bool      `json:"acknowledged"`
}

// RemediationSuggestionsResult represents suggested remediation actions.
type RemediationSuggestionsResult struct {
	Suggestions []RemediationSuggestion `json:"suggestions"`
	Count       int                     `json:"count"`
	Timestamp   time.Time               `json:"timestamp"`
}

// RemediationSuggestion represents a remediation suggestion.
type RemediationSuggestion struct {
	Issue      string   `json:"issue"`
	Severity   string   `json:"severity"`
	Category   string   `json:"category"`
	Suggestion string   `json:"suggestion"`
	Commands   []string `json:"commands,omitempty"`
	Risk       string   `json:"risk"` // low, medium, high
	Automated  bool     `json:"automated_available"`
	References []string `json:"references,omitempty"`
}

// RunbookRecommendationsResult represents runbook recommendations.
type RunbookRecommendationsResult struct {
	Recommendations []RunbookRecommendation `json:"recommendations"`
	Count           int                     `json:"count"`
	Timestamp       time.Time               `json:"timestamp"`
}

// RunbookRecommendation represents a runbook recommendation.
type RunbookRecommendation struct {
	Title      string   `json:"title"`
	Category   string   `json:"category"`
	Priority   string   `json:"priority"` // high, medium, low
	Reason     string   `json:"reason"`
	Steps      []string `json:"steps"`
	References []string `json:"references,omitempty"`
}

// ============================================================================
// Phase 7: Security & Compliance Types
// ============================================================================

// SecurityScanResult represents a security vulnerability scan.
type SecurityScanResult struct {
	Findings  []SecurityFinding `json:"findings"`
	Summary   SecuritySummary   `json:"summary"`
	Score     int               `json:"score"` // 0-100
	Grade     string            `json:"grade"` // A, B, C, D, F
	Timestamp time.Time         `json:"timestamp"`
}

// SecurityFinding represents a security finding.
type SecurityFinding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"` // critical, high, medium, low, info
	Category    string   `json:"category"` // authentication, encryption, permissions, network
	Resource    string   `json:"resource,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	CVE         string   `json:"cve,omitempty"`
}

// SecuritySummary provides security scan summary.
type SecuritySummary struct {
	TotalFindings    int `json:"total_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings      int `json:"low_findings"`
	InfoFindings     int `json:"info_findings"`
	PassedChecks     int `json:"passed_checks"`
	FailedChecks     int `json:"failed_checks"`
}

// ComplianceCheckResult represents compliance check results.
type ComplianceCheckResult struct {
	Framework string            `json:"framework"` // CIS, STIG, PCI-DSS
	Version   string            `json:"version"`
	Profile   string            `json:"profile,omitempty"` // Level 1, Level 2
	Checks    []ComplianceCheck `json:"checks"`
	Summary   ComplianceSummary `json:"summary"`
	Score     float64           `json:"score_percent"`
	Timestamp time.Time         `json:"timestamp"`
}

// ComplianceCheck represents a single compliance check.
type ComplianceCheck struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Section     string `json:"section,omitempty"`
	Status      string `json:"status"` // pass, fail, skip, manual
	Severity    string `json:"severity"`
	Actual      string `json:"actual,omitempty"`
	Expected    string `json:"expected,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// ComplianceSummary provides compliance summary.
type ComplianceSummary struct {
	TotalChecks int `json:"total_checks"`
	Passed      int `json:"passed"`
	Failed      int `json:"failed"`
	Skipped     int `json:"skipped"`
	Manual      int `json:"manual"`
}

// ForensicSnapshotResult represents a forensic data snapshot.
type ForensicSnapshotResult struct {
	SnapshotID    string                 `json:"snapshot_id"`
	CollectedAt   time.Time              `json:"collected_at"`
	System        ForensicSystem         `json:"system"`
	Users         []ForensicUser         `json:"users"`
	Processes     []ForensicProcess      `json:"processes"`
	NetworkConns  []ForensicConnection   `json:"network_connections"`
	OpenFiles     []ForensicOpenFile     `json:"open_files"`
	RecentLogins  []ForensicLogin        `json:"recent_logins"`
	ModifiedFiles []ForensicModifiedFile `json:"recently_modified_files,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

// ForensicSystem represents system forensic data.
type ForensicSystem struct {
	Hostname    string    `json:"hostname"`
	OS          string    `json:"os"`
	Kernel      string    `json:"kernel"`
	BootTime    time.Time `json:"boot_time"`
	Uptime      string    `json:"uptime"`
	Timezone    string    `json:"timezone"`
	LastUpdated string    `json:"last_package_update,omitempty"`
}

// ForensicUser represents user forensic data.
type ForensicUser struct {
	Username  string    `json:"username"`
	UID       int       `json:"uid"`
	Groups    []string  `json:"groups"`
	Shell     string    `json:"shell"`
	HomeDir   string    `json:"home_dir"`
	LastLogin time.Time `json:"last_login,omitempty"`
	IsAdmin   bool      `json:"is_admin"`
	IsLocked  bool      `json:"is_locked"`
}

// ForensicProcess represents process forensic data.
type ForensicProcess struct {
	PID         int32     `json:"pid"`
	PPID        int32     `json:"ppid"`
	Name        string    `json:"name"`
	Cmdline     string    `json:"cmdline"`
	User        string    `json:"user"`
	StartTime   time.Time `json:"start_time"`
	CPUPercent  float64   `json:"cpu_percent"`
	MemPercent  float32   `json:"mem_percent"`
	OpenFiles   int       `json:"open_files"`
	Connections int       `json:"connections"`
}

// ForensicConnection represents network connection forensic data.
type ForensicConnection struct {
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	PID        int32  `json:"pid"`
	Process    string `json:"process"`
}

// ForensicOpenFile represents open file forensic data.
type ForensicOpenFile struct {
	Path    string `json:"path"`
	PID     int32  `json:"pid"`
	Process string `json:"process"`
	Type    string `json:"type"` // file, socket, pipe
	Mode    string `json:"mode,omitempty"`
}

// ForensicLogin represents login forensic data.
type ForensicLogin struct {
	Username  string    `json:"username"`
	Terminal  string    `json:"terminal"`
	Host      string    `json:"host"`
	LoginTime time.Time `json:"login_time"`
	Type      string    `json:"type"` // login, logout, failed
}

// ForensicModifiedFile represents recently modified file data.
type ForensicModifiedFile struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	Owner    string    `json:"owner"`
	Modified time.Time `json:"modified"`
	Type     string    `json:"type"` // config, binary, script
}

// AuditTrailResult represents security audit trail.
type AuditTrailResult struct {
	Events    []AuditEvent `json:"events"`
	Count     int          `json:"count"`
	TimeRange TimeRange    `json:"time_range"`
	Sources   []string     `json:"sources"`
	Timestamp time.Time    `json:"timestamp"`
}

// AuditEvent represents a security audit event.
type AuditEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"` // auth, exec, file, network, privilege
	Action    string    `json:"action"`
	Subject   string    `json:"subject"` // user or process
	Object    string    `json:"object"`  // file, service, etc
	Result    string    `json:"result"`  // success, failure
	Source    string    `json:"source"`  // auth.log, audit.log, syslog
	Details   string    `json:"details,omitempty"`
	Severity  string    `json:"severity,omitempty"`
}

// HardeningRecommendationsResult represents security hardening recommendations.
type HardeningRecommendationsResult struct {
	Recommendations []HardeningRecommendation `json:"recommendations"`
	Categories      map[string]int            `json:"by_category"`
	PriorityCount   map[string]int            `json:"by_priority"`
	Timestamp       time.Time                 `json:"timestamp"`
}

// HardeningRecommendation represents a security hardening recommendation.
type HardeningRecommendation struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"` // authentication, network, filesystem, kernel
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Priority     string   `json:"priority"` // critical, high, medium, low
	CurrentState string   `json:"current_state"`
	TargetState  string   `json:"target_state"`
	Remediation  string   `json:"remediation"`
	Commands     []string `json:"commands,omitempty"`
	References   []string `json:"references,omitempty"`
	Impact       string   `json:"impact,omitempty"`
}

// ============================================================================
// Phase 1.9: Consumer Diagnostics Types
// ============================================================================

// BluetoothDevicesResult represents Bluetooth device information.
type BluetoothDevicesResult struct {
	Devices   []BluetoothDevice  `json:"devices"`
	Adapters  []BluetoothAdapter `json:"adapters,omitempty"`
	Available bool               `json:"available"`
	Error     string             `json:"error,omitempty"`
	Timestamp time.Time          `json:"timestamp"`
}

// BluetoothDevice represents a Bluetooth device.
type BluetoothDevice struct {
	Name       string `json:"name"`
	InstanceID string `json:"instance_id,omitempty"`
	Status     string `json:"status"`                // OK, Error, Degraded, Unknown
	DeviceType string `json:"device_type,omitempty"` // Audio, Input, etc.
	Connected  bool   `json:"connected"`
	Paired     bool   `json:"paired,omitempty"`
	Address    string `json:"address,omitempty"`
}

// BluetoothAdapter represents a Bluetooth adapter/radio.
type BluetoothAdapter struct {
	Name         string `json:"name"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Status       string `json:"status"`
	Enabled      bool   `json:"enabled"`
}

// AudioDevicesResult represents audio device information.
type AudioDevicesResult struct {
	Devices   []AudioDevice `json:"devices"`
	Available bool          `json:"available"`
	Error     string        `json:"error,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// AudioDevice represents an audio device.
type AudioDevice struct {
	Name         string `json:"name"`
	DeviceID     string `json:"device_id,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Status       string `json:"status"`                // OK, Error, Degraded, Unknown
	DeviceType   string `json:"device_type,omitempty"` // Playback, Recording
	IsDefault    bool   `json:"is_default,omitempty"`
	Driver       string `json:"driver,omitempty"`
}

// PrintersResult represents printer information.
type PrintersResult struct {
	Printers       []PrinterInfo `json:"printers"`
	SpoolerStatus  string        `json:"spooler_status"` // Running, Stopped, etc.
	SpoolerRunning bool          `json:"spooler_running"`
	Available      bool          `json:"available"`
	Error          string        `json:"error,omitempty"`
	Timestamp      time.Time     `json:"timestamp"`
}

// PrinterInfo represents a printer.
type PrinterInfo struct {
	Name         string `json:"name"`
	PortName     string `json:"port_name,omitempty"`
	DriverName   string `json:"driver_name,omitempty"`
	Status       string `json:"status"` // Ready, Printing, Error, Offline
	StatusCode   int    `json:"status_code,omitempty"`
	IsDefault    bool   `json:"is_default"`
	IsNetwork    bool   `json:"is_network"`
	IsShared     bool   `json:"is_shared"`
	JobCount     int    `json:"job_count,omitempty"`
	PrinterState string `json:"printer_state,omitempty"` // Idle, Printing, etc.
	Location     string `json:"location,omitempty"`
}

// DisplayConfigResult represents display configuration information.
type DisplayConfigResult struct {
	Monitors      []MonitorInfo  `json:"monitors"`
	VideoAdapters []VideoAdapter `json:"video_adapters"`
	Available     bool           `json:"available"`
	Error         string         `json:"error,omitempty"`
	Timestamp     time.Time      `json:"timestamp"`
}

// MonitorInfo represents a display monitor.
type MonitorInfo struct {
	Name           string `json:"name"`
	DeviceID       string `json:"device_id,omitempty"`
	ScreenWidth    int    `json:"screen_width"`
	ScreenHeight   int    `json:"screen_height"`
	BitsPerPixel   int    `json:"bits_per_pixel,omitempty"`
	RefreshRate    int    `json:"refresh_rate_hz,omitempty"`
	IsPrimary      bool   `json:"is_primary"`
	Status         string `json:"status,omitempty"`
	MonitorType    string `json:"monitor_type,omitempty"`
	PixelsPerXInch int    `json:"pixels_per_x_inch,omitempty"`
	PixelsPerYInch int    `json:"pixels_per_y_inch,omitempty"`
}

// VideoAdapter represents a video/graphics adapter.
type VideoAdapter struct {
	Name                string `json:"name"`
	DeviceID            string `json:"device_id,omitempty"`
	AdapterRAM          uint64 `json:"adapter_ram_bytes,omitempty"`
	DriverVersion       string `json:"driver_version,omitempty"`
	DriverDate          string `json:"driver_date,omitempty"`
	VideoProcessor      string `json:"video_processor,omitempty"`
	CurrentRefreshRate  int    `json:"current_refresh_rate_hz,omitempty"`
	CurrentResolutionH  int    `json:"current_resolution_horizontal,omitempty"`
	CurrentResolutionV  int    `json:"current_resolution_vertical,omitempty"`
	CurrentBitsPerPixel int    `json:"current_bits_per_pixel,omitempty"`
	Status              string `json:"status,omitempty"`
}
