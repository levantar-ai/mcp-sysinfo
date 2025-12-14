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
