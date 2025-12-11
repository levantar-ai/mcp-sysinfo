// Package types defines common types used across the mcp-sysinfo project.
package types

import "time"

// CPUInfo represents CPU metrics.
type CPUInfo struct {
	Percent      float64            `json:"percent"`
	PerCPU       []float64          `json:"per_cpu,omitempty"`
	Count        int                `json:"count"`
	PhysicalCount int               `json:"physical_count"`
	Frequency    *FrequencyInfo     `json:"frequency,omitempty"`
	LoadAverage  *LoadAverage       `json:"load_average,omitempty"`
	Timestamp    time.Time          `json:"timestamp"`
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
	Active        uint64    `json:"active,omitempty"`        // Linux/macOS
	Inactive      uint64    `json:"inactive,omitempty"`      // Linux/macOS
	Wired         uint64    `json:"wired,omitempty"`         // macOS only
	Compressed    uint64    `json:"compressed,omitempty"`    // macOS only
	Buffers       uint64    `json:"buffers,omitempty"`       // Linux only
	Cached        uint64    `json:"cached,omitempty"`        // Linux/Windows
	Shared        uint64    `json:"shared,omitempty"`        // Linux only
	Slab          uint64    `json:"slab,omitempty"`          // Linux only
	SReclaimable  uint64    `json:"sreclaimable,omitempty"`  // Linux only
	SUReClaimable uint64    `json:"sunreclaimable,omitempty"` // Linux only
	PageTables    uint64    `json:"page_tables,omitempty"`   // Linux only
	SwapCached    uint64    `json:"swap_cached,omitempty"`   // Linux only
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
	Type       string `json:"type"`        // tcp, udp, tcp6, udp6
	LocalAddr  string `json:"local_addr"`
	LocalPort  uint16 `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	Status     string `json:"status"`
	PID        int32  `json:"pid,omitempty"`
}

// ProcessInfo represents a single process.
type ProcessInfo struct {
	PID         int32     `json:"pid"`
	Name        string    `json:"name"`
	Username    string    `json:"username,omitempty"`
	CPUPercent  float64   `json:"cpu_percent"`
	MemPercent  float32   `json:"mem_percent"`
	MemRSS      uint64    `json:"mem_rss"`
	Status      string    `json:"status"`
	CreateTime  time.Time `json:"create_time"`
	Cmdline     string    `json:"cmdline,omitempty"`
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
	Score      int                  `json:"score"` // 0-100
	Categories map[string]int       `json:"categories"`
	Issues     []Issue              `json:"issues"`
	Timestamp  time.Time            `json:"timestamp"`
}

// Issue represents a detected system issue.
type Issue struct {
	Severity    string `json:"severity"` // critical, warning, info
	Category    string `json:"category"`
	Message     string `json:"message"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// Alert represents an alert configuration.
type Alert struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Condition   string                 `json:"condition"`
	Threshold   float64                `json:"threshold"`
	Duration    time.Duration          `json:"duration"`
	Severity    string                 `json:"severity"`
	Actions     []string               `json:"actions"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Platform represents the current platform.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformDarwin  Platform = "darwin"
	PlatformWindows Platform = "windows"
	PlatformUnknown Platform = "unknown"
)
