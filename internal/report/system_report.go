// Package report provides system report generation with parallel data collection.
package report

import (
	"context"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/alerts"
	"github.com/levantar-ai/mcp-sysinfo/internal/analytics"
	"github.com/levantar-ai/mcp-sysinfo/internal/collector"
	"github.com/levantar-ai/mcp-sysinfo/internal/compliance"
	"github.com/levantar-ai/mcp-sysinfo/internal/cpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
	"github.com/levantar-ai/mcp-sysinfo/internal/gpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/hardware"
	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
	"github.com/levantar-ai/mcp-sysinfo/internal/netconfig"
	"github.com/levantar-ai/mcp-sysinfo/internal/network"
	"github.com/levantar-ai/mcp-sysinfo/internal/osinfo"
	"github.com/levantar-ai/mcp-sysinfo/internal/process"
	"github.com/levantar-ai/mcp-sysinfo/internal/runtimes"
	"github.com/levantar-ai/mcp-sysinfo/internal/scheduled"
	"github.com/levantar-ai/mcp-sysinfo/internal/software"
	"github.com/levantar-ai/mcp-sysinfo/internal/uptime"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// SystemReport contains all data needed for system overview HTML reports.
type SystemReport struct {
	Generated time.Time `json:"generated"`
	Hostname  string    `json:"hostname"`

	// System Overview
	OS       interface{} `json:"os,omitempty"`
	Hardware interface{} `json:"hardware,omitempty"`
	Uptime   interface{} `json:"uptime,omitempty"`

	// Performance
	CPU       interface{} `json:"cpu,omitempty"`
	Memory    interface{} `json:"memory,omitempty"`
	GPU       interface{} `json:"gpu,omitempty"`
	Processes interface{} `json:"processes,omitempty"`

	// Storage
	Disks interface{} `json:"disks,omitempty"`

	// Network
	Network        interface{} `json:"network,omitempty"`
	ListeningPorts interface{} `json:"listening_ports,omitempty"`
	DNS            interface{} `json:"dns,omitempty"`
	Routes         interface{} `json:"routes,omitempty"`
	ARP            interface{} `json:"arp,omitempty"`

	// Security
	StartupItems interface{} `json:"startup_items,omitempty"`

	// Software
	Programs interface{} `json:"programs,omitempty"`
	Runtimes interface{} `json:"runtimes,omitempty"`

	// Phase 4: Network Intelligence
	ConnectionTracking interface{} `json:"connection_tracking,omitempty"`
	DNSStats           interface{} `json:"dns_stats,omitempty"`
	FirewallDeep       interface{} `json:"firewall_deep,omitempty"`
	WiFiMetrics        interface{} `json:"wifi_metrics,omitempty"`
	NetworkLatency     interface{} `json:"network_latency,omitempty"`

	// Phase 5: Analytics & Trends
	AnomalyDetection interface{} `json:"anomaly_detection,omitempty"`
	CapacityForecast interface{} `json:"capacity_forecast,omitempty"`
	TrendAnalysis    interface{} `json:"trend_analysis,omitempty"`

	// Phase 6: Alerts & Remediation
	AlertStatus              interface{} `json:"alert_status,omitempty"`
	RemediationSuggestions   interface{} `json:"remediation_suggestions,omitempty"`
	RunbookRecommendations   interface{} `json:"runbook_recommendations,omitempty"`

	// Phase 7: Security & Compliance
	SecurityScan              interface{} `json:"security_scan,omitempty"`
	ComplianceCheck           interface{} `json:"compliance_check,omitempty"`
	HardeningRecommendations  interface{} `json:"hardening_recommendations,omitempty"`

	// Errors encountered during collection
	Errors map[string]string `json:"errors,omitempty"`
}

// ReportGenerator generates system reports with parallel collection.
type ReportGenerator struct {
	timeout time.Duration
}

// NewReportGenerator creates a new report generator.
func NewReportGenerator(timeout time.Duration) *ReportGenerator {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &ReportGenerator{timeout: timeout}
}

// GenerateSystemReport collects all system data in parallel and returns a report.
func (rg *ReportGenerator) GenerateSystemReport(ctx context.Context, sections []string) (*SystemReport, error) {
	pc := collector.NewParallelCollector(rg.timeout)

	// Define all collectors
	allCollectors := map[string]collector.CollectorFunc{
		"os": func(ctx context.Context) (interface{}, error) {
			return osinfo.NewCollector().GetOSInfo()
		},
		"hardware": func(ctx context.Context) (interface{}, error) {
			return hardware.NewCollector().GetHardwareInfo()
		},
		"uptime": func(ctx context.Context) (interface{}, error) {
			return uptime.NewCollector().Collect()
		},
		"cpu": func(ctx context.Context) (interface{}, error) {
			return cpu.NewCollector().Collect(false)
		},
		"memory": func(ctx context.Context) (interface{}, error) {
			return memory.NewCollector().Collect()
		},
		"gpu": func(ctx context.Context) (interface{}, error) {
			return gpu.NewCollector().GetGPUInfo()
		},
		"processes": func(ctx context.Context) (interface{}, error) {
			return process.NewCollector().GetTopProcesses(20, "memory")
		},
		"disks": func(ctx context.Context) (interface{}, error) {
			return disk.NewCollector().Collect()
		},
		"network": func(ctx context.Context) (interface{}, error) {
			return network.NewCollector().Collect()
		},
		"listening_ports": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetListeningPorts()
		},
		"dns": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetDNSServers()
		},
		"routes": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetRoutes()
		},
		"arp": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetARPTable()
		},
		"startup_items": func(ctx context.Context) (interface{}, error) {
			return scheduled.NewCollector().GetStartupItems()
		},
		"programs": func(ctx context.Context) (interface{}, error) {
			return software.NewCollector().GetWindowsPrograms()
		},
		"runtimes": func(ctx context.Context) (interface{}, error) {
			return runtimes.NewCollector().GetLanguageRuntimes()
		},
		// Phase 4: Network Intelligence
		"connection_tracking": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetConnectionTracking()
		},
		"dns_stats": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetDNSStats()
		},
		"firewall_deep": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetFirewallDeep()
		},
		"wifi_metrics": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetWiFiMetrics()
		},
		"network_latency": func(ctx context.Context) (interface{}, error) {
			return netconfig.NewCollector().GetNetworkLatency([]string{"8.8.8.8", "1.1.1.1"})
		},
		// Phase 5: Analytics & Trends
		"anomaly_detection": func(ctx context.Context) (interface{}, error) {
			return analytics.NewCollector().GetAnomalyDetection()
		},
		"capacity_forecast": func(ctx context.Context) (interface{}, error) {
			return analytics.NewCollector().GetCapacityForecast()
		},
		"trend_analysis": func(ctx context.Context) (interface{}, error) {
			return analytics.NewCollector().GetTrendAnalysis("1h")
		},
		// Phase 6: Alerts & Remediation
		"alert_status": func(ctx context.Context) (interface{}, error) {
			return alerts.NewCollector().GetAlertStatus()
		},
		"remediation_suggestions": func(ctx context.Context) (interface{}, error) {
			return alerts.NewCollector().GetRemediationSuggestions()
		},
		"runbook_recommendations": func(ctx context.Context) (interface{}, error) {
			return alerts.NewCollector().GetRunbookRecommendations()
		},
		// Phase 7: Security & Compliance
		"security_scan": func(ctx context.Context) (interface{}, error) {
			return compliance.NewCollector().GetSecurityScan()
		},
		"compliance_check": func(ctx context.Context) (interface{}, error) {
			return compliance.NewCollector().GetComplianceCheck("basic")
		},
		"hardening_recommendations": func(ctx context.Context) (interface{}, error) {
			return compliance.NewCollector().GetHardeningRecommendations()
		},
	}

	// Filter collectors if sections specified
	collectors := allCollectors
	if len(sections) > 0 {
		collectors = make(map[string]collector.CollectorFunc)
		for _, s := range sections {
			if fn, ok := allCollectors[s]; ok {
				collectors[s] = fn
			}
		}
	}

	// Run all collectors in parallel
	results := pc.Collect(ctx, collectors)

	// Build report
	report := &SystemReport{
		Generated: time.Now().UTC(),
		Errors:    make(map[string]string),
	}

	// Map results to report fields
	for name, result := range results {
		if result.Error != nil {
			report.Errors[name] = result.Error.Error()
			continue
		}

		switch name {
		case "os":
			report.OS = result.Data
			if osData, ok := result.Data.(*types.OSInfoResult); ok {
				report.Hostname = osData.Hostname
			}
		case "hardware":
			report.Hardware = result.Data
		case "uptime":
			report.Uptime = result.Data
		case "cpu":
			report.CPU = result.Data
		case "memory":
			report.Memory = result.Data
		case "gpu":
			report.GPU = result.Data
		case "processes":
			report.Processes = result.Data
		case "disks":
			report.Disks = result.Data
		case "network":
			report.Network = result.Data
		case "listening_ports":
			report.ListeningPorts = result.Data
		case "dns":
			report.DNS = result.Data
		case "routes":
			report.Routes = result.Data
		case "arp":
			report.ARP = result.Data
		case "startup_items":
			report.StartupItems = result.Data
		case "programs":
			report.Programs = result.Data
		case "runtimes":
			report.Runtimes = result.Data
		// Phase 4: Network Intelligence
		case "connection_tracking":
			report.ConnectionTracking = result.Data
		case "dns_stats":
			report.DNSStats = result.Data
		case "firewall_deep":
			report.FirewallDeep = result.Data
		case "wifi_metrics":
			report.WiFiMetrics = result.Data
		case "network_latency":
			report.NetworkLatency = result.Data
		// Phase 5: Analytics & Trends
		case "anomaly_detection":
			report.AnomalyDetection = result.Data
		case "capacity_forecast":
			report.CapacityForecast = result.Data
		case "trend_analysis":
			report.TrendAnalysis = result.Data
		// Phase 6: Alerts & Remediation
		case "alert_status":
			report.AlertStatus = result.Data
		case "remediation_suggestions":
			report.RemediationSuggestions = result.Data
		case "runbook_recommendations":
			report.RunbookRecommendations = result.Data
		// Phase 7: Security & Compliance
		case "security_scan":
			report.SecurityScan = result.Data
		case "compliance_check":
			report.ComplianceCheck = result.Data
		case "hardening_recommendations":
			report.HardeningRecommendations = result.Data
		}
	}

	return report, nil
}
