// Package alerts provides system alert detection and remediation suggestions.
package alerts

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
	"github.com/levantar-ai/mcp-sysinfo/internal/netconfig"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects alert and remediation data.
type Collector struct{}

// NewCollector creates a new alerts collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetAlertStatus retrieves current system alert status.
func (c *Collector) GetAlertStatus() (*types.AlertStatusResult, error) {
	result := &types.AlertStatusResult{
		Timestamp: time.Now(),
	}

	now := time.Now()

	// Check CPU alerts
	cpuCollector := cpu.NewCollector()
	cpuInfo, err := cpuCollector.Collect(false)
	if err == nil {
		if cpuInfo.Percent > 95 {
			result.Alerts = append(result.Alerts, types.SystemAlert{
				ID:        generateAlertID("cpu_critical", cpuInfo.Percent),
				Severity:  "critical",
				Category:  "cpu",
				Message:   fmt.Sprintf("CPU usage critical: %.1f%%", cpuInfo.Percent),
				Source:    "cpu_monitor",
				Value:     cpuInfo.Percent,
				Threshold: 95,
				FirstSeen: now,
				LastSeen:  now,
				Count:     1,
			})
		} else if cpuInfo.Percent > 80 {
			result.Alerts = append(result.Alerts, types.SystemAlert{
				ID:        generateAlertID("cpu_high", cpuInfo.Percent),
				Severity:  "warning",
				Category:  "cpu",
				Message:   fmt.Sprintf("CPU usage high: %.1f%%", cpuInfo.Percent),
				Source:    "cpu_monitor",
				Value:     cpuInfo.Percent,
				Threshold: 80,
				FirstSeen: now,
				LastSeen:  now,
				Count:     1,
			})
		}

		// Check load average
		if cpuInfo.LoadAverage != nil {
			loadPerCPU := cpuInfo.LoadAverage.Load1 / float64(cpuInfo.Count)
			if loadPerCPU > 2 {
				severity := "warning"
				if loadPerCPU > 4 {
					severity = "critical"
				}
				result.Alerts = append(result.Alerts, types.SystemAlert{
					ID:        generateAlertID("load_high", loadPerCPU),
					Severity:  severity,
					Category:  "cpu",
					Message:   fmt.Sprintf("System load high: %.2f (%.2f per CPU)", cpuInfo.LoadAverage.Load1, loadPerCPU),
					Source:    "load_monitor",
					Value:     cpuInfo.LoadAverage.Load1,
					Threshold: float64(cpuInfo.Count) * 2,
					FirstSeen: now,
					LastSeen:  now,
					Count:     1,
				})
			}
		}
	}

	// Check memory alerts
	memCollector := memory.NewCollector()
	memInfo, err := memCollector.Collect()
	if err == nil {
		if memInfo.UsedPercent > 95 {
			result.Alerts = append(result.Alerts, types.SystemAlert{
				ID:        generateAlertID("memory_critical", memInfo.UsedPercent),
				Severity:  "critical",
				Category:  "memory",
				Message:   fmt.Sprintf("Memory usage critical: %.1f%%", memInfo.UsedPercent),
				Source:    "memory_monitor",
				Value:     memInfo.UsedPercent,
				Threshold: 95,
				FirstSeen: now,
				LastSeen:  now,
				Count:     1,
			})
		} else if memInfo.UsedPercent > 85 {
			result.Alerts = append(result.Alerts, types.SystemAlert{
				ID:        generateAlertID("memory_high", memInfo.UsedPercent),
				Severity:  "warning",
				Category:  "memory",
				Message:   fmt.Sprintf("Memory usage high: %.1f%%", memInfo.UsedPercent),
				Source:    "memory_monitor",
				Value:     memInfo.UsedPercent,
				Threshold: 85,
				FirstSeen: now,
				LastSeen:  now,
				Count:     1,
			})
		}

		// Check swap usage
		if memInfo.Swap != nil && memInfo.Swap.UsedPercent > 80 {
			result.Alerts = append(result.Alerts, types.SystemAlert{
				ID:        generateAlertID("swap_high", memInfo.Swap.UsedPercent),
				Severity:  "warning",
				Category:  "memory",
				Message:   fmt.Sprintf("Swap usage high: %.1f%%", memInfo.Swap.UsedPercent),
				Source:    "swap_monitor",
				Value:     memInfo.Swap.UsedPercent,
				Threshold: 80,
				FirstSeen: now,
				LastSeen:  now,
				Count:     1,
			})
		}
	}

	// Check disk alerts
	diskCollector := disk.NewCollector()
	diskInfo, err := diskCollector.Collect()
	if err == nil {
		for _, part := range diskInfo.Partitions {
			if part.UsedPercent > 95 {
				result.Alerts = append(result.Alerts, types.SystemAlert{
					ID:        generateAlertID("disk_critical_"+part.Mountpoint, part.UsedPercent),
					Severity:  "critical",
					Category:  "disk",
					Message:   fmt.Sprintf("Disk %s critically full: %.1f%%", part.Mountpoint, part.UsedPercent),
					Source:    "disk_monitor",
					Value:     part.UsedPercent,
					Threshold: 95,
					FirstSeen: now,
					LastSeen:  now,
					Count:     1,
				})
			} else if part.UsedPercent > 85 {
				result.Alerts = append(result.Alerts, types.SystemAlert{
					ID:        generateAlertID("disk_warning_"+part.Mountpoint, part.UsedPercent),
					Severity:  "warning",
					Category:  "disk",
					Message:   fmt.Sprintf("Disk %s usage high: %.1f%%", part.Mountpoint, part.UsedPercent),
					Source:    "disk_monitor",
					Value:     part.UsedPercent,
					Threshold: 85,
					FirstSeen: now,
					LastSeen:  now,
					Count:     1,
				})
			}
		}
	}

	// Count by severity
	for _, alert := range result.Alerts {
		switch alert.Severity {
		case "critical":
			result.Critical++
		case "warning":
			result.Warning++
		case "info":
			result.Info++
		}
	}

	result.Count = len(result.Alerts)
	return result, nil
}

// generateAlertID generates a unique alert ID based on type and value.
func generateAlertID(alertType string, value float64) string {
	data := fmt.Sprintf("%s:%.2f", alertType, value)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// GetRemediationSuggestions provides remediation suggestions based on current issues.
func (c *Collector) GetRemediationSuggestions() (*types.RemediationSuggestionsResult, error) {
	result := &types.RemediationSuggestionsResult{
		Timestamp: time.Now(),
	}

	// Get current alerts to base suggestions on
	alertStatus, err := c.GetAlertStatus()
	if err == nil {
		for _, alert := range alertStatus.Alerts {
			suggestion := generateSuggestion(alert)
			if suggestion != nil {
				result.Suggestions = append(result.Suggestions, *suggestion)
			}
		}
	}

	// Check for network issues
	netCollector := netconfig.NewCollector()
	ports, err := netCollector.GetListeningPorts()
	if err == nil {
		// Check for potentially risky open ports
		riskyPorts := map[uint16]string{
			23:   "Telnet (insecure)",
			21:   "FTP (insecure)",
			3389: "RDP (remote access)",
			5900: "VNC (remote access)",
		}

		for _, port := range ports.Ports {
			if desc, risky := riskyPorts[port.Port]; risky {
				result.Suggestions = append(result.Suggestions, types.RemediationSuggestion{
					Issue:      fmt.Sprintf("Port %d (%s) is open", port.Port, desc),
					Severity:   "medium",
					Category:   "network",
					Suggestion: fmt.Sprintf("Consider disabling %s or restricting access via firewall", desc),
					Risk:       "medium",
					Automated:  false,
				})
			}
		}
	}

	result.Count = len(result.Suggestions)
	return result, nil
}

// generateSuggestion creates a remediation suggestion for an alert.
func generateSuggestion(alert types.SystemAlert) *types.RemediationSuggestion {
	switch alert.Category {
	case "cpu":
		if alert.Severity == "critical" || alert.Severity == "warning" {
			return &types.RemediationSuggestion{
				Issue:      alert.Message,
				Severity:   alert.Severity,
				Category:   "cpu",
				Suggestion: "Identify and optimize CPU-intensive processes. Consider scaling resources or load balancing.",
				Commands:   []string{"top -o %CPU", "ps aux --sort=-%cpu | head -20"},
				Risk:       "low",
				Automated:  false,
				References: []string{"https://linux.die.net/man/1/top"},
			}
		}

	case "memory":
		if alert.Severity == "critical" || alert.Severity == "warning" {
			return &types.RemediationSuggestion{
				Issue:      alert.Message,
				Severity:   alert.Severity,
				Category:   "memory",
				Suggestion: "Identify memory-intensive processes. Consider adding RAM or optimizing applications.",
				Commands:   []string{"ps aux --sort=-%mem | head -20", "free -h"},
				Risk:       "low",
				Automated:  false,
				References: []string{"https://linux.die.net/man/1/free"},
			}
		}

	case "disk":
		if alert.Severity == "critical" {
			return &types.RemediationSuggestion{
				Issue:      alert.Message,
				Severity:   "critical",
				Category:   "disk",
				Suggestion: "URGENT: Free disk space immediately. Remove old logs, temp files, or expand storage.",
				Commands:   []string{"du -sh /* 2>/dev/null | sort -rh | head -10", "journalctl --vacuum-size=100M"},
				Risk:       "medium",
				Automated:  false,
				References: []string{"https://linux.die.net/man/1/du"},
			}
		} else if alert.Severity == "warning" {
			return &types.RemediationSuggestion{
				Issue:      alert.Message,
				Severity:   "warning",
				Category:   "disk",
				Suggestion: "Plan disk cleanup or expansion. Review large files and old logs.",
				Commands:   []string{"du -sh /* 2>/dev/null | sort -rh | head -10", "find /var/log -type f -mtime +30"},
				Risk:       "low",
				Automated:  false,
			}
		}
	}

	return nil
}

// GetRunbookRecommendations provides runbook recommendations based on system state.
func (c *Collector) GetRunbookRecommendations() (*types.RunbookRecommendationsResult, error) {
	result := &types.RunbookRecommendationsResult{
		Timestamp: time.Now(),
	}

	// Get alerts to determine relevant runbooks
	alertStatus, err := c.GetAlertStatus()
	if err != nil {
		return result, nil
	}

	// Track which categories have issues
	hasIssue := make(map[string]bool)
	for _, alert := range alertStatus.Alerts {
		hasIssue[alert.Category] = true
	}

	// Add relevant runbooks based on issues
	if hasIssue["cpu"] {
		result.Recommendations = append(result.Recommendations, types.RunbookRecommendation{
			Title:    "High CPU Usage Investigation",
			Category: "performance",
			Priority: "high",
			Reason:   "Active CPU alerts detected",
			Steps: []string{
				"1. Run 'top' or 'htop' to identify high CPU processes",
				"2. Check process history with 'ps aux --sort=-%cpu'",
				"3. Review application logs for errors or loops",
				"4. Check for runaway processes or infinite loops",
				"5. Consider process priorities with 'renice'",
			},
		})
	}

	if hasIssue["memory"] {
		result.Recommendations = append(result.Recommendations, types.RunbookRecommendation{
			Title:    "Memory Pressure Investigation",
			Category: "performance",
			Priority: "high",
			Reason:   "Active memory alerts detected",
			Steps: []string{
				"1. Check memory usage with 'free -h'",
				"2. Identify memory-heavy processes with 'ps aux --sort=-%mem'",
				"3. Check for memory leaks in applications",
				"4. Review OOM killer logs in dmesg or journal",
				"5. Consider adjusting vm.swappiness if needed",
			},
		})
	}

	if hasIssue["disk"] {
		result.Recommendations = append(result.Recommendations, types.RunbookRecommendation{
			Title:    "Disk Space Emergency Cleanup",
			Category: "storage",
			Priority: "critical",
			Reason:   "Active disk space alerts detected",
			Steps: []string{
				"1. Find largest directories: du -sh /* 2>/dev/null | sort -rh",
				"2. Clean package cache: apt clean or yum clean all",
				"3. Rotate and compress logs: journalctl --vacuum-size=100M",
				"4. Find and remove old files: find /tmp -mtime +7 -delete",
				"5. Consider moving large files to external storage",
			},
		})
	}

	// Always recommend periodic maintenance
	result.Recommendations = append(result.Recommendations, types.RunbookRecommendation{
		Title:    "Regular System Health Check",
		Category: "maintenance",
		Priority: "low",
		Reason:   "Periodic maintenance recommendation",
		Steps: []string{
			"1. Review system logs for errors",
			"2. Check disk SMART health status",
			"3. Verify backup integrity",
			"4. Review and apply security updates",
			"5. Check service status and restart failed services",
		},
	})

	result.Count = len(result.Recommendations)
	return result, nil
}
