//go:build linux
// +build linux

package triage

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/internal/osinfo"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

func (c *Collector) getRecentReboots(limit int) (*types.RecentRebootsResult, error) {
	result := &types.RecentRebootsResult{
		Reboots:   []types.RebootEvent{},
		Timestamp: time.Now(),
	}

	// Use last command to get reboot history
	cmd := cmdexec.Command("last", "-x", "reboot", "-F", "-n", strconv.Itoa(limit))
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "reboot") {
				event := parseRebootLine(line)
				if event != nil {
					result.Reboots = append(result.Reboots, *event)
				}
			}
		}
	}

	// Also check journald for boot events
	cmd = cmdexec.Command("journalctl", "--list-boots", "-n", strconv.Itoa(limit))
	output, err = cmd.Output()
	if err == nil && len(result.Reboots) == 0 {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			event := parseJournalBoot(line)
			if event != nil {
				result.Reboots = append(result.Reboots, *event)
			}
		}
	}

	result.Count = len(result.Reboots)
	return result, nil
}

func parseRebootLine(line string) *types.RebootEvent {
	event := &types.RebootEvent{
		Type:   "reboot",
		Reason: "system boot",
	}

	// Parse timestamp - look for date pattern
	re := regexp.MustCompile(`[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}`)
	match := re.FindString(line)
	if match != "" {
		layouts := []string{
			"Mon Jan 2 15:04:05 2006",
			"Mon Jan  2 15:04:05 2006",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, match); err == nil {
				event.Time = t
				break
			}
		}
	}

	return event
}

func parseJournalBoot(line string) *types.RebootEvent {
	event := &types.RebootEvent{
		Type:   "reboot",
		Reason: "system boot",
	}

	parts := strings.Fields(line)
	if len(parts) < 4 {
		return nil
	}

	// Parse timestamp from journalctl format
	for i, p := range parts {
		if strings.Contains(p, "-") && len(p) == 10 { // Date format YYYY-MM-DD
			if i+1 < len(parts) {
				timeStr := p + " " + parts[i+1]
				if t, err := time.Parse("2006-01-02 15:04:05", timeStr); err == nil {
					event.Time = t
					break
				}
			}
		}
	}

	return event
}

func (c *Collector) getRecentServiceFailures(limit int) (*types.RecentServiceFailuresResult, error) {
	result := &types.RecentServiceFailuresResult{
		Failures:  []types.ServiceFailure{},
		Timestamp: time.Now(),
	}

	// Query journald for service failures
	cmd := cmdexec.Command("journalctl", "-p", "err", "-u", "*.service", "--since", "24 hours ago", "-o", "json", "-n", strconv.Itoa(limit*5))
	output, err := cmd.Output()
	if err == nil {
		failures := parseServiceFailuresJSON(string(output), limit)
		result.Failures = failures
	}

	// Also check systemctl for failed services
	cmd = cmdexec.Command("systemctl", "list-units", "--failed", "--no-legend", "--plain")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				serviceName := parts[0]
				// Check if we already have this service
				found := false
				for _, f := range result.Failures {
					if f.Service == serviceName {
						found = true
						break
					}
				}
				if !found && len(result.Failures) < limit {
					result.Failures = append(result.Failures, types.ServiceFailure{
						Service: serviceName,
						Time:    time.Now(),
						Status:  "failed",
					})
				}
			}
		}
	}

	result.Count = len(result.Failures)
	return result, nil
}

func parseServiceFailuresJSON(jsonOutput string, limit int) []types.ServiceFailure {
	var failures []types.ServiceFailure
	serviceMap := make(map[string]*types.ServiceFailure)

	lines := strings.Split(jsonOutput, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		unit := extractJSONField(line, "_SYSTEMD_UNIT")
		message := extractJSONField(line, "MESSAGE")
		timestamp := extractJSONField(line, "__REALTIME_TIMESTAMP")

		if unit != "" && strings.HasSuffix(unit, ".service") {
			if existing, ok := serviceMap[unit]; ok {
				existing.Restarts++
			} else {
				sf := &types.ServiceFailure{
					Service:  unit,
					Status:   "error",
					Restarts: 1,
					Message:  truncateString(message, 200),
				}
				if ts, err := strconv.ParseInt(timestamp, 10, 64); err == nil {
					sf.Time = time.Unix(0, ts*1000)
				}
				serviceMap[unit] = sf
			}
		}
	}

	for _, sf := range serviceMap {
		failures = append(failures, *sf)
		if len(failures) >= limit {
			break
		}
	}

	return failures
}

func extractJSONField(line, field string) string {
	pattern := fmt.Sprintf(`"%s"\s*:\s*"([^"]*)"`, field)
	re := regexp.MustCompile(pattern)
	match := re.FindStringSubmatch(line)
	if len(match) >= 2 {
		return match[1]
	}
	pattern = fmt.Sprintf(`"%s"\s*:\s*(\d+)`, field)
	re = regexp.MustCompile(pattern)
	match = re.FindStringSubmatch(line)
	if len(match) >= 2 {
		return match[1]
	}
	return ""
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func (c *Collector) getRecentKernelEvents(limit int) (*types.RecentKernelEventsResult, error) {
	result := &types.RecentKernelEventsResult{
		Events:    []types.KernelEvent{},
		Timestamp: time.Now(),
	}

	// Get kernel messages from dmesg
	cmd := cmdexec.Command("dmesg", "-T", "--level=err,warn,crit,alert,emerg")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		count := 0
		for i := len(lines) - 1; i >= 0 && count < limit; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			event := parseKernelEvent(line)
			if event != nil {
				result.Events = append(result.Events, *event)
				count++
				if event.Level == "error" {
					result.Errors++
				} else if event.Level == "warning" {
					result.Warnings++
				}
			}
		}
	}

	// Also check journald kernel messages
	if len(result.Events) == 0 {
		cmd = cmdexec.Command("journalctl", "-k", "-p", "warning", "-n", strconv.Itoa(limit), "--no-pager")
		output, err = cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "--") {
					continue
				}
				event := parseJournalKernelEvent(line)
				if event != nil && len(result.Events) < limit {
					result.Events = append(result.Events, *event)
				}
			}
		}
	}

	result.Count = len(result.Events)
	return result, nil
}

func parseKernelEvent(line string) *types.KernelEvent {
	event := &types.KernelEvent{}

	// Extract timestamp
	re := regexp.MustCompile(`\[([^\]]+)\]`)
	match := re.FindStringSubmatch(line)
	if len(match) >= 2 {
		if t, err := time.Parse("Mon Jan 2 15:04:05 2006", match[1]); err == nil {
			event.Time = t
		}
		line = strings.TrimSpace(line[len(match[0]):])
	}

	// Determine level from message content
	lowerLine := strings.ToLower(line)
	switch {
	case strings.Contains(lowerLine, "error") || strings.Contains(lowerLine, "fail"):
		event.Level = "error"
	case strings.Contains(lowerLine, "warn"):
		event.Level = "warning"
	case strings.Contains(lowerLine, "critical") || strings.Contains(lowerLine, "crit"):
		event.Level = "critical"
	default:
		event.Level = "info"
	}

	// Determine facility
	if strings.Contains(lowerLine, "usb") {
		event.Facility = "usb"
	} else if strings.Contains(lowerLine, "cpu") {
		event.Facility = "cpu"
	} else if strings.Contains(lowerLine, "memory") || strings.Contains(lowerLine, "oom") {
		event.Facility = "memory"
	} else if strings.Contains(lowerLine, "disk") || strings.Contains(lowerLine, "sd") || strings.Contains(lowerLine, "nvme") {
		event.Facility = "disk"
	} else if strings.Contains(lowerLine, "net") || strings.Contains(lowerLine, "eth") {
		event.Facility = "network"
	} else {
		event.Facility = "kernel"
	}

	event.Message = truncateString(line, 300)
	return event
}

func parseJournalKernelEvent(line string) *types.KernelEvent {
	parts := strings.SplitN(line, "kernel:", 2)
	if len(parts) < 2 {
		return nil
	}

	event := &types.KernelEvent{
		Message:  truncateString(strings.TrimSpace(parts[1]), 300),
		Facility: "kernel",
		Level:    "warning",
	}

	// Parse timestamp from beginning
	timeStr := strings.TrimSpace(parts[0])
	fields := strings.Fields(timeStr)
	if len(fields) >= 3 {
		tStr := strings.Join(fields[:3], " ")
		year := time.Now().Year()
		if t, err := time.Parse("Jan 02 15:04:05", tStr); err == nil {
			event.Time = t.AddDate(year, 0, 0)
		}
	}

	return event
}

func (c *Collector) getRecentResourceIncidents(limit int) (*types.RecentResourceIncidentsResult, error) {
	result := &types.RecentResourceIncidentsResult{
		Incidents: []types.ResourceIncident{},
		Timestamp: time.Now(),
	}

	// Check for OOM events
	cmd := cmdexec.Command("dmesg", "-T")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for i := len(lines) - 1; i >= 0 && len(result.Incidents) < limit; i-- {
			line := lines[i]
			if strings.Contains(line, "Out of memory") || strings.Contains(line, "oom-kill") {
				incident := parseOOMIncident(line)
				if incident != nil {
					result.Incidents = append(result.Incidents, *incident)
					result.OOMKills++
				}
			}
			if strings.Contains(line, "I/O error") || strings.Contains(line, "hard resetting link") {
				incident := &types.ResourceIncident{
					Time:    time.Now(),
					Type:    "io_error",
					Details: truncateString(line, 200),
				}
				result.Incidents = append(result.Incidents, *incident)
			}
		}
	}

	// Check journald for resource issues
	cmd = cmdexec.Command("journalctl", "-p", "warning", "--since", "24 hours ago", "-g", "memory|oom|disk|cpu|load", "-n", strconv.Itoa(limit*2), "--no-pager")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "--") {
				continue
			}
			if len(result.Incidents) >= limit {
				break
			}
			incident := parseResourceIncident(line)
			if incident != nil {
				result.Incidents = append(result.Incidents, *incident)
			}
		}
	}

	result.Count = len(result.Incidents)
	return result, nil
}

func parseOOMIncident(line string) *types.ResourceIncident {
	incident := &types.ResourceIncident{
		Time:    time.Now(),
		Type:    "oom",
		Details: truncateString(line, 200),
	}

	// Extract process if mentioned
	re := regexp.MustCompile(`Killed process \d+ \(([^)]+)\)`)
	match := re.FindStringSubmatch(line)
	if len(match) >= 2 {
		incident.Process = match[1]
	}

	return incident
}

func parseResourceIncident(line string) *types.ResourceIncident {
	lowerLine := strings.ToLower(line)
	incident := &types.ResourceIncident{
		Time:    time.Now(),
		Details: truncateString(line, 200),
	}

	switch {
	case strings.Contains(lowerLine, "memory") || strings.Contains(lowerLine, "oom"):
		incident.Type = "memory_pressure"
	case strings.Contains(lowerLine, "disk") || strings.Contains(lowerLine, "no space"):
		incident.Type = "disk_space"
	case strings.Contains(lowerLine, "cpu") || strings.Contains(lowerLine, "load"):
		incident.Type = "cpu_throttle"
	default:
		return nil
	}

	return incident
}

func (c *Collector) getRecentConfigChanges(limit int) (*types.RecentConfigChangesResult, error) {
	result := &types.RecentConfigChangesResult{
		Changes:   []types.ConfigChange{},
		Timestamp: time.Now(),
	}

	// Check for recently modified config files
	configDirs := []string{"/etc", "/usr/lib/systemd/system", "/etc/systemd/system"}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)

	for _, dir := range configDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if info.ModTime().After(cutoff) && len(result.Changes) < limit {
				change := types.ConfigChange{
					Path: path,
					Time: info.ModTime(),
					Type: "config_change",
				}
				result.Changes = append(result.Changes, change)
			}
			return nil
		})
	}

	result.Count = len(result.Changes)
	return result, nil
}

func (c *Collector) getRecentCriticalEvents(limit int) (*types.RecentCriticalEventsResult, error) {
	result := &types.RecentCriticalEventsResult{
		Events:    []types.CriticalEvent{},
		Timestamp: time.Now(),
	}

	// Query journald for critical/emergency events
	cmd := cmdexec.Command("journalctl", "-p", "crit", "--since", "7 days ago", "-o", "short-iso", "-n", strconv.Itoa(limit), "--no-pager")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "--") {
				continue
			}
			event := parseCriticalEvent(line)
			if event != nil && len(result.Events) < limit {
				result.Events = append(result.Events, *event)
			}
		}
	}

	// Also check emergency level
	cmd = cmdexec.Command("journalctl", "-p", "emerg", "--since", "30 days ago", "-o", "short-iso", "-n", strconv.Itoa(limit), "--no-pager")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "--") {
				continue
			}
			event := parseCriticalEvent(line)
			if event != nil {
				event.Priority = "emergency"
				if len(result.Events) < limit {
					result.Events = append(result.Events, *event)
				}
			}
		}
	}

	result.Count = len(result.Events)
	return result, nil
}

func parseCriticalEvent(line string) *types.CriticalEvent {
	event := &types.CriticalEvent{
		Priority: "critical",
	}

	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		return nil
	}

	// Parse timestamp
	if t, err := time.Parse("2006-01-02T15:04:05-0700", parts[0]); err == nil {
		event.Time = t
	}

	// Extract source (service name)
	sourcePart := parts[2]
	if idx := strings.Index(sourcePart, "["); idx > 0 {
		event.Source = sourcePart[:idx]
	} else if idx := strings.Index(sourcePart, ":"); idx > 0 {
		event.Source = sourcePart[:idx]
	} else {
		event.Source = sourcePart
	}

	event.Message = truncateString(parts[3], 300)

	return event
}

func (c *Collector) getFailedUnits() (*types.FailedUnitsResult, error) {
	result := &types.FailedUnitsResult{
		Units:     []types.FailedUnit{},
		Timestamp: time.Now(),
	}

	cmd := cmdexec.Command("systemctl", "list-units", "--failed", "--no-legend", "--plain", "--full")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 4 {
			unit := types.FailedUnit{
				Name:        parts[0],
				LoadState:   parts[1],
				ActiveState: parts[2],
				SubState:    parts[3],
			}
			if len(parts) >= 5 {
				unit.Description = strings.Join(parts[4:], " ")
			}

			// Get failure reason
			cmd := cmdexec.Command("systemctl", "show", parts[0], "--property=Result,ExecMainStatus,ActiveEnterTimestamp")
			showOutput, err := cmd.Output()
			if err == nil {
				for _, showLine := range strings.Split(string(showOutput), "\n") {
					if strings.HasPrefix(showLine, "Result=") {
						unit.Result = strings.TrimPrefix(showLine, "Result=")
					}
					if strings.HasPrefix(showLine, "ActiveEnterTimestamp=") {
						tsStr := strings.TrimPrefix(showLine, "ActiveEnterTimestamp=")
						if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", tsStr); err == nil {
							unit.FailedAt = t
						}
					}
				}
			}

			result.Units = append(result.Units, unit)
		}
	}

	result.Count = len(result.Units)
	return result, nil
}

func (c *Collector) getTimerJobs() (*types.TimerJobsResult, error) {
	result := &types.TimerJobsResult{
		Timers:    []types.TimerJob{},
		Timestamp: time.Now(),
	}

	// Get systemd timers
	cmd := cmdexec.Command("systemctl", "list-timers", "--all", "--no-legend", "--plain")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			timer := parseTimerLine(line)
			if timer != nil {
				result.Timers = append(result.Timers, *timer)
			}
		}
	}

	// Get cron jobs
	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			timer := types.TimerJob{
				Name:     entry.Name(),
				Schedule: filepath.Base(dir),
			}
			result.Timers = append(result.Timers, timer)
		}
	}

	result.Count = len(result.Timers)
	return result, nil
}

func parseTimerLine(line string) *types.TimerJob {
	parts := strings.Fields(line)
	if len(parts) < 6 {
		return nil
	}

	timer := &types.TimerJob{}

	// Find the .timer unit name
	for i, p := range parts {
		if strings.HasSuffix(p, ".timer") {
			timer.Name = p
			if i+1 < len(parts) {
				timer.Unit = parts[i+1]
			}
			break
		}
	}

	if timer.Name == "" {
		return nil
	}

	// Try to parse next run time
	if len(parts) >= 4 {
		dateStr := strings.Join(parts[:3], " ")
		layouts := []string{
			"Mon 2006-01-02 15:04:05",
			"2006-01-02 15:04:05",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, dateStr); err == nil {
				timer.NextRun = t
				break
			}
		}
	}

	return timer
}

func (c *Collector) getServiceLogView(service string, lines int) (*types.ServiceLogViewResult, error) {
	result := &types.ServiceLogViewResult{
		Service:   service,
		Logs:      []types.ServiceLog{},
		Timestamp: time.Now(),
	}

	cmd := cmdexec.Command("journalctl", "-u", service, "-n", strconv.Itoa(lines), "-o", "short-iso", "--no-pager")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	logLines := strings.Split(string(output), "\n")
	for _, line := range logLines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "--") {
			continue
		}
		log := parseServiceLogLine(line)
		if log != nil {
			result.Logs = append(result.Logs, *log)
		}
	}

	result.Count = len(result.Logs)
	return result, nil
}

func parseServiceLogLine(line string) *types.ServiceLog {
	log := &types.ServiceLog{
		Level: "info",
	}

	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 3 {
		return nil
	}

	if t, err := time.Parse("2006-01-02T15:04:05-0700", parts[0]); err == nil {
		log.Time = t
	}

	if len(parts) >= 4 {
		log.Message = parts[3]
	} else {
		log.Message = strings.Join(parts[2:], " ")
	}

	// Determine level from message content
	lowerMsg := strings.ToLower(log.Message)
	switch {
	case strings.Contains(lowerMsg, "error") || strings.Contains(lowerMsg, "fail"):
		log.Level = "error"
	case strings.Contains(lowerMsg, "warn"):
		log.Level = "warning"
	case strings.Contains(lowerMsg, "debug"):
		log.Level = "debug"
	}

	return log
}

func (c *Collector) getDeploymentEvents(limit int) (*types.DeploymentEventsResult, error) {
	result := &types.DeploymentEventsResult{
		Events:    []types.DeploymentEvent{},
		Timestamp: time.Now(),
	}

	// Check apt/dpkg history
	historyFiles := []string{
		"/var/log/apt/history.log",
		"/var/log/dpkg.log",
	}

	for _, file := range historyFiles {
		// #nosec G304 -- reading from hardcoded list of known paths
		if data, err := os.ReadFile(file); err == nil {
			events := parsePackageHistory(string(data), limit)
			for _, e := range events {
				result.Events = append(result.Events, e)
				switch e.Action {
				case "install":
					result.Installs++
				case "update", "upgrade":
					result.Updates++
				case "remove":
					result.Removes++
				}
			}
		}
	}

	if len(result.Events) > limit {
		result.Events = result.Events[:limit]
	}

	result.Count = len(result.Events)
	return result, nil
}

func parsePackageHistory(content string, limit int) []types.DeploymentEvent {
	var events []types.DeploymentEvent

	lines := strings.Split(content, "\n")
	for i := len(lines) - 1; i >= 0 && len(events) < limit; i-- {
		line := lines[i]
		if strings.Contains(line, "install") || strings.Contains(line, "upgrade") || strings.Contains(line, "remove") {
			event := types.DeploymentEvent{
				Time: time.Now(),
			}

			if strings.Contains(line, "install") {
				event.Action = "install"
			} else if strings.Contains(line, "upgrade") {
				event.Action = "update"
			} else if strings.Contains(line, "remove") {
				event.Action = "remove"
			}

			// Extract package name
			re := regexp.MustCompile(`(\S+):(\S+)\s`)
			match := re.FindStringSubmatch(line)
			if len(match) >= 2 {
				event.Package = match[1]
				event.Version = match[2]
			}

			events = append(events, event)
		}
	}

	return events
}

func (c *Collector) getAuthFailureSummary(hours int) (*types.AuthFailureSummaryResult, error) {
	result := &types.AuthFailureSummaryResult{
		Failures:  []types.AuthFailure{},
		TopIPs:    []types.IPCount{},
		TopUsers:  []types.UserCount{},
		Timestamp: time.Now(),
	}

	since := fmt.Sprintf("%d hours ago", hours)
	ipCounts := make(map[string]int)
	userCounts := make(map[string]int)

	// Query journald for auth failures
	cmd := cmdexec.Command("journalctl", "-u", "sshd", "-u", "systemd-logind", "--since", since, "-g", "Failed|failure|invalid|refused", "--no-pager")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			lowerLine := strings.ToLower(line)
			if !strings.Contains(lowerLine, "fail") && !strings.Contains(lowerLine, "invalid") {
				continue
			}

			result.TotalCount++

			// Extract IP
			ipRe := regexp.MustCompile(`from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
			ipMatch := ipRe.FindStringSubmatch(line)
			if len(ipMatch) >= 2 {
				ipCounts[ipMatch[1]]++
			}

			// Extract user
			userRe := regexp.MustCompile(`(?:user|for)\s+(\S+)`)
			userMatch := userRe.FindStringSubmatch(line)
			if len(userMatch) >= 2 {
				user := userMatch[1]
				if user != "invalid" && user != "from" {
					userCounts[user]++
				}
			}
		}
	}

	// Also check auth.log if available
	if data, err := os.ReadFile("/var/log/auth.log"); err == nil {
		parseAuthLogFailures(string(data), hours, &ipCounts, &userCounts, result)
	}

	// Convert to sorted slices
	for ip, count := range ipCounts {
		result.TopIPs = append(result.TopIPs, types.IPCount{IP: ip, Count: count})
	}
	for user, count := range userCounts {
		result.TopUsers = append(result.TopUsers, types.UserCount{User: user, Count: count})
	}

	result.UniqueIPs = len(ipCounts)
	result.UniqueUser = len(userCounts)

	return result, nil
}

func parseAuthLogFailures(content string, hours int, ipCounts, userCounts *map[string]int, result *types.AuthFailureSummaryResult) {
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if !strings.Contains(lowerLine, "fail") && !strings.Contains(lowerLine, "invalid") {
			continue
		}

		// Parse timestamp
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		timeStr := strings.Join(parts[:3], " ")
		logTime, err := time.Parse("Jan 2 15:04:05", timeStr)
		if err != nil {
			continue
		}
		logTime = logTime.AddDate(time.Now().Year(), 0, 0)
		if logTime.Before(cutoff) {
			continue
		}

		result.TotalCount++

		// Extract IP
		ipRe := regexp.MustCompile(`from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
		ipMatch := ipRe.FindStringSubmatch(line)
		if len(ipMatch) >= 2 {
			(*ipCounts)[ipMatch[1]]++
		}

		// Extract user
		userRe := regexp.MustCompile(`(?:user|for)\s+(\S+)`)
		userMatch := userRe.FindStringSubmatch(line)
		if len(userMatch) >= 2 {
			user := userMatch[1]
			if user != "invalid" && user != "from" {
				(*userCounts)[user]++
			}
		}
	}
}

func (c *Collector) getSecurityBasics() (*types.SecurityBasicsResult, error) {
	result := &types.SecurityBasicsResult{
		Timestamp: time.Now(),
	}

	result.Firewall = getFirewallStatus()
	result.SELinux = getSELinuxStatus()
	result.AppArmor = getAppArmorStatus()
	result.Updates = getUpdateStatus()

	return result, nil
}

func getFirewallStatus() types.FirewallStatus {
	status := types.FirewallStatus{}

	// Check iptables
	cmd := cmdexec.Command("iptables", "-L", "-n")
	output, err := cmd.Output()
	if err == nil {
		status.Enabled = true
		status.Type = "iptables"
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ACCEPT") || strings.HasPrefix(line, "DROP") || strings.HasPrefix(line, "REJECT") {
				status.RuleCount++
			}
		}
	}

	// Check nftables
	cmd = cmdexec.Command("nft", "list", "ruleset")
	output, err = cmd.Output()
	if err == nil && len(output) > 0 {
		status.Enabled = true
		status.Type = "nftables"
	}

	// Check ufw
	cmd = cmdexec.Command("ufw", "status")
	output, err = cmd.Output()
	if err == nil {
		if strings.Contains(string(output), "Status: active") {
			status.Enabled = true
			status.Type = "ufw"
		}
	}

	// Check firewalld
	cmd = cmdexec.Command("firewall-cmd", "--state")
	output, err = cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "running" {
		status.Enabled = true
		status.Type = "firewalld"
	}

	return status
}

func getSELinuxStatus() types.SELinuxStatus {
	status := types.SELinuxStatus{}

	cmd := cmdexec.Command("getenforce")
	output, err := cmd.Output()
	if err == nil {
		mode := strings.TrimSpace(string(output))
		status.Mode = mode
		status.Enabled = mode != "Disabled"
	}

	// Get policy type
	if data, err := os.ReadFile("/etc/selinux/config"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "SELINUXTYPE=") {
				status.Policy = strings.TrimPrefix(line, "SELINUXTYPE=")
				break
			}
		}
	}

	return status
}

func getAppArmorStatus() types.AppArmorStatus {
	status := types.AppArmorStatus{}

	cmd := cmdexec.Command("aa-status")
	output, err := cmd.Output()
	if err == nil {
		status.Enabled = true
		for _, line := range strings.Split(string(output), "\n") {
			if strings.Contains(line, "profiles are loaded") {
				re := regexp.MustCompile(`(\d+)\s+profiles`)
				match := re.FindStringSubmatch(line)
				if len(match) >= 2 {
					status.Profiles, _ = strconv.Atoi(match[1])
				}
			}
			if strings.Contains(line, "enforce mode") {
				re := regexp.MustCompile(`(\d+)\s+profiles are in enforce`)
				match := re.FindStringSubmatch(line)
				if len(match) >= 2 {
					status.Enforce, _ = strconv.Atoi(match[1])
				}
			}
			if strings.Contains(line, "complain mode") {
				re := regexp.MustCompile(`(\d+)\s+profiles are in complain`)
				match := re.FindStringSubmatch(line)
				if len(match) >= 2 {
					status.Complain, _ = strconv.Atoi(match[1])
				}
			}
		}
	}

	return status
}

func getUpdateStatus() types.UpdateStatus {
	status := types.UpdateStatus{}

	// Check apt
	cmd := cmdexec.Command("apt", "list", "--upgradable")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "upgradable") {
				status.PendingUpdates++
				if strings.Contains(strings.ToLower(line), "security") {
					status.SecurityUpdates++
				}
			}
		}
	}

	// Check yum/dnf
	cmd = cmdexec.Command("yum", "check-update", "-q")
	output, _ = cmd.Output()
	if len(output) > 0 {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) != "" {
				status.PendingUpdates++
			}
		}
	}

	// Get last update time
	if info, err := os.Stat("/var/lib/apt/periodic/update-success-stamp"); err == nil {
		status.LastCheck = info.ModTime().Format(time.RFC3339)
	} else if info, err := os.Stat("/var/cache/yum"); err == nil {
		status.LastCheck = info.ModTime().Format(time.RFC3339)
	}

	return status
}

func (c *Collector) getSSHSecuritySummary() (*types.SSHSecuritySummaryResult, error) {
	result := &types.SSHSecuritySummaryResult{
		Timestamp: time.Now(),
	}

	// Check if SSH is installed
	if _, err := cmdexec.LookPath("sshd"); err == nil {
		result.Installed = true
	}

	// Check if running
	cmd := cmdexec.Command("systemctl", "is-active", "sshd")
	output, err := cmd.Output()
	if err == nil && strings.TrimSpace(string(output)) == "active" {
		result.Running = true
	}

	// Parse sshd_config
	settings := types.SSHSettings{}
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		parseSSHConfig(string(data), &settings)
	}

	result.Settings = settings

	// Generate recommendations
	if settings.PermitRootLogin == "yes" {
		result.Recommendations = append(result.Recommendations, "Disable root login via SSH")
	}
	if settings.PasswordAuth {
		result.Recommendations = append(result.Recommendations, "Consider disabling password authentication")
	}
	if settings.PermitEmptyPasswords {
		result.Recommendations = append(result.Recommendations, "Disable empty passwords")
	}

	return result, nil
}

func parseSSHConfig(content string, settings *types.SSHSettings) {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		key := strings.ToLower(parts[0])
		value := strings.ToLower(parts[1])

		switch key {
		case "permitrootlogin":
			settings.PermitRootLogin = parts[1]
		case "passwordauthentication":
			settings.PasswordAuth = value == "yes"
		case "pubkeyauthentication":
			settings.PubkeyAuth = value == "yes"
		case "permitemptypasswords":
			settings.PermitEmptyPasswords = value == "yes"
		case "x11forwarding":
			settings.X11Forwarding = value == "yes"
		case "maxauthtries":
			settings.MaxAuthTries, _ = strconv.Atoi(parts[1])
		case "logingracetime":
			settings.LoginGraceTime, _ = strconv.Atoi(parts[1])
		case "allowusers":
			settings.AllowUsers = strings.Join(parts[1:], " ")
		case "allowgroups":
			settings.AllowGroups = strings.Join(parts[1:], " ")
		}
	}
}

func (c *Collector) getAdminAccountSummary() (*types.AdminAccountSummaryResult, error) {
	result := &types.AdminAccountSummaryResult{
		Admins:    []types.AdminAccount{},
		Timestamp: time.Now(),
	}

	// Get users in sudo/wheel groups
	sudoGroups := []string{"sudo", "wheel", "admin", "root"}

	for _, group := range sudoGroups {
		cmd := cmdexec.Command("getent", "group", group)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		parts := strings.Split(string(output), ":")
		if len(parts) >= 4 {
			users := strings.Split(parts[3], ",")
			for _, user := range users {
				user = strings.TrimSpace(user)
				if user == "" {
					continue
				}
				account := getAdminAccountDetails(user)
				result.Admins = append(result.Admins, account)
			}
		}
	}

	// Also check /etc/passwd for UID 0
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.Split(line, ":")
			if len(parts) >= 4 && parts[2] == "0" {
				account := types.AdminAccount{
					User:   parts[0],
					UID:    0,
					Groups: []string{"root"},
				}
				if len(parts) >= 7 {
					account.Shell = parts[6]
				}
				result.Admins = append(result.Admins, account)
			}
		}
	}

	result.Count = len(result.Admins)
	return result, nil
}

func getAdminAccountDetails(username string) types.AdminAccount {
	account := types.AdminAccount{
		User: username,
	}

	// Get UID
	cmd := cmdexec.Command("id", "-u", username)
	output, err := cmd.Output()
	if err == nil {
		if uid, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			account.UID = uid
		}
	}

	// Get all groups
	cmd = cmdexec.Command("groups", username)
	output, err = cmd.Output()
	if err == nil {
		parts := strings.SplitN(string(output), ":", 2)
		if len(parts) >= 2 {
			account.Groups = strings.Fields(parts[1])
		}
	}

	// Get shell
	cmd = cmdexec.Command("getent", "passwd", username)
	output, err = cmd.Output()
	if err == nil {
		parts := strings.Split(string(output), ":")
		if len(parts) >= 7 {
			account.Shell = strings.TrimSpace(parts[6])
		}
	}

	// Check last login
	cmd = cmdexec.Command("lastlog", "-u", username)
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		if len(lines) >= 2 {
			if !strings.Contains(lines[1], "Never logged in") {
				account.LastLogin = strings.TrimSpace(lines[1])
			}
		}
	}

	// Check if account is locked
	cmd = cmdexec.Command("passwd", "-S", username)
	output, err = cmd.Output()
	if err == nil {
		if strings.Contains(string(output), " L ") || strings.Contains(string(output), " LK ") {
			account.Locked = true
		}
	}

	return account
}

func (c *Collector) getExposedServicesSummary() (*types.ExposedServicesSummaryResult, error) {
	result := &types.ExposedServicesSummaryResult{
		Services:  []types.ExposedService{},
		Timestamp: time.Now(),
	}

	// Use ss to get listening sockets
	cmd := cmdexec.Command("ss", "-tlnp")
	output, err := cmd.Output()
	if err != nil {
		cmd = cmdexec.Command("netstat", "-tlnp")
		output, err = cmd.Output()
	}

	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Proto") {
				continue
			}
			service := parseListeningService(line)
			if service != nil {
				result.Services = append(result.Services, *service)
				if service.External {
					result.External++
				} else {
					result.Internal++
				}
			}
		}
	}

	result.Count = len(result.Services)
	return result, nil
}

func parseListeningService(line string) *types.ExposedService {
	parts := strings.Fields(line)
	if len(parts) < 4 {
		return nil
	}

	service := &types.ExposedService{
		Protocol: "tcp",
	}

	// Parse local address
	var localAddr string
	for _, p := range parts {
		if strings.Contains(p, ":") && !strings.HasPrefix(p, "users:") {
			localAddr = p
			break
		}
	}

	if localAddr == "" {
		return nil
	}

	// Handle IPv4 and IPv6
	lastColon := strings.LastIndex(localAddr, ":")
	if lastColon > 0 {
		service.Address = localAddr[:lastColon]
		portStr := localAddr[lastColon+1:]
		if port, err := strconv.Atoi(portStr); err == nil {
			service.Port = port
		}
	}

	// Extract process name
	for _, p := range parts {
		if strings.HasPrefix(p, "users:") {
			re := regexp.MustCompile(`\("([^"]+)"`)
			match := re.FindStringSubmatch(p)
			if len(match) >= 2 {
				service.Process = match[1]
			}
			break
		}
	}

	// Check if external
	service.External = service.Address == "0.0.0.0" || service.Address == "::" || service.Address == "*"

	return service
}

func (c *Collector) getResourceLimits() (*types.ResourceLimitsResult, error) {
	result := &types.ResourceLimitsResult{
		Limits:    []types.ResourceLimit{},
		Timestamp: time.Now(),
	}

	// Get system-wide limits
	sysLimits := map[string]string{
		"open_files":    "/proc/sys/fs/file-max",
		"max_processes": "/proc/sys/kernel/pid_max",
		"max_threads":   "/proc/sys/kernel/threads-max",
		"max_map_count": "/proc/sys/vm/max_map_count",
		"somaxconn":     "/proc/sys/net/core/somaxconn",
	}

	for name, path := range sysLimits {
		// #nosec G304 -- reading from hardcoded map of known paths
		if data, err := os.ReadFile(path); err == nil {
			value := strings.TrimSpace(string(data))
			if v, err := strconv.ParseInt(value, 10, 64); err == nil {
				limit := types.ResourceLimit{
					Type: name,
					Hard: v,
					Soft: v,
				}
				result.Limits = append(result.Limits, limit)
			}
		}
	}

	// Get current file descriptor usage
	if data, err := os.ReadFile("/proc/sys/fs/file-nr"); err == nil {
		parts := strings.Fields(string(data))
		if len(parts) >= 3 {
			current, _ := strconv.ParseInt(parts[0], 10, 64)
			max, _ := strconv.ParseInt(parts[2], 10, 64)
			limit := types.ResourceLimit{
				Type:    "file_descriptors",
				Hard:    max,
				Soft:    max,
				Current: current,
			}
			result.Limits = append(result.Limits, limit)
		}
	}

	return result, nil
}

func (c *Collector) getRecentlyInstalledSoftware(days int) (*types.RecentlyInstalledSoftwareResult, error) {
	result := &types.RecentlyInstalledSoftwareResult{
		Packages:  []types.InstalledPackage{},
		Since:     time.Now().AddDate(0, 0, -days),
		Timestamp: time.Now(),
	}

	cutoff := time.Now().AddDate(0, 0, -days)

	// Check apt history
	if data, err := os.ReadFile("/var/log/apt/history.log"); err == nil {
		packages := parseAptHistory(string(data), cutoff)
		result.Packages = append(result.Packages, packages...)
	}

	// Check dpkg log
	if data, err := os.ReadFile("/var/log/dpkg.log"); err == nil {
		packages := parseDpkgLog(string(data), cutoff)
		result.Packages = append(result.Packages, packages...)
	}

	// Check rpm query for install times
	cmd := cmdexec.Command("rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}|%{INSTALLTIME}\n")
	output, err := cmd.Output()
	if err == nil {
		packages := parseRpmQuery(string(output), cutoff)
		result.Packages = append(result.Packages, packages...)
	}

	result.Count = len(result.Packages)
	return result, nil
}

func parseAptHistory(content string, cutoff time.Time) []types.InstalledPackage {
	var packages []types.InstalledPackage
	var currentTime time.Time

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Start-Date:") {
			dateStr := strings.TrimPrefix(line, "Start-Date:")
			dateStr = strings.TrimSpace(dateStr)
			if t, err := time.Parse("2006-01-02  15:04:05", dateStr); err == nil {
				currentTime = t
			}
		}
		if strings.HasPrefix(line, "Install:") {
			if currentTime.Before(cutoff) {
				continue
			}
			pkgLine := strings.TrimPrefix(line, "Install:")

			for _, pkg := range strings.Split(pkgLine, ",") {
				pkg = strings.TrimSpace(pkg)
				if pkg == "" {
					continue
				}
				re := regexp.MustCompile(`^([^:]+)(?::\S+)?\s+\(([^)]+)\)`)
				match := re.FindStringSubmatch(pkg)
				if len(match) >= 3 {
					p := types.InstalledPackage{
						Name:      match[1],
						Version:   match[2],
						Installed: currentTime,
						Manager:   "apt",
					}
					packages = append(packages, p)
				}
			}
		}
	}

	return packages
}

func parseDpkgLog(content string, cutoff time.Time) []types.InstalledPackage {
	var packages []types.InstalledPackage

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if !strings.Contains(line, " install ") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}

		dateStr := parts[0] + " " + parts[1]
		logTime, err := time.Parse("2006-01-02 15:04:05", dateStr)
		if err != nil || logTime.Before(cutoff) {
			continue
		}

		pkgParts := strings.Split(parts[3], ":")
		pkgName := pkgParts[0]

		var version string
		if len(parts) >= 5 {
			version = parts[4]
		}

		pkg := types.InstalledPackage{
			Name:      pkgName,
			Version:   version,
			Installed: logTime,
			Manager:   "dpkg",
		}
		packages = append(packages, pkg)
	}

	return packages
}

func parseRpmQuery(content string, cutoff time.Time) []types.InstalledPackage {
	var packages []types.InstalledPackage

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}

		installTime, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			continue
		}

		t := time.Unix(installTime, 0)
		if t.Before(cutoff) {
			continue
		}

		pkg := types.InstalledPackage{
			Name:      parts[0],
			Version:   parts[1],
			Installed: t,
			Manager:   "rpm",
		}
		packages = append(packages, pkg)
	}

	return packages
}

func (c *Collector) getFSHealthSummary() (*types.FSHealthSummaryResult, error) {
	result := &types.FSHealthSummaryResult{
		Filesystems: []types.FSHealth{},
		Timestamp:   time.Now(),
	}

	// Get filesystem usage
	cmd := cmdexec.Command("df", "-B1", "--output=source,fstype,size,used,avail,pcent,target")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 7 {
			continue
		}

		// Skip pseudo filesystems
		if strings.HasPrefix(parts[0], "/dev/loop") || parts[1] == "tmpfs" || parts[1] == "devtmpfs" {
			continue
		}

		size, _ := strconv.ParseInt(parts[2], 10, 64)
		used, _ := strconv.ParseInt(parts[3], 10, 64)
		avail, _ := strconv.ParseInt(parts[4], 10, 64)

		pctStr := strings.TrimSuffix(parts[5], "%")
		pct, _ := strconv.ParseFloat(pctStr, 64)

		fs := types.FSHealth{
			Device:    parts[0],
			Mount:     parts[6],
			Type:      parts[1],
			Size:      size,
			Used:      used,
			Available: avail,
			UsedPct:   pct,
		}

		// Determine health
		if pct >= 95 {
			fs.Status = "critical"
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s is %d%% full", fs.Mount, int(pct)))
		} else if pct >= 85 {
			fs.Status = "warning"
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s is %d%% full", fs.Mount, int(pct)))
		} else {
			fs.Status = "healthy"
		}

		// Check for read-only
		if data, err := os.ReadFile("/proc/mounts"); err == nil {
			for _, mountLine := range strings.Split(string(data), "\n") {
				if strings.Contains(mountLine, fs.Mount) && strings.Contains(mountLine, "ro,") {
					fs.ReadOnly = true
					fs.Status = "warning"
					result.Warnings = append(result.Warnings, fmt.Sprintf("%s is read-only", fs.Mount))
					break
				}
			}
		}

		// Check inode usage
		cmdInode := cmdexec.Command("df", "-i", fs.Mount)
		inodeOutput, err := cmdInode.Output()
		if err == nil {
			inodeLines := strings.Split(string(inodeOutput), "\n")
			if len(inodeLines) >= 2 {
				inodeParts := strings.Fields(inodeLines[1])
				if len(inodeParts) >= 5 {
					inodePctStr := strings.TrimSuffix(inodeParts[4], "%")
					if inodePct, err := strconv.ParseFloat(inodePctStr, 64); err == nil {
						fs.InodePct = inodePct
					}
				}
			}
		}

		result.Filesystems = append(result.Filesystems, fs)
	}

	return result, nil
}

func (c *Collector) getIncidentTriageSnapshot() (*types.IncidentTriageSnapshotResult, error) {
	result := &types.IncidentTriageSnapshotResult{
		Timestamp: time.Now(),
	}

	// Get OS info
	osCollector := osinfo.NewCollector()
	if osInfo, err := osCollector.GetOSInfo(); err == nil {
		result.System = osInfo
	}

	// Get recent reboots
	if reboots, err := c.getRecentReboots(5); err == nil {
		result.RecentReboots = reboots
	}

	// Get service failures
	if failures, err := c.getRecentServiceFailures(10); err == nil {
		result.ServiceFailures = failures
	}

	// Get kernel events
	if events, err := c.getRecentKernelEvents(20); err == nil {
		result.KernelEvents = events
	}

	// Get resource incidents
	if incidents, err := c.getRecentResourceIncidents(10); err == nil {
		result.ResourceIssues = incidents
	}

	// Get critical events
	if critical, err := c.getRecentCriticalEvents(10); err == nil {
		result.CriticalEvents = critical
	}

	// Get failed units
	if units, err := c.getFailedUnits(); err == nil {
		result.FailedUnits = units
	}

	return result, nil
}

func (c *Collector) getSecurityPostureSnapshot() (*types.SecurityPostureSnapshotResult, error) {
	result := &types.SecurityPostureSnapshotResult{
		Timestamp:       time.Now(),
		Recommendations: []string{},
	}

	score := 100

	// Get security basics
	if basics, err := c.getSecurityBasics(); err == nil {
		result.SecurityBasics = basics
		if !basics.Firewall.Enabled {
			score -= 20
			result.Recommendations = append(result.Recommendations, "Enable firewall protection")
		}
		if !basics.SELinux.Enabled && !basics.AppArmor.Enabled {
			score -= 15
			result.Recommendations = append(result.Recommendations, "Enable SELinux or AppArmor")
		}
		if basics.Updates.PendingUpdates > 0 {
			score -= 10
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("Install %d pending updates", basics.Updates.PendingUpdates))
		}
		if basics.Updates.SecurityUpdates > 0 {
			score -= 10
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("Install %d security updates urgently", basics.Updates.SecurityUpdates))
		}
	}

	// Get SSH security
	if ssh, err := c.getSSHSecuritySummary(); err == nil {
		result.SSHSecurity = ssh
		if ssh.Settings.PermitRootLogin == "yes" {
			score -= 15
		}
		if ssh.Settings.PasswordAuth {
			score -= 5
		}
		result.Recommendations = append(result.Recommendations, ssh.Recommendations...)
	}

	// Get admin accounts
	if admins, err := c.getAdminAccountSummary(); err == nil {
		result.AdminAccounts = admins
		if admins.Count > 5 {
			score -= 5
			result.Recommendations = append(result.Recommendations, "Review excessive admin accounts")
		}
	}

	// Get exposed services
	if exposed, err := c.getExposedServicesSummary(); err == nil {
		result.ExposedServices = exposed
		if exposed.External > 5 {
			score -= 10
			result.Recommendations = append(result.Recommendations, "Review publicly exposed services")
		}
	}

	// Get auth failures
	if auth, err := c.getAuthFailureSummary(24); err == nil {
		result.AuthFailures = auth
		if auth.TotalCount > 100 {
			score -= 10
			result.Recommendations = append(result.Recommendations, "Investigate high authentication failure rate")
		}
	}

	// Calculate overall score
	if score < 0 {
		score = 0
	}
	result.OverallScore = score

	// Determine risk level
	switch {
	case score >= 80:
		result.RiskLevel = "low"
	case score >= 60:
		result.RiskLevel = "medium"
	case score >= 40:
		result.RiskLevel = "high"
	default:
		result.RiskLevel = "critical"
	}

	return result, nil
}
