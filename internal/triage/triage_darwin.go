//go:build darwin
// +build darwin

package triage

import (
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
	cmd := cmdexec.Command("last", "reboot")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		count := 0
		for _, line := range lines {
			if strings.HasPrefix(line, "reboot") && count < limit {
				event := parseRebootLineDarwin(line)
				if event != nil {
					result.Reboots = append(result.Reboots, *event)
					count++
				}
			}
		}
	}

	// Also check system log for boot events
	cmd = cmdexec.Command("log", "show", "--predicate", "eventMessage contains 'BOOT_TIME'", "--style", "compact", "--last", "7d")
	output, err = cmd.Output()
	if err == nil && len(result.Reboots) == 0 {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			event := parseLogBootEvent(line)
			if event != nil && len(result.Reboots) < limit {
				result.Reboots = append(result.Reboots, *event)
			}
		}
	}

	result.Count = len(result.Reboots)
	return result, nil
}

func parseRebootLineDarwin(line string) *types.RebootEvent {
	event := &types.RebootEvent{
		Type:   "reboot",
		Reason: "system boot",
	}

	// Extract time from end of line
	re := regexp.MustCompile(`([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2})`)
	match := re.FindStringSubmatch(line)
	if len(match) >= 2 {
		year := time.Now().Year()
		if t, err := time.Parse("Mon Jan 2 15:04", match[1]); err == nil {
			event.Time = t.AddDate(year, 0, 0)
		}
	}

	return event
}

func parseLogBootEvent(line string) *types.RebootEvent {
	event := &types.RebootEvent{
		Type:   "reboot",
		Reason: "system boot",
	}

	// Parse timestamp from log line
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		dateStr := parts[0] + " " + parts[1]
		if t, err := time.Parse("2006-01-02 15:04:05", dateStr); err == nil {
			event.Time = t
		}
	}

	return event
}

func (c *Collector) getRecentServiceFailures(limit int) (*types.RecentServiceFailuresResult, error) {
	result := &types.RecentServiceFailuresResult{
		Failures:  []types.ServiceFailure{},
		Timestamp: time.Now(),
	}

	// Check launchd for failed services
	cmd := cmdexec.Command("launchctl", "list")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				// First column is PID (- if not running), second is exit status, third is label
				exitStatus := parts[1]
				if exitStatus != "0" && exitStatus != "-" {
					exitCode, _ := strconv.Atoi(exitStatus)
					if exitCode != 0 && len(result.Failures) < limit {
						failure := types.ServiceFailure{
							Service:  parts[2],
							Status:   "failed",
							ExitCode: exitCode,
							Time:     time.Now(),
						}
						result.Failures = append(result.Failures, failure)
					}
				}
			}
		}
	}

	// Check system log for service failures
	cmd = cmdexec.Command("log", "show", "--predicate", "eventMessage contains 'failed' AND subsystem == 'com.apple.launchd'", "--style", "compact", "--last", "24h")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || len(result.Failures) >= limit {
				continue
			}
			if strings.Contains(line, "Service exited") || strings.Contains(line, "failed") {
				failure := parseServiceFailureDarwin(line)
				if failure != nil {
					result.Failures = append(result.Failures, *failure)
				}
			}
		}
	}

	result.Count = len(result.Failures)
	return result, nil
}

func parseServiceFailureDarwin(line string) *types.ServiceFailure {
	failure := &types.ServiceFailure{
		Status: "failed",
		Time:   time.Now(),
	}

	// Extract service name
	re := regexp.MustCompile(`Service\s+(\S+)`)
	match := re.FindStringSubmatch(line)
	if len(match) >= 2 {
		failure.Service = match[1]
	}

	// Extract error message
	failure.Message = truncateString(line, 200)

	return failure
}

func (c *Collector) getRecentKernelEvents(limit int) (*types.RecentKernelEventsResult, error) {
	result := &types.RecentKernelEventsResult{
		Events:    []types.KernelEvent{},
		Timestamp: time.Now(),
	}

	// Get kernel messages from log
	cmd := cmdexec.Command("log", "show", "--predicate", "sender == 'kernel' AND (eventMessage contains 'error' OR eventMessage contains 'warning' OR eventMessage contains 'panic')", "--style", "compact", "--last", "7d")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			event := parseKernelEventDarwin(line)
			if event != nil && len(result.Events) < limit {
				result.Events = append(result.Events, *event)
				// Count errors and warnings
				switch event.Level {
				case "error", "critical":
					result.Errors++
				case "warning":
					result.Warnings++
				}
			}
		}
	}

	// Fallback to dmesg if available
	if len(result.Events) == 0 {
		cmd = cmdexec.Command("dmesg")
		output, err = cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for i := len(lines) - 1; i >= 0 && len(result.Events) < limit; i-- {
				line := lines[i]
				if strings.Contains(strings.ToLower(line), "error") || strings.Contains(strings.ToLower(line), "warning") {
					event := &types.KernelEvent{
						Message:  truncateString(line, 300),
						Facility: "kernel",
						Level:    "warning",
						Time:     time.Now(),
					}
					result.Events = append(result.Events, *event)
					result.Warnings++
				}
			}
		}
	}

	result.Count = len(result.Events)
	return result, nil
}

func parseKernelEventDarwin(line string) *types.KernelEvent {
	event := &types.KernelEvent{
		Facility: "kernel",
	}

	// Parse timestamp
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		dateStr := parts[0] + " " + parts[1]
		if t, err := time.Parse("2006-01-02 15:04:05", dateStr); err == nil {
			event.Time = t
		}
	}

	// Determine level
	lowerLine := strings.ToLower(line)
	switch {
	case strings.Contains(lowerLine, "panic"):
		event.Level = "critical"
	case strings.Contains(lowerLine, "error"):
		event.Level = "error"
	case strings.Contains(lowerLine, "warning"):
		event.Level = "warning"
	default:
		event.Level = "info"
	}

	// Extract message (everything after timestamp and sender)
	if idx := strings.Index(line, "kernel:"); idx > 0 {
		event.Message = truncateString(strings.TrimSpace(line[idx+7:]), 300)
	} else if len(parts) >= 4 {
		event.Message = truncateString(strings.Join(parts[3:], " "), 300)
	}

	return event
}

func (c *Collector) getRecentResourceIncidents(limit int) (*types.RecentResourceIncidentsResult, error) {
	result := &types.RecentResourceIncidentsResult{
		Incidents: []types.ResourceIncident{},
		Timestamp: time.Now(),
	}

	// Check for memory pressure events
	cmd := cmdexec.Command("log", "show", "--predicate", "eventMessage contains 'memory pressure' OR eventMessage contains 'jetsam' OR eventMessage contains 'killed'", "--style", "compact", "--last", "24h")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || len(result.Incidents) >= limit {
				continue
			}
			incident := parseResourceIncidentDarwin(line)
			if incident != nil {
				result.Incidents = append(result.Incidents, *incident)
				if incident.Type == "oom" {
					result.OOMKills++
				}
			}
		}
	}

	// Check for disk issues
	cmd = cmdexec.Command("log", "show", "--predicate", "eventMessage contains 'disk' AND (eventMessage contains 'error' OR eventMessage contains 'I/O')", "--style", "compact", "--last", "24h")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || len(result.Incidents) >= limit {
				continue
			}
			incident := &types.ResourceIncident{
				Type:    "io_error",
				Details: truncateString(line, 200),
				Time:    time.Now(),
			}
			result.Incidents = append(result.Incidents, *incident)
		}
	}

	result.Count = len(result.Incidents)
	return result, nil
}

func parseResourceIncidentDarwin(line string) *types.ResourceIncident {
	lowerLine := strings.ToLower(line)
	incident := &types.ResourceIncident{
		Details: truncateString(line, 200),
		Time:    time.Now(),
	}

	switch {
	case strings.Contains(lowerLine, "memory pressure") || strings.Contains(lowerLine, "jetsam"):
		incident.Type = "memory_pressure"
	case strings.Contains(lowerLine, "killed"):
		incident.Type = "oom"
		// Try to extract process name
		re := regexp.MustCompile(`killed\s+(\S+)`)
		match := re.FindStringSubmatch(line)
		if len(match) >= 2 {
			incident.Process = match[1]
		}
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
	configDirs := []string{"/etc", "/Library/Preferences", "/Library/LaunchDaemons", "/Library/LaunchAgents"}
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

	// Query unified log for critical events
	cmd := cmdexec.Command("log", "show", "--predicate", "messageType == 16 OR messageType == 17", "--style", "compact", "--last", "7d")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			event := parseCriticalEventDarwin(line)
			if event != nil && len(result.Events) < limit {
				result.Events = append(result.Events, *event)
			}
		}
	}

	// Also check for panics
	cmd = cmdexec.Command("log", "show", "--predicate", "eventMessage contains 'panic' OR eventMessage contains 'CRITICAL'", "--style", "compact", "--last", "30d")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || len(result.Events) >= limit {
				continue
			}
			event := parseCriticalEventDarwin(line)
			if event != nil {
				event.Priority = "critical"
				result.Events = append(result.Events, *event)
			}
		}
	}

	result.Count = len(result.Events)
	return result, nil
}

func parseCriticalEventDarwin(line string) *types.CriticalEvent {
	event := &types.CriticalEvent{
		Priority: "critical",
	}

	// Parse timestamp
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		dateStr := parts[0] + " " + parts[1]
		if t, err := time.Parse("2006-01-02 15:04:05", dateStr); err == nil {
			event.Time = t
		}
	}

	// Extract source (process)
	if len(parts) >= 4 {
		event.Source = parts[3]
	}

	event.Message = truncateString(line, 300)

	return event
}

func (c *Collector) getFailedUnits() (*types.FailedUnitsResult, error) {
	result := &types.FailedUnitsResult{
		Units:     []types.FailedUnit{},
		Timestamp: time.Now(),
	}

	// Check launchd for failed jobs
	cmd := cmdexec.Command("launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "PID") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			exitStatus := parts[1]
			if exitStatus != "0" && exitStatus != "-" {
				exitCode, _ := strconv.Atoi(exitStatus)
				if exitCode != 0 {
					unit := types.FailedUnit{
						Name:        parts[2],
						ActiveState: "failed",
						Result:      "exit-code",
					}
					result.Units = append(result.Units, unit)
				}
			}
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

	// Get launchd scheduled jobs
	launchDirs := []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		"/System/Library/LaunchDaemons",
		"/System/Library/LaunchAgents",
	}

	for _, dir := range launchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}

			timer := types.TimerJob{
				Name: strings.TrimSuffix(entry.Name(), ".plist"),
			}

			// Try to read plist for schedule info
			plistPath := filepath.Join(dir, entry.Name())
			if data, err := os.ReadFile(plistPath); err == nil {
				content := string(data)
				if strings.Contains(content, "StartInterval") || strings.Contains(content, "StartCalendarInterval") {
					timer.Schedule = "scheduled"
				}
			}

			result.Timers = append(result.Timers, timer)
		}
	}

	// Check cron if available
	homeDir, _ := os.UserHomeDir()
	cronFiles := []string{"/etc/crontab", filepath.Join(homeDir, ".crontab")}
	for _, file := range cronFiles {
		if data, err := os.ReadFile(file); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 6 {
					timer := types.TimerJob{
						Name:     parts[5],
						Schedule: strings.Join(parts[:5], " "),
					}
					result.Timers = append(result.Timers, timer)
				}
			}
		}
	}

	result.Count = len(result.Timers)
	return result, nil
}

func (c *Collector) getServiceLogView(service string, lines int) (*types.ServiceLogViewResult, error) {
	result := &types.ServiceLogViewResult{
		Service:   service,
		Logs:      []types.ServiceLog{},
		Timestamp: time.Now(),
	}

	// Use unified log to get service logs
	predicate := "subsystem == '" + service + "' OR sender == '" + service + "' OR processImagePath contains '" + service + "'"
	cmd := cmdexec.Command("log", "show", "--predicate", predicate, "--style", "compact", "--last", "1h")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	logLines := strings.Split(string(output), "\n")
	count := 0
	for i := len(logLines) - 1; i >= 0 && count < lines; i-- {
		line := logLines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		log := parseServiceLogDarwin(line)
		if log != nil {
			result.Logs = append(result.Logs, *log)
			count++
		}
	}

	result.Count = len(result.Logs)
	return result, nil
}

func parseServiceLogDarwin(line string) *types.ServiceLog {
	log := &types.ServiceLog{
		Level: "info",
	}

	parts := strings.Fields(line)
	if len(parts) < 3 {
		return nil
	}

	// Parse timestamp
	dateStr := parts[0] + " " + parts[1]
	if t, err := time.Parse("2006-01-02 15:04:05", dateStr); err == nil {
		log.Time = t
	}

	// Message is the rest
	if len(parts) >= 4 {
		log.Message = strings.Join(parts[3:], " ")
	}

	// Determine level
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

	// Check for Homebrew installations
	cmd := cmdexec.Command("brew", "list", "--versions")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) >= 2 && len(result.Events) < limit {
				event := types.DeploymentEvent{
					Package: parts[0],
					Version: parts[len(parts)-1],
					Action:  "install",
					Time:    time.Now(),
				}
				result.Events = append(result.Events, event)
				result.Installs++
			}
		}
	}

	// Check installer history
	cmd = cmdexec.Command("pkgutil", "--pkgs")
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			pkg := strings.TrimSpace(line)
			if pkg == "" || len(result.Events) >= limit {
				continue
			}
			// Get install time
			cmd := cmdexec.Command("pkgutil", "--pkg-info", pkg)
			infoOutput, err := cmd.Output()
			if err == nil {
				event := types.DeploymentEvent{
					Package: pkg,
					Action:  "install",
				}
				for _, infoLine := range strings.Split(string(infoOutput), "\n") {
					if strings.HasPrefix(infoLine, "version:") {
						event.Version = strings.TrimSpace(strings.TrimPrefix(infoLine, "version:"))
					}
					if strings.HasPrefix(infoLine, "install-time:") {
						ts := strings.TrimSpace(strings.TrimPrefix(infoLine, "install-time:"))
						if unix, err := strconv.ParseInt(ts, 10, 64); err == nil {
							event.Time = time.Unix(unix, 0)
						}
					}
				}
				result.Events = append(result.Events, event)
				result.Installs++
			}
		}
	}

	result.Count = len(result.Events)
	return result, nil
}

func (c *Collector) getAuthFailureSummary(hours int) (*types.AuthFailureSummaryResult, error) {
	result := &types.AuthFailureSummaryResult{
		Failures:  []types.AuthFailure{},
		TopIPs:    []types.IPCount{},
		TopUsers:  []types.UserCount{},
		Timestamp: time.Now(),
	}

	// Query unified log for auth failures
	predicate := "eventMessage contains 'authentication failure' OR eventMessage contains 'Failed password' OR eventMessage contains 'Invalid user'"
	cmd := cmdexec.Command("log", "show", "--predicate", predicate, "--style", "compact", "--last", strconv.Itoa(hours)+"h")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	ipCounts := make(map[string]int)
	userCounts := make(map[string]int)

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
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

	// Convert to sorted slices
	for ip, count := range ipCounts {
		result.TopIPs = append(result.TopIPs, types.IPCount{IP: ip, Count: count})
	}
	result.UniqueIPs = len(ipCounts)

	for user, count := range userCounts {
		result.TopUsers = append(result.TopUsers, types.UserCount{User: user, Count: count})
	}
	result.UniqueUser = len(userCounts)

	return result, nil
}

func (c *Collector) getSecurityBasics() (*types.SecurityBasicsResult, error) {
	result := &types.SecurityBasicsResult{
		Timestamp: time.Now(),
	}

	// Check firewall status
	result.Firewall = getFirewallStatusDarwin()

	// Check Gatekeeper
	result.Gatekeeper = getGatekeeperStatus()

	// Check for updates
	result.Updates = getUpdateStatusDarwin()

	return result, nil
}

func getFirewallStatusDarwin() types.FirewallStatus {
	status := types.FirewallStatus{}

	// Check Application Firewall
	cmd := cmdexec.Command("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate")
	output, err := cmd.Output()
	if err == nil {
		state := strings.TrimSpace(string(output))
		status.Enabled = state == "1" || state == "2"
		status.Type = "application_firewall"
	}

	// Check pf firewall
	cmd = cmdexec.Command("pfctl", "-s", "info")
	output, err = cmd.Output()
	if err == nil && strings.Contains(string(output), "Status: Enabled") {
		status.Enabled = true
		status.Type = "pf"
	}

	return status
}

func getGatekeeperStatus() types.GatekeeperStatus {
	status := types.GatekeeperStatus{}

	cmd := cmdexec.Command("spctl", "--status")
	output, err := cmd.Output()
	if err == nil {
		outputStr := strings.TrimSpace(string(output))
		status.Enabled = strings.Contains(outputStr, "enabled")
		if strings.Contains(outputStr, "developer id") {
			status.Assessment = "developer_id"
		} else if strings.Contains(outputStr, "app store") {
			status.Assessment = "app_store"
		} else {
			status.Assessment = "anywhere"
		}
	}

	return status
}

func getUpdateStatusDarwin() types.UpdateStatus {
	status := types.UpdateStatus{}

	// Check software update
	cmd := cmdexec.Command("softwareupdate", "-l")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, "* ") {
				status.PendingUpdates++
				if strings.Contains(strings.ToLower(line), "security") {
					status.SecurityUpdates++
				}
			}
		}
	}

	return status
}

func (c *Collector) getSSHSecuritySummary() (*types.SSHSecuritySummaryResult, error) {
	result := &types.SSHSecuritySummaryResult{
		Timestamp: time.Now(),
	}

	// Parse sshd_config
	settings := types.SSHSettings{}
	if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
		parseSSHConfigDarwin(string(data), &settings)
		result.Installed = true
	}

	result.Settings = settings

	// Determine warnings and recommendations
	if settings.PermitRootLogin == "yes" {
		result.Warnings = append(result.Warnings, "Root login is enabled")
		result.Recommendations = append(result.Recommendations, "Disable root login via SSH")
	}
	if settings.PasswordAuth {
		result.Recommendations = append(result.Recommendations, "Consider disabling password authentication")
	}

	return result, nil
}

func parseSSHConfigDarwin(content string, settings *types.SSHSettings) {
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
		value := parts[1]

		switch key {
		case "port":
			if port, err := strconv.Atoi(value); err == nil {
				settings.MaxAuthTries = port // Store port in a numeric field temporarily
			}
		case "permitrootlogin":
			settings.PermitRootLogin = value
		case "passwordauthentication":
			settings.PasswordAuth = strings.ToLower(value) == "yes"
		case "pubkeyauthentication":
			settings.PubkeyAuth = strings.ToLower(value) == "yes"
		case "permitemptypasswords":
			settings.PermitEmptyPasswords = strings.ToLower(value) == "yes"
		case "x11forwarding":
			settings.X11Forwarding = strings.ToLower(value) == "yes"
		case "maxauthtries":
			if tries, err := strconv.Atoi(value); err == nil {
				settings.MaxAuthTries = tries
			}
		}
	}
}

func (c *Collector) getAdminAccountSummary() (*types.AdminAccountSummaryResult, error) {
	result := &types.AdminAccountSummaryResult{
		Admins:    []types.AdminAccount{},
		Timestamp: time.Now(),
	}

	// Get admin users
	cmd := cmdexec.Command("dscl", ".", "-read", "/Groups/admin", "GroupMembership")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	// Parse: GroupMembership: user1 user2 user3
	parts := strings.SplitN(string(output), ":", 2)
	if len(parts) >= 2 {
		users := strings.Fields(parts[1])
		for _, user := range users {
			account := getAdminAccountDetailsDarwin(user)
			result.Admins = append(result.Admins, account)
		}
	}

	result.Count = len(result.Admins)
	return result, nil
}

func getAdminAccountDetailsDarwin(username string) types.AdminAccount {
	account := types.AdminAccount{
		User:   username,
		Groups: []string{"admin"},
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
		account.Groups = strings.Fields(string(output))
	}

	// Get shell
	cmd = cmdexec.Command("dscl", ".", "-read", "/Users/"+username, "UserShell")
	output, err = cmd.Output()
	if err == nil {
		parts := strings.SplitN(string(output), ":", 2)
		if len(parts) >= 2 {
			account.Shell = strings.TrimSpace(parts[1])
		}
	}

	return account
}

func (c *Collector) getExposedServicesSummary() (*types.ExposedServicesSummaryResult, error) {
	result := &types.ExposedServicesSummaryResult{
		Services:  []types.ExposedService{},
		Timestamp: time.Now(),
	}

	// Use lsof to get listening sockets
	cmd := cmdexec.Command("lsof", "-i", "-P", "-n")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	seen := make(map[string]bool)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if !strings.Contains(line, "LISTEN") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 9 {
			continue
		}

		// Parse address (format: *:port or host:port)
		addrPart := parts[8]
		addrParts := strings.Split(addrPart, ":")
		if len(addrParts) < 2 {
			continue
		}

		port, err := strconv.Atoi(addrParts[len(addrParts)-1])
		if err != nil {
			continue
		}

		key := parts[0] + ":" + strconv.Itoa(port)
		if seen[key] {
			continue
		}
		seen[key] = true

		service := types.ExposedService{
			Protocol: "tcp",
			Port:     port,
			Process:  parts[0],
			Address:  addrParts[0],
			External: addrParts[0] == "*" || addrParts[0] == "0.0.0.0",
		}

		result.Services = append(result.Services, service)
		if service.External {
			result.External++
		} else {
			result.Internal++
		}
	}

	result.Count = len(result.Services)

	return result, nil
}

func (c *Collector) getResourceLimits() (*types.ResourceLimitsResult, error) {
	result := &types.ResourceLimitsResult{
		Limits:    []types.ResourceLimit{},
		Timestamp: time.Now(),
	}

	// Get system limits via sysctl
	sysctlKeys := map[string]string{
		"kern.maxfiles":        "max_files",
		"kern.maxfilesperproc": "max_files_per_proc",
		"kern.maxproc":         "max_processes",
		"kern.maxprocperuid":   "max_proc_per_user",
	}

	for key, limitType := range sysctlKeys {
		cmd := cmdexec.Command("sysctl", "-n", key)
		output, err := cmd.Output()
		if err == nil {
			if val, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
				limit := types.ResourceLimit{
					Type: limitType,
					Hard: val,
					Soft: val,
					Unit: "count",
				}
				result.Limits = append(result.Limits, limit)
			}
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

	// Check pkgutil for recent installations
	cmd := cmdexec.Command("pkgutil", "--pkgs")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			pkg := strings.TrimSpace(line)
			if pkg == "" {
				continue
			}
			cmd := cmdexec.Command("pkgutil", "--pkg-info", pkg)
			infoOutput, err := cmd.Output()
			if err == nil {
				var installTime time.Time
				var version string
				for _, infoLine := range strings.Split(string(infoOutput), "\n") {
					if strings.HasPrefix(infoLine, "version:") {
						version = strings.TrimSpace(strings.TrimPrefix(infoLine, "version:"))
					}
					if strings.HasPrefix(infoLine, "install-time:") {
						ts := strings.TrimSpace(strings.TrimPrefix(infoLine, "install-time:"))
						if unix, err := strconv.ParseInt(ts, 10, 64); err == nil {
							installTime = time.Unix(unix, 0)
						}
					}
				}
				if installTime.After(cutoff) {
					p := types.InstalledPackage{
						Name:      pkg,
						Version:   version,
						Installed: installTime,
						Manager:   "pkgutil",
					}
					result.Packages = append(result.Packages, p)
				}
			}
		}
	}

	result.Count = len(result.Packages)
	return result, nil
}

func (c *Collector) getFSHealthSummary() (*types.FSHealthSummaryResult, error) {
	result := &types.FSHealthSummaryResult{
		Filesystems: []types.FSHealth{},
		Timestamp:   time.Now(),
	}

	// Get filesystem usage
	cmd := cmdexec.Command("df", "-k")
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
		if len(parts) < 6 {
			continue
		}

		// Skip pseudo filesystems
		if !strings.HasPrefix(parts[0], "/dev/") {
			continue
		}

		size, _ := strconv.ParseInt(parts[1], 10, 64)
		used, _ := strconv.ParseInt(parts[2], 10, 64)
		available, _ := strconv.ParseInt(parts[3], 10, 64)
		// Convert from 1K blocks to bytes
		size *= 1024
		used *= 1024
		available *= 1024

		var usedPct float64
		if size > 0 {
			usedPct = float64(used) / float64(size) * 100
		}

		fs := types.FSHealth{
			Device:    parts[0],
			Mount:     parts[5],
			Type:      "apfs", // macOS typically uses APFS
			Size:      size,
			Used:      used,
			Available: available,
			UsedPct:   usedPct,
		}

		// Determine health status
		if usedPct >= 95 {
			fs.Status = "critical"
			result.Warnings = append(result.Warnings, fs.Mount+" is critically full")
		} else if usedPct >= 85 {
			fs.Status = "warning"
			result.Warnings = append(result.Warnings, fs.Mount+" is getting full")
		} else {
			fs.Status = "healthy"
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
		if !basics.Gatekeeper.Enabled {
			score -= 15
			result.Recommendations = append(result.Recommendations, "Enable Gatekeeper")
		}
		if basics.Updates.PendingUpdates > 0 {
			score -= 10
			result.Recommendations = append(result.Recommendations, "Install pending updates: "+strconv.Itoa(basics.Updates.PendingUpdates))
		}
	}

	// Get SSH security
	if ssh, err := c.getSSHSecuritySummary(); err == nil {
		result.SSHSecurity = ssh
		if ssh.Settings.PermitRootLogin == "yes" {
			score -= 15
		}
		result.Recommendations = append(result.Recommendations, ssh.Recommendations...)
	}

	// Get admin accounts
	if admins, err := c.getAdminAccountSummary(); err == nil {
		result.AdminAccounts = admins
		if admins.Count > 3 {
			score -= 5
			result.Recommendations = append(result.Recommendations, "Review admin account list")
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
		if auth.TotalCount > 50 {
			score -= 10
			result.Recommendations = append(result.Recommendations, "Investigate authentication failures")
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

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
