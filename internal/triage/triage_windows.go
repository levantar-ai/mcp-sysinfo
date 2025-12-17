//go:build windows
// +build windows

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

	// Query Windows Event Log for system startup events
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='System'; ID=6005,6006,6008,6009,1074} -MaxEvents %d 2>$null | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.Id + '|' + $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)) }`, limit*2)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 3)
			if len(parts) >= 2 {
				event := types.RebootEvent{
					Type: "reboot",
				}
				if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
					event.Time = t
				}
				eventID := parts[1]
				switch eventID {
				case "6005":
					event.Reason = "Event Log Service started (boot)"
				case "6006":
					event.Reason = "Event Log Service stopped (shutdown)"
					event.Type = "shutdown"
				case "6008":
					event.Reason = "Unexpected shutdown"
					event.Type = "crash"
				case "6009":
					event.Reason = "Boot information"
				case "1074":
					event.Reason = "User-initiated restart/shutdown"
				}
				if len(result.Reboots) < limit {
					result.Reboots = append(result.Reboots, event)
				}
			}
		}
	}

	result.Count = len(result.Reboots)
	return result, nil
}

func (c *Collector) getRecentServiceFailures(limit int) (*types.RecentServiceFailuresResult, error) {
	result := &types.RecentServiceFailuresResult{
		Failures:  []types.ServiceFailure{},
		Timestamp: time.Now(),
	}

	// Query for service failure events
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='System'; ID=7031,7034,7000,7001,7009,7011,7023,7024} -MaxEvents %d 2>$null | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.Id + '|' + $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length)) }`, limit*2)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		serviceMap := make(map[string]*types.ServiceFailure)
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 3)
			if len(parts) < 3 {
				continue
			}

			// Extract service name from message
			serviceName := extractServiceName(parts[2])
			if serviceName == "" {
				continue
			}

			if existing, ok := serviceMap[serviceName]; ok {
				existing.Restarts++
			} else {
				sf := &types.ServiceFailure{
					Service:  serviceName,
					Status:   "failed",
					Restarts: 1,
					Message:  truncateString(parts[2], 200),
				}
				if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
					sf.Time = t
				}
				serviceMap[serviceName] = sf
			}
		}

		for _, sf := range serviceMap {
			if len(result.Failures) < limit {
				result.Failures = append(result.Failures, *sf)
			}
		}
	}

	// Also check for stopped services that should be running
	psScript = `Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | Select-Object -Property Name,Status,StartType | ForEach-Object { $_.Name + '|' + $_.Status + '|' + $_.StartType }`
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) >= 2 && len(result.Failures) < limit {
				// Check if we already have this service
				found := false
				for _, f := range result.Failures {
					if f.Service == parts[0] {
						found = true
						break
					}
				}
				if !found {
					result.Failures = append(result.Failures, types.ServiceFailure{
						Service: parts[0],
						Status:  parts[1],
						Time:    time.Now(),
					})
				}
			}
		}
	}

	result.Count = len(result.Failures)
	return result, nil
}

func extractServiceName(message string) string {
	// Try common patterns
	patterns := []string{
		`The (.+?) service`,
		`service (.+?) `,
		`'(.+?)' service`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		match := re.FindStringSubmatch(message)
		if len(match) >= 2 {
			return match[1]
		}
	}
	return ""
}

func (c *Collector) getRecentKernelEvents(limit int) (*types.RecentKernelEventsResult, error) {
	result := &types.RecentKernelEventsResult{
		Events:    []types.KernelEvent{},
		Timestamp: time.Now(),
	}

	// Query System log for kernel/driver events
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3} -MaxEvents %d 2>$null | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.LevelDisplayName + '|' + $_.ProviderName + '|' + $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }`, limit)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 4)
			if len(parts) < 4 {
				continue
			}

			event := types.KernelEvent{
				Facility: parts[2],
				Message:  truncateString(parts[3], 300),
			}

			if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
				event.Time = t
			}

			// Map Windows level to severity
			switch strings.ToLower(parts[1]) {
			case "critical":
				event.Level = "critical"
				result.Errors++
			case "error":
				event.Level = "error"
				result.Errors++
			case "warning":
				event.Level = "warning"
				result.Warnings++
			default:
				event.Level = "info"
			}

			result.Events = append(result.Events, event)
		}
	}

	result.Count = len(result.Events)
	return result, nil
}

func (c *Collector) getRecentResourceIncidents(limit int) (*types.RecentResourceIncidentsResult, error) {
	result := &types.RecentResourceIncidentsResult{
		Incidents: []types.ResourceIncident{},
		Timestamp: time.Now(),
	}

	// Query for resource-related events
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='System'; ID=2004,2013,2019,2020,2021,51,55,129,153} -MaxEvents %d 2>$null | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.Id + '|' + $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length)) }`, limit)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 3)
			if len(parts) < 3 {
				continue
			}

			incident := types.ResourceIncident{
				Details: truncateString(parts[2], 200),
			}

			if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
				incident.Time = t
			}

			eventID := parts[1]
			switch eventID {
			case "2004":
				incident.Type = "memory_pressure"
			case "2013":
				incident.Type = "oom"
				result.OOMKills++
			case "2019", "2020", "2021":
				incident.Type = "oom"
				result.OOMKills++
			case "51", "55":
				incident.Type = "io_error"
			case "129":
				incident.Type = "io_throttle"
				result.Throttles++
			case "153":
				incident.Type = "io_error"
			}

			result.Incidents = append(result.Incidents, incident)
		}
	}

	result.Count = len(result.Incidents)
	return result, nil
}

func (c *Collector) getRecentConfigChanges(limit int) (*types.RecentConfigChangesResult, error) {
	result := &types.RecentConfigChangesResult{
		Changes:   []types.ConfigChange{},
		Timestamp: time.Now(),
	}

	// Check for recently modified config files in common locations
	configDirs := []string{
		os.Getenv("WINDIR") + "\\System32\\drivers\\etc",
		os.Getenv("ProgramData"),
	}
	cutoff := time.Now().Add(-7 * 24 * time.Hour)

	for _, dir := range configDirs {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if (ext == ".ini" || ext == ".conf" || ext == ".config" || ext == ".xml") && info.ModTime().After(cutoff) && len(result.Changes) < limit {
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

	// Check Security event log for policy changes
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4719,4739,4946,4947,4948,4950} -MaxEvents %d 2>$null | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.Id + '|' + $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)) }`, limit)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || len(result.Changes) >= limit {
				continue
			}
			parts := strings.SplitN(line, "|", 3)
			if len(parts) >= 2 {
				change := types.ConfigChange{
					Type: "config_change",
				}
				if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
					change.Time = t
				}
				if len(parts) >= 3 {
					change.Path = parts[2]
				}
				result.Changes = append(result.Changes, change)
			}
		}
	}

	result.Count = len(result.Changes)
	return result, nil
}

func (c *Collector) getRecentCriticalEvents(limit int) (*types.RecentCriticalEventsResult, error) {
	result := &types.RecentCriticalEventsResult{
		Events:    []types.CriticalEvent{},
		Timestamp: time.Now(),
	}

	// Query for critical events across all major logs
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='System','Application','Security'; Level=1} -MaxEvents %d 2>$null | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.LogName + '|' + $_.ProviderName + '|' + $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length)) }`, limit)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 4)
			if len(parts) < 4 {
				continue
			}

			event := types.CriticalEvent{
				Source:   parts[2],
				Priority: "critical",
				Message:  truncateString(parts[3], 300),
			}

			if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
				event.Time = t
			}

			result.Events = append(result.Events, event)
		}
	}

	result.Count = len(result.Events)
	return result, nil
}

func (c *Collector) getFailedUnits() (*types.FailedUnitsResult, error) {
	result := &types.FailedUnitsResult{
		Units:     []types.FailedUnit{},
		Timestamp: time.Now(),
	}

	// Get stopped automatic services
	psScript := `Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | Select-Object -Property Name,Status,DisplayName | ForEach-Object { $_.Name + '|' + $_.Status + '|' + $_.DisplayName }`

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 3 {
			unit := types.FailedUnit{
				Name:        parts[0],
				ActiveState: strings.TrimSpace(parts[1]),
				Description: strings.TrimSpace(parts[2]),
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

	// Get scheduled tasks
	psScript := `Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object -Property TaskName,State,TaskPath | ForEach-Object { $_.TaskName + '|' + $_.State + '|' + $_.TaskPath }`

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				timer := types.TimerJob{
					Name: parts[0],
				}
				if parts[1] == "Ready" || parts[1] == "Running" {
					timer.LastResult = "success"
				}
				result.Timers = append(result.Timers, timer)
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

	// Query Application and System logs for service-related events
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='Application','System'} -MaxEvents %d 2>$null | Where-Object { $_.Message -match '%s' } | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.LevelDisplayName + '|' + $_.Message.Substring(0, [Math]::Min(500, $_.Message.Length)) }`, lines*10, service)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	logLines := strings.Split(string(output), "\n")
	count := 0
	for _, line := range logLines {
		if strings.TrimSpace(line) == "" || count >= lines {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}

		log := types.ServiceLog{
			Message: parts[2],
		}

		if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
			log.Time = t
		}

		switch strings.ToLower(parts[1]) {
		case "error":
			log.Level = "error"
		case "warning":
			log.Level = "warning"
		default:
			log.Level = "info"
		}

		result.Logs = append(result.Logs, log)
		count++
	}

	result.Count = len(result.Logs)
	return result, nil
}

func (c *Collector) getDeploymentEvents(limit int) (*types.DeploymentEventsResult, error) {
	result := &types.DeploymentEventsResult{
		Events:    []types.DeploymentEvent{},
		Timestamp: time.Now(),
	}

	// Get recently installed software
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MsiInstaller'} -MaxEvents %d 2>$null | ForEach-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.Id + '|' + $_.Message.Substring(0, [Math]::Min(200, $_.Message.Length)) }`, limit)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || len(result.Events) >= limit {
				continue
			}
			parts := strings.SplitN(line, "|", 3)
			if len(parts) < 3 {
				continue
			}

			event := types.DeploymentEvent{}

			if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
				event.Time = t
			}

			// Determine action from event ID
			switch parts[1] {
			case "1033":
				event.Action = "install"
				result.Installs++
			case "1034":
				event.Action = "remove"
				result.Removes++
			case "1035":
				event.Action = "update"
				result.Updates++
			default:
				event.Action = "install"
			}

			// Extract package name from message
			re := regexp.MustCompile(`Product:\s*([^-]+)`)
			match := re.FindStringSubmatch(parts[2])
			if len(match) >= 2 {
				event.Package = strings.TrimSpace(match[1])
			} else {
				event.Package = truncateString(parts[2], 100)
			}

			result.Events = append(result.Events, event)
		}
	}

	// Check Windows Update history
	psScript = fmt.Sprintf(`Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First %d | ForEach-Object { $_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss') + '|' + $_.HotFixID + '|' + $_.Description }`, limit)
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" || len(result.Events) >= limit {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) >= 3 {
				event := types.DeploymentEvent{
					Package: parts[1],
					Action:  "update",
				}
				if t, err := time.Parse("2006-01-02 15:04:05", parts[0]); err == nil {
					event.Time = t
				}
				result.Events = append(result.Events, event)
				result.Updates++
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

	// Query Security log for logon failures
	startTime := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02T15:04:05")
	psScript := fmt.Sprintf(`Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime='%s'} 2>$null | ForEach-Object { $xml = [xml]$_.ToXml(); $ip = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}).'#text'; $user = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'; $logonType = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'LogonType'}).'#text'; "$ip|$user|$logonType" }`, startTime)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
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
		parts := strings.Split(line, "|")

		if len(parts) >= 1 && parts[0] != "" && parts[0] != "-" {
			ipCounts[parts[0]]++
		}

		if len(parts) >= 2 && parts[1] != "" {
			userCounts[parts[1]]++
		}
	}

	// Convert to slices
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

	// Check Windows Firewall
	result.Firewall = getFirewallStatusWindows()

	// Check Windows Defender
	result.Defender = getDefenderStatus()

	// Check for updates
	result.Updates = getUpdateStatusWindows()

	return result, nil
}

func getFirewallStatusWindows() types.FirewallStatus {
	status := types.FirewallStatus{
		Type: "windows_firewall",
	}

	psScript := `Get-NetFirewallProfile | Select-Object -Property Name,Enabled | ForEach-Object { $_.Name + '|' + $_.Enabled }`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		enabledCount := 0
		for _, line := range lines {
			if strings.Contains(line, "True") {
				enabledCount++
			}
		}
		status.Enabled = enabledCount > 0
		status.RuleCount = enabledCount
	}

	return status
}

func getDefenderStatus() types.DefenderStatus {
	status := types.DefenderStatus{}

	psScript := `Get-MpComputerStatus | Select-Object -Property AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AMProductVersion | ForEach-Object { $_.AMServiceEnabled.ToString() + '|' + $_.AntispywareEnabled.ToString() + '|' + $_.AntivirusEnabled.ToString() + '|' + $_.RealTimeProtectionEnabled.ToString() + '|' + $_.AMProductVersion }`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		parts := strings.Split(strings.TrimSpace(string(output)), "|")
		if len(parts) >= 5 {
			status.Enabled = parts[0] == "True"
			status.RealTime = parts[3] == "True"
			status.DefinitionVer = parts[4]
		}
	}

	// Check last scan time
	psScript = `Get-MpComputerStatus | Select-Object -Property AntivirusSignatureLastUpdated | ForEach-Object { $_.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd HH:mm:ss') }`
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err = cmd.Output()
	if err == nil {
		status.LastScan = strings.TrimSpace(string(output))
	}

	return status
}

func getUpdateStatusWindows() types.UpdateStatus {
	status := types.UpdateStatus{}

	// Check Windows Update status
	psScript := `$Session = New-Object -ComObject Microsoft.Update.Session; $Searcher = $Session.CreateUpdateSearcher(); $Results = $Searcher.Search("IsInstalled=0"); $Results.Updates.Count`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		if count, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			status.PendingUpdates = count
		}
	}

	// Check last update
	psScript = `Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | ForEach-Object { $_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss') }`
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err = cmd.Output()
	if err == nil {
		status.LastCheck = strings.TrimSpace(string(output))
	}

	return status
}

func (c *Collector) getSSHSecuritySummary() (*types.SSHSecuritySummaryResult, error) {
	result := &types.SSHSecuritySummaryResult{
		Timestamp: time.Now(),
	}

	// Check if OpenSSH Server is installed
	psScript := `Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' | Select-Object -Property State | ForEach-Object { $_.State }`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil || !strings.Contains(string(output), "Installed") {
		result.Installed = false
		return result, nil
	}

	result.Installed = true
	settings := types.SSHSettings{}

	// Parse sshd_config if it exists
	sshdConfig := os.Getenv("ProgramData") + "\\ssh\\sshd_config"
	if data, err := os.ReadFile(sshdConfig); err == nil {
		parseSSHConfigWindows(string(data), &settings)
	}

	result.Settings = settings

	// Determine warnings and recommendations
	if settings.PermitRootLogin == "yes" {
		result.Warnings = append(result.Warnings, "Administrator login is enabled")
		result.Recommendations = append(result.Recommendations, "Disable administrator login via SSH")
	}
	if settings.PasswordAuth {
		result.Recommendations = append(result.Recommendations, "Consider disabling password authentication")
	}

	return result, nil
}

func parseSSHConfigWindows(content string, settings *types.SSHSettings) {
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
				settings.MaxAuthTries = port // Store port temporarily
			}
		case "permitrootlogin":
			settings.PermitRootLogin = value
		case "passwordauthentication":
			settings.PasswordAuth = strings.ToLower(value) == "yes"
		case "pubkeyauthentication":
			settings.PubkeyAuth = strings.ToLower(value) == "yes"
		}
	}
}

func (c *Collector) getAdminAccountSummary() (*types.AdminAccountSummaryResult, error) {
	result := &types.AdminAccountSummaryResult{
		Admins:    []types.AdminAccount{},
		Timestamp: time.Now(),
	}

	// Get local administrators
	psScript := `Get-LocalGroupMember -Group 'Administrators' | Select-Object -Property Name,ObjectClass,PrincipalSource | ForEach-Object { $_.Name + '|' + $_.ObjectClass + '|' + $_.PrincipalSource }`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) >= 1 {
			name := strings.TrimSpace(parts[0])
			// Extract just the username from DOMAIN\user format
			if idx := strings.LastIndex(name, "\\"); idx > 0 {
				name = name[idx+1:]
			}

			account := types.AdminAccount{
				User:   name,
				Groups: []string{"Administrators"},
			}

			if len(parts) >= 2 {
				account.Shell = parts[1] // Using shell field for object class
			}

			result.Admins = append(result.Admins, account)
		}
	}

	result.Count = len(result.Admins)
	return result, nil
}

func (c *Collector) getExposedServicesSummary() (*types.ExposedServicesSummaryResult, error) {
	result := &types.ExposedServicesSummaryResult{
		Services:  []types.ExposedService{},
		Timestamp: time.Now(),
	}

	// Use netstat to get listening ports
	cmd := cmdexec.Command("netstat", "-ano", "-p", "tcp")
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	seen := make(map[int]bool)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if !strings.Contains(line, "LISTENING") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}

		// Parse local address
		addrParts := strings.Split(parts[1], ":")
		if len(addrParts) < 2 {
			continue
		}

		port, err := strconv.Atoi(addrParts[len(addrParts)-1])
		if err != nil || seen[port] {
			continue
		}
		seen[port] = true

		bindAddr := strings.Join(addrParts[:len(addrParts)-1], ":")
		pid := parts[4]

		service := types.ExposedService{
			Protocol: "tcp",
			Port:     port,
			Address:  bindAddr,
			External: bindAddr == "0.0.0.0" || bindAddr == "::",
		}

		// Get process name from PID
		if pid != "0" {
			psScript := fmt.Sprintf(`Get-Process -Id %s 2>$null | Select-Object -Property ProcessName | ForEach-Object { $_.ProcessName }`, pid)
			procCmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
			procOutput, err := procCmd.Output()
			if err == nil {
				service.Process = strings.TrimSpace(string(procOutput))
			}
			if pidInt, err := strconv.ParseInt(pid, 10, 32); err == nil {
				service.PID = int32(pidInt)
			}
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

	// Get system limits
	psScript := `
$os = Get-WmiObject -Class Win32_OperatingSystem
$cs = Get-WmiObject -Class Win32_ComputerSystem
Write-Output "TotalVisibleMemorySize|$($os.TotalVisibleMemorySize)"
Write-Output "FreePhysicalMemory|$($os.FreePhysicalMemory)"
Write-Output "TotalVirtualMemorySize|$($os.TotalVirtualMemorySize)"
Write-Output "FreeVirtualMemory|$($os.FreeVirtualMemory)"
Write-Output "NumberOfProcesses|$($os.NumberOfProcesses)"
Write-Output "NumberOfUsers|$($os.NumberOfUsers)"
Write-Output "MaxProcessMemorySize|$($os.MaxProcessMemorySize)"
`
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 2)
			if len(parts) >= 2 {
				val, _ := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				limit := types.ResourceLimit{
					Type:    strings.TrimSpace(parts[0]),
					Hard:    val,
					Soft:    val,
					Current: val,
					Unit:    "KB",
				}
				result.Limits = append(result.Limits, limit)
			}
		}
	}

	// Get handle limits
	psScript = `Get-Process | Measure-Object -Property Handles -Sum | ForEach-Object { $_.Sum }`
	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err = cmd.Output()
	if err == nil {
		if val, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64); err == nil {
			result.Limits = append(result.Limits, types.ResourceLimit{
				Type:    "TotalHandles",
				Hard:    val,
				Soft:    val,
				Current: val,
				Unit:    "count",
			})
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
	cutoffStr := cutoff.Format("20060102")

	// Query registry for installed software
	psScript := fmt.Sprintf(`Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.InstallDate -ge '%s' } | Select-Object DisplayName,DisplayVersion,InstallDate,Publisher | ForEach-Object { $_.DisplayName + '|' + $_.DisplayVersion + '|' + $_.InstallDate + '|' + $_.Publisher }`, cutoffStr)

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) >= 1 && parts[0] != "" {
				pkg := types.InstalledPackage{
					Name:    parts[0],
					Manager: "windows",
				}
				if len(parts) >= 2 {
					pkg.Version = parts[1]
				}
				if len(parts) >= 3 && parts[2] != "" {
					if t, err := time.Parse("20060102", parts[2]); err == nil {
						pkg.Installed = t
					}
				}
				result.Packages = append(result.Packages, pkg)
			}
		}
	}

	// Also check 32-bit registry on 64-bit systems
	psScript = fmt.Sprintf(`Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.InstallDate -ge '%s' } | Select-Object DisplayName,DisplayVersion,InstallDate | ForEach-Object { $_.DisplayName + '|' + $_.DisplayVersion + '|' + $_.InstallDate }`, cutoffStr)

	cmd = cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err = cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := strings.Split(line, "|")
			if len(parts) >= 1 && parts[0] != "" {
				pkg := types.InstalledPackage{
					Name:    parts[0],
					Manager: "windows-wow64",
				}
				if len(parts) >= 2 {
					pkg.Version = parts[1]
				}
				result.Packages = append(result.Packages, pkg)
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

	// Get disk information
	psScript := `Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object DeviceID,FileSystem,Size,FreeSpace | ForEach-Object { $_.DeviceID + '|' + $_.FileSystem + '|' + $_.Size + '|' + $_.FreeSpace }`

	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return result, nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 4 {
			continue
		}

		size, _ := strconv.ParseInt(parts[2], 10, 64)
		free, _ := strconv.ParseInt(parts[3], 10, 64)
		used := size - free
		var usedPct float64
		if size > 0 {
			usedPct = float64(used) / float64(size) * 100
		}

		fs := types.FSHealth{
			Device:    parts[0],
			Mount:     parts[0],
			Type:      parts[1],
			Size:      size,
			Used:      used,
			Available: free,
			UsedPct:   usedPct,
		}

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
			result.Recommendations = append(result.Recommendations, "Enable Windows Firewall")
		}
		if !basics.Defender.Enabled {
			score -= 20
			result.Recommendations = append(result.Recommendations, "Enable Windows Defender")
		}
		if !basics.Defender.RealTime {
			score -= 10
			result.Recommendations = append(result.Recommendations, "Enable real-time protection")
		}
		if basics.Updates.PendingUpdates > 0 {
			score -= 10
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("Install %d pending updates", basics.Updates.PendingUpdates))
		}
	}

	// Get SSH security (if applicable)
	if ssh, err := c.getSSHSecuritySummary(); err == nil && ssh.Installed {
		result.SSHSecurity = ssh
		result.Recommendations = append(result.Recommendations, ssh.Recommendations...)
	}

	// Get admin accounts
	if admins, err := c.getAdminAccountSummary(); err == nil {
		result.AdminAccounts = admins
		if admins.Count > 3 {
			score -= 5
			result.Recommendations = append(result.Recommendations, "Review administrator accounts")
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

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
