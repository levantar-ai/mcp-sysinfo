//go:build windows

package scheduled

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getScheduledTasks retrieves Windows Task Scheduler tasks.
func (c *Collector) getScheduledTasks() (*types.ScheduledTasksResult, error) {
	var tasks []types.ScheduledTask

	// Use schtasks to list tasks
	// #nosec G204 -- schtasks is a system tool
	cmd := cmdexec.Command("schtasks", "/query", "/fo", "csv", "/v")
	output, err := cmd.Output()
	if err != nil {
		// Try PowerShell as fallback
		return c.getScheduledTasksPowerShell()
	}

	tasks = parseSchTasksCSV(output)

	return &types.ScheduledTasksResult{
		Tasks:     tasks,
		Count:     len(tasks),
		Source:    "taskscheduler",
		Timestamp: time.Now(),
	}, nil
}

// parseSchTasksCSV parses schtasks CSV output.
func parseSchTasksCSV(output []byte) []types.ScheduledTask {
	var tasks []types.ScheduledTask

	reader := csv.NewReader(bytes.NewReader(output))
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return tasks
	}

	// Find column indices
	header := records[0]
	indices := make(map[string]int)
	for i, h := range header {
		h = strings.TrimSpace(h)
		indices[h] = i
	}

	// Process records
	for _, record := range records[1:] {
		if len(record) < len(header) {
			continue
		}

		getField := func(name string) string {
			if idx, ok := indices[name]; ok && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}

		task := types.ScheduledTask{
			Name:        getField("TaskName"),
			Path:        getField("TaskName"),
			Status:      getField("Status"),
			Author:      getField("Author"),
			Description: getField("Comment"),
			Command:     getField("Task To Run"),
			RunAsUser:   getField("Run As User"),
			Schedule:    getField("Scheduled Task State"),
		}

		// Parse times
		if nextRun := getField("Next Run Time"); nextRun != "" && nextRun != "N/A" {
			if t, err := parseWindowsTime(nextRun); err == nil {
				task.NextRun = t
			}
		}
		if lastRun := getField("Last Run Time"); lastRun != "" && lastRun != "N/A" {
			if t, err := parseWindowsTime(lastRun); err == nil {
				task.LastRun = t
			}
		}
		if lastResult := getField("Last Result"); lastResult != "" {
			if code, err := strconv.Atoi(lastResult); err == nil {
				task.LastResult = code
			}
		}

		tasks = append(tasks, task)
	}

	return tasks
}

// parseWindowsTime parses Windows date/time formats.
func parseWindowsTime(s string) (time.Time, error) {
	formats := []string{
		"1/2/2006 3:04:05 PM",
		"2006-01-02 15:04:05",
		"01/02/2006 15:04:05",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, nil
}

// getScheduledTasksPowerShell uses PowerShell as fallback.
func (c *Collector) getScheduledTasksPowerShell() (*types.ScheduledTasksResult, error) {
	var tasks []types.ScheduledTask

	psCmd := `Get-ScheduledTask | Select-Object TaskName,State,Description | ConvertTo-Json`
	// #nosec G204 -- PowerShell is a system tool
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return &types.ScheduledTasksResult{
			Tasks:     tasks,
			Count:     0,
			Source:    "taskscheduler",
			Timestamp: time.Now(),
		}, nil
	}

	// Simple JSON parsing
	content := string(output)
	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentTask types.ScheduledTask
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "TaskName") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentTask.Name = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "State") {
			if idx := strings.Index(line, ":"); idx > 0 {
				stateNum := strings.Trim(line[idx+1:], `", `)
				switch stateNum {
				case "0":
					currentTask.Status = "Unknown"
				case "1":
					currentTask.Status = "Disabled"
				case "2":
					currentTask.Status = "Queued"
				case "3":
					currentTask.Status = "Ready"
				case "4":
					currentTask.Status = "Running"
				default:
					currentTask.Status = stateNum
				}
			}
		} else if strings.Contains(line, "Description") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentTask.Description = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "}") {
			if currentTask.Name != "" {
				tasks = append(tasks, currentTask)
			}
			currentTask = types.ScheduledTask{}
		}
	}

	return &types.ScheduledTasksResult{
		Tasks:     tasks,
		Count:     len(tasks),
		Source:    "taskscheduler",
		Timestamp: time.Now(),
	}, nil
}

// getCronJobs returns empty result on Windows (Unix only).
func (c *Collector) getCronJobs() (*types.CronJobsResult, error) {
	return &types.CronJobsResult{
		Jobs:      []types.CronJob{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// getStartupItems retrieves startup items on Windows.
func (c *Collector) getStartupItems() (*types.StartupItemsResult, error) {
	var items []types.StartupItem

	// Registry locations for startup items
	registryLocations := []struct {
		root registry.Key
		path string
		user string
	}{
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, "current_user"},
		{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "current_user"},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`, "system"},
		{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "system"},
		{registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "system"},
	}

	for _, loc := range registryLocations {
		key, err := registry.OpenKey(loc.root, loc.path, registry.READ)
		if err != nil {
			continue
		}

		names, err := key.ReadValueNames(-1)
		if err != nil {
			key.Close()
			continue
		}

		for _, name := range names {
			value, _, err := key.GetStringValue(name)
			if err != nil {
				continue
			}

			rootName := "HKCU"
			if loc.root == registry.LOCAL_MACHINE {
				rootName = "HKLM"
			}

			items = append(items, types.StartupItem{
				Name:     name,
				Command:  value,
				Location: rootName + `\` + loc.path,
				Type:     "registry",
				Enabled:  true,
				User:     loc.user,
			})
		}
		key.Close()
	}

	// Startup folders
	startupFolders := []struct {
		path string
		user string
	}{
		{os.ExpandEnv(`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`), "current_user"},
		{os.ExpandEnv(`%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup`), "system"},
	}

	for _, folder := range startupFolders {
		entries, err := os.ReadDir(folder.path)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			path := filepath.Join(folder.path, name)

			// Skip desktop.ini
			if strings.EqualFold(name, "desktop.ini") {
				continue
			}

			items = append(items, types.StartupItem{
				Name:     strings.TrimSuffix(name, filepath.Ext(name)),
				Command:  path,
				Location: folder.path,
				Type:     "startup_folder",
				Enabled:  true,
				User:     folder.user,
			})
		}
	}

	return &types.StartupItemsResult{
		Items:     items,
		Count:     len(items),
		Timestamp: time.Now(),
	}, nil
}

// getSystemdServices returns empty result on Windows (Linux only).
func (c *Collector) getSystemdServices() (*types.SystemdServicesResult, error) {
	return &types.SystemdServicesResult{
		Services:  []types.SystemdService{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}
