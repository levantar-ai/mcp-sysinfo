//go:build linux

package scheduled

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getScheduledTasks retrieves at jobs on Linux.
func (c *Collector) getScheduledTasks() (*types.ScheduledTasksResult, error) {
	var tasks []types.ScheduledTask

	// Try to get at jobs
	atq, err := exec.LookPath("atq")
	if err == nil {
		// #nosec G204 -- atq path is from LookPath
		cmd := exec.Command(atq)
		output, err := cmd.Output()
		if err == nil {
			tasks = append(tasks, parseAtQueue(output)...)
		}
	}

	return &types.ScheduledTasksResult{
		Tasks:     tasks,
		Count:     len(tasks),
		Source:    "at",
		Timestamp: time.Now(),
	}, nil
}

// parseAtQueue parses atq output.
func parseAtQueue(output []byte) []types.ScheduledTask {
	var tasks []types.ScheduledTask
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// atq format: 1	Thu Jan 15 10:30:00 2024 a user
	pattern := regexp.MustCompile(`^(\d+)\s+(.+?)\s+([a-z])\s+(\S+)$`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		// Parse the scheduled time
		timeStr := matches[2]
		nextRun, _ := time.Parse("Mon Jan 2 15:04:05 2006", timeStr)

		tasks = append(tasks, types.ScheduledTask{
			Name:      "at job " + matches[1],
			Status:    "Scheduled",
			NextRun:   nextRun,
			RunAsUser: matches[4],
			Schedule:  timeStr,
		})
	}

	return tasks
}

// getCronJobs retrieves cron jobs on Linux.
func (c *Collector) getCronJobs() (*types.CronJobsResult, error) {
	var jobs []types.CronJob

	// System crontab
	if entries, err := parseCrontab("/etc/crontab", "root"); err == nil {
		jobs = append(jobs, entries...)
	}

	// /etc/cron.d/ directory
	cronDPath := "/etc/cron.d"
	if entries, err := os.ReadDir(cronDPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			path := filepath.Join(cronDPath, entry.Name())
			if cronJobs, err := parseCrontab(path, ""); err == nil {
				jobs = append(jobs, cronJobs...)
			}
		}
	}

	// User crontabs
	users := []string{"root"}
	// Try to get current user's crontab
	if crontab, err := exec.LookPath("crontab"); err == nil {
		// #nosec G204 -- crontab path is from LookPath
		cmd := exec.Command(crontab, "-l")
		output, err := cmd.Output()
		if err == nil {
			currentUser := os.Getenv("USER")
			if currentUser == "" {
				currentUser = "current"
			}
			userJobs := parseCrontabOutput(output, currentUser, "user")
			jobs = append(jobs, userJobs...)
		}
	}

	// Check /var/spool/cron/crontabs for other users (requires root)
	spoolPath := "/var/spool/cron/crontabs"
	if entries, err := os.ReadDir(spoolPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			// Skip if already checked this user
			skip := false
			for _, u := range users {
				if entry.Name() == u {
					skip = true
					break
				}
			}
			if skip {
				continue
			}

			path := filepath.Join(spoolPath, entry.Name())
			if cronJobs, err := parseCrontab(path, entry.Name()); err == nil {
				jobs = append(jobs, cronJobs...)
			}
		}
	}

	// Check periodic directories (/etc/cron.hourly, daily, weekly, monthly)
	periodicDirs := map[string]string{
		"/etc/cron.hourly":  "@hourly",
		"/etc/cron.daily":   "@daily",
		"/etc/cron.weekly":  "@weekly",
		"/etc/cron.monthly": "@monthly",
	}
	for dir, schedule := range periodicDirs {
		if entries, err := os.ReadDir(dir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				jobs = append(jobs, types.CronJob{
					Schedule: schedule,
					Command:  filepath.Join(dir, entry.Name()),
					User:     "root",
					Source:   dir,
					Enabled:  true,
				})
			}
		}
	}

	return &types.CronJobsResult{
		Jobs:      jobs,
		Count:     len(jobs),
		Timestamp: time.Now(),
	}, nil
}

// parseCrontab parses a crontab file.
func parseCrontab(path string, defaultUser string) ([]types.CronJob, error) {
	// #nosec G304 -- path is from controlled input
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCrontabOutput(content, defaultUser, path), nil
}

// parseCrontabOutput parses crontab content.
func parseCrontabOutput(content []byte, defaultUser, source string) []types.CronJob {
	var jobs []types.CronJob
	scanner := bufio.NewScanner(bytes.NewReader(content))

	// Standard cron pattern: minute hour day month dow [user] command
	// Also handle special schedules: @reboot, @hourly, etc.
	standardPattern := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$`)
	specialPattern := regexp.MustCompile(`^(@\w+)\s+(.+)$`)

	var lastComment string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Track comments for description
		if strings.HasPrefix(line, "#") {
			lastComment = strings.TrimPrefix(line, "#")
			lastComment = strings.TrimSpace(lastComment)
			continue
		}

		// Skip empty lines and shell/path settings
		if line == "" || strings.HasPrefix(line, "SHELL=") ||
			strings.HasPrefix(line, "PATH=") || strings.HasPrefix(line, "MAILTO=") {
			continue
		}

		var job types.CronJob
		job.Source = source
		job.Enabled = true
		job.Description = lastComment
		lastComment = ""

		// Try special schedule first
		if matches := specialPattern.FindStringSubmatch(line); matches != nil {
			job.Schedule = matches[1]
			rest := matches[2]

			// Check if there's a user specified (for /etc/crontab format)
			parts := strings.Fields(rest)
			if len(parts) >= 2 && isUser(parts[0]) {
				job.User = parts[0]
				job.Command = strings.Join(parts[1:], " ")
			} else {
				job.User = defaultUser
				job.Command = rest
			}
			jobs = append(jobs, job)
			continue
		}

		// Try standard pattern
		if matches := standardPattern.FindStringSubmatch(line); matches != nil {
			job.Schedule = strings.Join(matches[1:6], " ")
			rest := matches[6]

			// Check if there's a user specified (for /etc/crontab format)
			parts := strings.Fields(rest)
			if len(parts) >= 2 && isUser(parts[0]) {
				job.User = parts[0]
				job.Command = strings.Join(parts[1:], " ")
			} else {
				job.User = defaultUser
				job.Command = rest
			}
			jobs = append(jobs, job)
		}
	}

	return jobs
}

// isUser checks if a string looks like a username (simple heuristic).
func isUser(s string) bool {
	// Usernames are typically alphanumeric, not starting with / or -
	if s == "" || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "-") {
		return false
	}
	// Check for common command prefixes that aren't users
	nonUsers := []string{"test", "echo", "cd", "if", "for", "while"}
	for _, nu := range nonUsers {
		if s == nu {
			return false
		}
	}
	return true
}

// getStartupItems retrieves startup items on Linux.
func (c *Collector) getStartupItems() (*types.StartupItemsResult, error) {
	var items []types.StartupItem

	// Check XDG autostart directories
	autostartDirs := []string{
		"/etc/xdg/autostart",
		os.ExpandEnv("$HOME/.config/autostart"),
	}

	for _, dir := range autostartDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".desktop") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if item, err := parseDesktopFile(path); err == nil {
				item.Location = path
				item.Type = "autostart"
				if strings.HasPrefix(dir, "/etc") {
					item.User = "system"
				} else {
					item.User = os.Getenv("USER")
				}
				items = append(items, item)
			}
		}
	}

	// Check systemd user services
	userServiceDirs := []string{
		os.ExpandEnv("$HOME/.config/systemd/user"),
		"/etc/systemd/user",
	}

	for _, dir := range userServiceDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			items = append(items, types.StartupItem{
				Name:     strings.TrimSuffix(entry.Name(), ".service"),
				Command:  path,
				Location: path,
				Type:     "systemd-user",
				Enabled:  true, // Would need to check symlinks for actual status
				User:     "user",
			})
		}
	}

	// Check init.d (legacy)
	initDPath := "/etc/init.d"
	if entries, err := os.ReadDir(initDPath); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") ||
				entry.Name() == "README" || entry.Name() == "skeleton" {
				continue
			}
			path := filepath.Join(initDPath, entry.Name())
			items = append(items, types.StartupItem{
				Name:     entry.Name(),
				Command:  path,
				Location: path,
				Type:     "init.d",
				Enabled:  true, // Would need to check rc levels
				User:     "system",
			})
		}
	}

	return &types.StartupItemsResult{
		Items:     items,
		Count:     len(items),
		Timestamp: time.Now(),
	}, nil
}

// parseDesktopFile parses a .desktop file for autostart.
func parseDesktopFile(path string) (types.StartupItem, error) {
	// #nosec G304 -- path is from controlled directory listing
	content, err := os.ReadFile(path)
	if err != nil {
		return types.StartupItem{}, err
	}

	item := types.StartupItem{
		Name:    strings.TrimSuffix(filepath.Base(path), ".desktop"),
		Enabled: true,
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Name=") {
			item.Name = strings.TrimPrefix(line, "Name=")
		} else if strings.HasPrefix(line, "Exec=") {
			item.Command = strings.TrimPrefix(line, "Exec=")
		} else if strings.HasPrefix(line, "Comment=") {
			item.Description = strings.TrimPrefix(line, "Comment=")
		} else if strings.HasPrefix(line, "Hidden=true") || strings.HasPrefix(line, "NoDisplay=true") {
			item.Enabled = false
		}
	}

	return item, nil
}

// getSystemdServices retrieves systemd service status on Linux.
func (c *Collector) getSystemdServices() (*types.SystemdServicesResult, error) {
	var services []types.SystemdService

	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return &types.SystemdServicesResult{
			Services:  services,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// List all services
	// #nosec G204 -- systemctl path is from LookPath
	cmd := exec.Command(systemctl, "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return &types.SystemdServicesResult{
			Services:  services,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	// Format: UNIT LOAD ACTIVE SUB DESCRIPTION
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := fields[0]
		loadState := fields[1]
		activeState := fields[2]
		subState := fields[3]
		description := ""
		if len(fields) > 4 {
			description = strings.Join(fields[4:], " ")
		}

		// Get additional info for active services
		var mainPID int32
		if activeState == "active" {
			// #nosec G204 -- systemctl path is from LookPath
			showCmd := exec.Command(systemctl, "show", name, "--property=MainPID", "--no-pager")
			if showOutput, err := showCmd.Output(); err == nil {
				if strings.HasPrefix(string(showOutput), "MainPID=") {
					pidStr := strings.TrimPrefix(strings.TrimSpace(string(showOutput)), "MainPID=")
					if pid, err := strconv.ParseInt(pidStr, 10, 32); err == nil {
						mainPID = int32(pid)
					}
				}
			}
		}

		// Get enabled status
		enabled := "unknown"
		// #nosec G204 -- systemctl path is from LookPath
		enabledCmd := exec.Command(systemctl, "is-enabled", name, "--no-pager")
		if enabledOutput, err := enabledCmd.Output(); err == nil {
			enabled = strings.TrimSpace(string(enabledOutput))
		}

		services = append(services, types.SystemdService{
			Name:        name,
			LoadState:   loadState,
			ActiveState: activeState,
			SubState:    subState,
			Description: description,
			MainPID:     mainPID,
			Enabled:     enabled,
		})
	}

	return &types.SystemdServicesResult{
		Services:  services,
		Count:     len(services),
		Timestamp: time.Now(),
	}, nil
}
