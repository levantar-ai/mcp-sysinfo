//go:build darwin

package scheduled

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getScheduledTasks retrieves launchd jobs on macOS.
func (c *Collector) getScheduledTasks() (*types.ScheduledTasksResult, error) {
	var tasks []types.ScheduledTask

	// Get launchd jobs using launchctl
	launchctl, err := exec.LookPath("launchctl")
	if err != nil {
		return &types.ScheduledTasksResult{
			Tasks:     tasks,
			Count:     0,
			Source:    "launchd",
			Timestamp: time.Now(),
		}, nil
	}

	// List user jobs
	// #nosec G204 -- launchctl path is from LookPath
	cmd := exec.Command(launchctl, "list")
	output, err := cmd.Output()
	if err == nil {
		tasks = append(tasks, parseLaunchctlList(output, "user")...)
	}

	// Try to list system jobs (may require root)
	// #nosec G204 -- launchctl path is from LookPath
	sysCmd := exec.Command("sudo", "-n", launchctl, "list")
	sysOutput, err := sysCmd.Output()
	if err == nil {
		tasks = append(tasks, parseLaunchctlList(sysOutput, "system")...)
	}

	return &types.ScheduledTasksResult{
		Tasks:     tasks,
		Count:     len(tasks),
		Source:    "launchd",
		Timestamp: time.Now(),
	}, nil
}

// parseLaunchctlList parses launchctl list output.
func parseLaunchctlList(output []byte, scope string) []types.ScheduledTask {
	var tasks []types.ScheduledTask
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	// Format: PID	Status	Label
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		pid := fields[0]
		status := fields[1]
		label := fields[2]

		task := types.ScheduledTask{
			Name:      label,
			Status:    "Loaded",
			RunAsUser: scope,
		}

		if pid != "-" {
			task.Status = "Running"
		}
		if status != "0" && status != "-" {
			task.Status = "Error (" + status + ")"
		}

		tasks = append(tasks, task)
	}

	return tasks
}

// getCronJobs retrieves cron jobs on macOS.
func (c *Collector) getCronJobs() (*types.CronJobsResult, error) {
	var jobs []types.CronJob

	// System crontab
	if entries, err := parseCrontabDarwin("/etc/crontab", "root"); err == nil {
		jobs = append(jobs, entries...)
	}

	// User crontab
	if crontab, err := exec.LookPath("crontab"); err == nil {
		// #nosec G204 -- crontab path is from LookPath
		cmd := exec.Command(crontab, "-l")
		output, err := cmd.Output()
		if err == nil {
			currentUser := os.Getenv("USER")
			if currentUser == "" {
				currentUser = "current"
			}
			userJobs := parseCrontabOutputDarwin(output, currentUser, "user")
			jobs = append(jobs, userJobs...)
		}
	}

	// Check periodic directories
	periodicDirs := map[string]string{
		"/etc/periodic/daily":   "@daily",
		"/etc/periodic/weekly":  "@weekly",
		"/etc/periodic/monthly": "@monthly",
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

// parseCrontabDarwin parses a crontab file on macOS.
func parseCrontabDarwin(path string, defaultUser string) ([]types.CronJob, error) {
	// #nosec G304 -- path is from controlled input
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCrontabOutputDarwin(content, defaultUser, path), nil
}

// parseCrontabOutputDarwin parses crontab content on macOS.
func parseCrontabOutputDarwin(content []byte, defaultUser, source string) []types.CronJob {
	var jobs []types.CronJob
	scanner := bufio.NewScanner(bytes.NewReader(content))

	standardPattern := regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)$`)
	specialPattern := regexp.MustCompile(`^(@\w+)\s+(.+)$`)

	var lastComment string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "#") {
			lastComment = strings.TrimPrefix(line, "#")
			lastComment = strings.TrimSpace(lastComment)
			continue
		}

		if line == "" || strings.HasPrefix(line, "SHELL=") ||
			strings.HasPrefix(line, "PATH=") || strings.HasPrefix(line, "MAILTO=") {
			continue
		}

		var job types.CronJob
		job.Source = source
		job.Enabled = true
		job.Description = lastComment
		lastComment = ""

		if matches := specialPattern.FindStringSubmatch(line); matches != nil {
			job.Schedule = matches[1]
			job.User = defaultUser
			job.Command = matches[2]
			jobs = append(jobs, job)
			continue
		}

		if matches := standardPattern.FindStringSubmatch(line); matches != nil {
			job.Schedule = strings.Join(matches[1:6], " ")
			job.User = defaultUser
			job.Command = matches[6]
			jobs = append(jobs, job)
		}
	}

	return jobs
}

// getStartupItems retrieves startup items on macOS.
func (c *Collector) getStartupItems() (*types.StartupItemsResult, error) {
	var items []types.StartupItem

	// LaunchAgents (user level)
	launchAgentDirs := []string{
		os.ExpandEnv("$HOME/Library/LaunchAgents"),
		"/Library/LaunchAgents",
	}

	// LaunchDaemons (system level)
	launchDaemonDirs := []string{
		"/Library/LaunchDaemons",
		"/System/Library/LaunchDaemons",
	}

	// Process LaunchAgents
	for _, dir := range launchAgentDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			item := types.StartupItem{
				Name:     strings.TrimSuffix(entry.Name(), ".plist"),
				Command:  path,
				Location: path,
				Type:     "launchagent",
				Enabled:  true,
			}
			if strings.HasPrefix(dir, os.ExpandEnv("$HOME")) {
				item.User = os.Getenv("USER")
			} else {
				item.User = "system"
			}
			items = append(items, item)
		}
	}

	// Process LaunchDaemons
	for _, dir := range launchDaemonDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".plist") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			items = append(items, types.StartupItem{
				Name:     strings.TrimSuffix(entry.Name(), ".plist"),
				Command:  path,
				Location: path,
				Type:     "launchdaemon",
				Enabled:  true,
				User:     "root",
			})
		}
	}

	// Login Items (user login hooks) - check for common locations
	loginItemsDir := os.ExpandEnv("$HOME/Library/Application Support/com.apple.backgroundtaskmanagementagent")
	if entries, err := os.ReadDir(loginItemsDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			items = append(items, types.StartupItem{
				Name:     entry.Name(),
				Command:  filepath.Join(loginItemsDir, entry.Name()),
				Location: loginItemsDir,
				Type:     "loginitem",
				Enabled:  true,
				User:     os.Getenv("USER"),
			})
		}
	}

	return &types.StartupItemsResult{
		Items:     items,
		Count:     len(items),
		Timestamp: time.Now(),
	}, nil
}

// getSystemdServices returns empty result on macOS (Linux only).
func (c *Collector) getSystemdServices() (*types.SystemdServicesResult, error) {
	return &types.SystemdServicesResult{
		Services:  []types.SystemdService{},
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}
