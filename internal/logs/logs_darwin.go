//go:build darwin

package logs

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getJournalLogs returns empty result on macOS (Linux only).
func (c *Collector) getJournalLogs(query *types.LogQuery) (*types.JournalLogResult, error) {
	return &types.JournalLogResult{
		LogResult: types.LogResult{
			Entries:   []types.LogEntry{},
			Source:    "journald",
			Count:     0,
			Timestamp: time.Now(),
		},
	}, nil
}

// getSyslog retrieves system log entries on macOS using the `log` command.
func (c *Collector) getSyslog(query *types.LogQuery) (*types.LogResult, error) {
	query = normalizeQuery(query)

	// Use macOS `log` command
	args := []string{
		"show",
		"--style", "syslog",
		"--last", fmt.Sprintf("%dm", 60), // Last 60 minutes by default
	}

	if query.Source != "" {
		args = append(args, "--process", query.Source)
	}

	if query.Grep != "" {
		args = append(args, "--predicate", fmt.Sprintf("eventMessage CONTAINS '%s'", query.Grep))
	}

	// #nosec G204 -- log command path is hardcoded
	cmd := cmdexec.Command("/usr/bin/log", args...)
	output, err := cmd.Output()
	if err != nil {
		// Fallback to /var/log/system.log
		return c.readSystemLog(query)
	}

	entries := parseLogShowOutput(output)
	entries, truncated := truncateEntries(entries, query.Lines)

	return makeLogResult(entries, "log", truncated), nil
}

// parseLogShowOutput parses macOS `log show` output.
func parseLogShowOutput(output []byte) []types.LogEntry {
	var entries []types.LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Pattern: 2024-01-15 10:30:45.123456-0500 hostname process[pid]: message
	pattern := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?(?::\s*|\s+)(.*)$`)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Timestamp") || line == "" {
			continue // Skip header
		}

		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		timestamp, _ := time.Parse("2006-01-02 15:04:05.000000-0700", matches[1])
		var pid int32
		if matches[4] != "" {
			p, _ := strconv.ParseInt(matches[4], 10, 32)
			pid = int32(p)
		}

		entries = append(entries, types.LogEntry{
			Timestamp: timestamp,
			Source:    matches[3],
			Message:   matches[5],
			PID:       pid,
			Fields: map[string]string{
				"hostname": matches[2],
			},
		})
	}

	return entries
}

// readSystemLog reads from /var/log/system.log as fallback.
func (c *Collector) readSystemLog(query *types.LogQuery) (*types.LogResult, error) {
	entries, err := readLogFileDarwin("/var/log/system.log", query.Lines*2)
	if err != nil {
		return makeLogResult([]types.LogEntry{}, "syslog", false), nil
	}

	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}
	entries, truncated := truncateEntries(entries, query.Lines)

	return makeLogResult(entries, "system.log", truncated), nil
}

// getKernelLogs retrieves kernel logs on macOS.
func (c *Collector) getKernelLogs(query *types.LogQuery) (*types.KernelLogResult, error) {
	query = normalizeQuery(query)

	// Use macOS `log` command with kernel subsystem
	args := []string{
		"show",
		"--style", "syslog",
		"--last", "60m",
		"--predicate", "subsystem == 'com.apple.kernel'",
	}

	// #nosec G204 -- log command path is hardcoded
	cmd := cmdexec.Command("/usr/bin/log", args...)
	output, err := cmd.Output()
	if err != nil {
		// Try dmesg as fallback
		return c.getDmesgDarwin(query)
	}

	entries := parseLogShowOutput(output)
	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}
	entries, truncated := truncateEntries(entries, query.Lines)

	return &types.KernelLogResult{
		LogResult: types.LogResult{
			Entries:   entries,
			Source:    "log",
			Count:     len(entries),
			Truncated: truncated,
			Timestamp: time.Now(),
		},
	}, nil
}

// getDmesgDarwin uses dmesg as fallback for kernel logs.
func (c *Collector) getDmesgDarwin(query *types.LogQuery) (*types.KernelLogResult, error) {
	// #nosec G204 -- dmesg path is hardcoded
	cmd := cmdexec.Command("/sbin/dmesg")
	output, err := cmd.Output()
	if err != nil {
		return &types.KernelLogResult{
			LogResult: types.LogResult{
				Entries:   []types.LogEntry{},
				Source:    "dmesg",
				Count:     0,
				Timestamp: time.Now(),
			},
		}, nil
	}

	var entries []types.LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		entries = append(entries, types.LogEntry{
			Timestamp: time.Now(),
			Source:    "kernel",
			Message:   line,
		})
	}

	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}
	entries, truncated := truncateEntries(entries, query.Lines)

	return &types.KernelLogResult{
		LogResult: types.LogResult{
			Entries:   entries,
			Source:    "dmesg",
			Count:     len(entries),
			Truncated: truncated,
			Timestamp: time.Now(),
		},
	}, nil
}

// getAuthLogs retrieves authentication logs on macOS.
func (c *Collector) getAuthLogs(query *types.LogQuery) (*types.AuthLogResult, error) {
	query = normalizeQuery(query)

	// Use macOS `log` command with auth-related predicates
	args := []string{
		"show",
		"--style", "syslog",
		"--last", "60m",
		"--predicate", "subsystem == 'com.apple.securityd' OR process == 'sshd' OR process == 'sudo' OR process == 'login'",
	}

	// #nosec G204 -- log command path is hardcoded
	cmd := cmdexec.Command("/usr/bin/log", args...)
	output, err := cmd.Output()
	if err != nil {
		// Fallback to reading auth files
		return c.readAuthLogsDarwin(query)
	}

	entries := parseLogShowOutput(output)
	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}
	entries, truncated := truncateEntries(entries, query.Lines)
	failed, success := countAuthEventsDarwin(entries)

	return &types.AuthLogResult{
		LogResult: types.LogResult{
			Entries:   entries,
			Source:    "log",
			Count:     len(entries),
			Truncated: truncated,
			Timestamp: time.Now(),
		},
		FailedLogins:     failed,
		SuccessfulLogins: success,
	}, nil
}

// readAuthLogsDarwin reads from /var/log/secure.log as fallback.
func (c *Collector) readAuthLogsDarwin(query *types.LogQuery) (*types.AuthLogResult, error) {
	authPaths := []string{
		"/var/log/secure.log",
		"/var/log/authd.log",
	}

	var entries []types.LogEntry
	for _, path := range authPaths {
		if _, err := os.Stat(path); err == nil {
			e, err := readLogFileDarwin(path, query.Lines)
			if err == nil {
				entries = append(entries, e...)
			}
		}
	}

	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}
	entries, truncated := truncateEntries(entries, query.Lines)
	failed, success := countAuthEventsDarwin(entries)

	return &types.AuthLogResult{
		LogResult: types.LogResult{
			Entries:   entries,
			Source:    "auth",
			Count:     len(entries),
			Truncated: truncated,
			Timestamp: time.Now(),
		},
		FailedLogins:     failed,
		SuccessfulLogins: success,
	}, nil
}

// countAuthEventsDarwin counts failed and successful login attempts.
func countAuthEventsDarwin(entries []types.LogEntry) (failed, success int) {
	for _, e := range entries {
		msg := toLower(e.Message)
		if contains(msg, "failed") || contains(msg, "invalid") || contains(msg, "denied") {
			failed++
		} else if contains(msg, "accepted") || contains(msg, "succeeded") || contains(msg, "authenticated") {
			success++
		}
	}
	return
}

// getAppLogs retrieves application-specific logs on macOS.
func (c *Collector) getAppLogs(query *types.AppLogQuery) (*types.LogResult, error) {
	if query == nil {
		query = &types.AppLogQuery{}
	}
	query.LogQuery = *normalizeQuery(&query.LogQuery)

	var entries []types.LogEntry

	// Handle specific paths
	if query.Path != "" {
		e, err := readLogFileDarwin(query.Path, query.Lines*2)
		if err == nil {
			entries = append(entries, e...)
		}
	}

	// Handle multiple paths
	for _, path := range query.Paths {
		e, err := readLogFileDarwin(path, query.Lines)
		if err == nil {
			entries = append(entries, e...)
		}
	}

	// Handle glob pattern
	if query.Pattern != "" {
		matches, err := filepath.Glob(query.Pattern)
		if err == nil {
			for _, path := range matches {
				e, err := readLogFileDarwin(path, query.Lines/len(matches)+1)
				if err == nil {
					entries = append(entries, e...)
				}
			}
		}
	}

	// Default: check common app log locations on macOS
	if query.Path == "" && len(query.Paths) == 0 && query.Pattern == "" {
		defaultPaths := []string{
			"/var/log/apache2/access_log",
			"/var/log/apache2/error_log",
			"/usr/local/var/log/nginx/access.log",
			"/usr/local/var/log/nginx/error.log",
			"/opt/homebrew/var/log/nginx/access.log",
			"/opt/homebrew/var/log/nginx/error.log",
		}
		for _, path := range defaultPaths {
			if _, err := os.Stat(path); err == nil {
				e, err := readLogFileDarwin(path, query.Lines/2)
				if err == nil {
					entries = append(entries, e...)
				}
			}
		}
	}

	// Apply grep filter
	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}

	entries, truncated := truncateEntries(entries, query.Lines)
	return makeLogResult(entries, "app", truncated), nil
}

// getEventLog returns empty result on macOS (Windows only).
func (c *Collector) getEventLog(query *types.EventLogQuery) (*types.EventLogResult, error) {
	return &types.EventLogResult{
		LogResult: types.LogResult{
			Entries:   []types.LogEntry{},
			Source:    "eventlog",
			Count:     0,
			Timestamp: time.Now(),
		},
		Channel: "",
	}, nil
}

// readLogFileDarwin reads the last N lines from a log file.
func readLogFileDarwin(path string, maxLines int) ([]types.LogEntry, error) {
	// #nosec G304 -- path is from configuration or controlled input
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > maxLines*2 {
			lines = lines[len(lines)-maxLines*2:]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	var entries []types.LogEntry
	// macOS syslog pattern: Jan 15 10:30:45 hostname process[pid]: message
	pattern := regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)
	currentYear := time.Now().Year()

	for _, line := range lines {
		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			if line != "" {
				entries = append(entries, types.LogEntry{
					Timestamp: time.Now(),
					Source:    filepath.Base(path),
					Message:   line,
				})
			}
			continue
		}

		timestamp, _ := time.Parse("Jan 2 15:04:05 2006", matches[1]+" "+strconv.Itoa(currentYear))
		var pid int32
		if matches[4] != "" {
			p, _ := strconv.ParseInt(matches[4], 10, 32)
			pid = int32(p)
		}

		entries = append(entries, types.LogEntry{
			Timestamp: timestamp,
			Source:    matches[3],
			Message:   matches[5],
			PID:       pid,
			Fields: map[string]string{
				"hostname": matches[2],
				"file":     path,
			},
		})
	}

	return entries, nil
}
