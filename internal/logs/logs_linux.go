//go:build linux

package logs

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Syslog paths on Linux
var syslogPaths = []string{
	"/var/log/syslog",
	"/var/log/messages",
}

// Auth log paths on Linux
var authLogPaths = []string{
	"/var/log/auth.log",
	"/var/log/secure",
}

// getJournalLogs retrieves systemd journal logs on Linux.
func (c *Collector) getJournalLogs(query *types.LogQuery) (*types.JournalLogResult, error) {
	query = normalizeQuery(query)

	// Check if journalctl exists
	journalctl, err := cmdexec.LookPath("journalctl")
	if err != nil {
		return &types.JournalLogResult{
			LogResult: types.LogResult{
				Entries:   []types.LogEntry{},
				Source:    "journald",
				Count:     0,
				Timestamp: time.Now(),
			},
		}, nil
	}

	// Build journalctl command
	args := []string{
		"--no-pager",
		"--output=short-iso",
		fmt.Sprintf("--lines=%d", query.Lines),
	}

	if !query.Since.IsZero() {
		args = append(args, fmt.Sprintf("--since=%s", query.Since.Format("2006-01-02 15:04:05")))
	}
	if !query.Until.IsZero() {
		args = append(args, fmt.Sprintf("--until=%s", query.Until.Format("2006-01-02 15:04:05")))
	}
	if query.Unit != "" {
		args = append(args, fmt.Sprintf("--unit=%s", query.Unit))
	}
	if query.Priority > 0 && query.Priority <= 7 {
		args = append(args, fmt.Sprintf("--priority=%d", query.Priority))
	}
	if query.Grep != "" {
		args = append(args, fmt.Sprintf("--grep=%s", query.Grep))
	}

	// #nosec G204 -- arguments are validated/sanitized
	cmd := cmdexec.Command(journalctl, args...)
	output, err := cmd.Output()
	if err != nil {
		// journalctl might fail if journal is empty or user lacks permissions
		return &types.JournalLogResult{
			LogResult: types.LogResult{
				Entries:   []types.LogEntry{},
				Source:    "journald",
				Count:     0,
				Timestamp: time.Now(),
			},
		}, nil
	}

	entries := parseJournalOutput(output)
	entries, truncated := truncateEntries(entries, query.Lines)

	return &types.JournalLogResult{
		LogResult: types.LogResult{
			Entries:   entries,
			Source:    "journald",
			Count:     len(entries),
			Truncated: truncated,
			Timestamp: time.Now(),
		},
	}, nil
}

// parseJournalOutput parses journalctl output.
func parseJournalOutput(output []byte) []types.LogEntry {
	var entries []types.LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Pattern: 2024-01-15T10:30:45+0000 hostname unit[pid]: message
	pattern := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		timestamp, _ := time.Parse("2006-01-02T15:04:05-0700", matches[1])
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

// getSyslog retrieves traditional syslog entries on Linux.
func (c *Collector) getSyslog(query *types.LogQuery) (*types.LogResult, error) {
	query = normalizeQuery(query)

	// Find available syslog file
	var logPath string
	for _, path := range syslogPaths {
		if _, err := os.Stat(path); err == nil {
			logPath = path
			break
		}
	}

	if logPath == "" {
		return makeLogResult([]types.LogEntry{}, "syslog", false), nil
	}

	entries, err := readLogFile(logPath, query.Lines*2) // Read extra for filtering
	if err != nil {
		return makeLogResult([]types.LogEntry{}, "syslog", false), nil
	}

	// Apply grep filter
	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}

	entries, truncated := truncateEntries(entries, query.Lines)
	return makeLogResult(entries, "syslog", truncated), nil
}

// getKernelLogs retrieves kernel/dmesg logs on Linux.
func (c *Collector) getKernelLogs(query *types.LogQuery) (*types.KernelLogResult, error) {
	query = normalizeQuery(query)

	// Try dmesg command first
	dmesg, err := cmdexec.LookPath("dmesg")
	if err == nil {
		// #nosec G204 -- dmesg path is from LookPath
		cmd := cmdexec.Command(dmesg, "--time-format=iso", "--nopager")
		output, err := cmd.Output()
		if err == nil {
			entries := parseDmesgOutput(output)
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
	}

	// Fallback: read /var/log/kern.log or /var/log/dmesg
	kernLogPaths := []string{"/var/log/kern.log", "/var/log/dmesg"}
	for _, path := range kernLogPaths {
		if _, err := os.Stat(path); err == nil {
			entries, err := readLogFile(path, query.Lines*2)
			if err == nil {
				if query.Grep != "" {
					entries = filterEntries(entries, query.Grep)
				}
				entries, truncated := truncateEntries(entries, query.Lines)

				return &types.KernelLogResult{
					LogResult: types.LogResult{
						Entries:   entries,
						Source:    "kern.log",
						Count:     len(entries),
						Truncated: truncated,
						Timestamp: time.Now(),
					},
				}, nil
			}
		}
	}

	return &types.KernelLogResult{
		LogResult: types.LogResult{
			Entries:   []types.LogEntry{},
			Source:    "dmesg",
			Count:     0,
			Timestamp: time.Now(),
		},
	}, nil
}

// parseDmesgOutput parses dmesg output with ISO timestamps.
func parseDmesgOutput(output []byte) []types.LogEntry {
	var entries []types.LogEntry
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Pattern: 2024-01-15T10:30:45,123456+00:00 message
	pattern := regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}),\d+[+-]\d{2}:\d{2}\s+(.*)$`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			// Try simpler format without timestamp
			if line != "" {
				entries = append(entries, types.LogEntry{
					Timestamp: time.Now(),
					Source:    "kernel",
					Message:   line,
				})
			}
			continue
		}

		timestamp, _ := time.Parse("2006-01-02T15:04:05", matches[1])
		entries = append(entries, types.LogEntry{
			Timestamp: timestamp,
			Source:    "kernel",
			Message:   matches[2],
		})
	}

	return entries
}

// getAuthLogs retrieves authentication logs on Linux.
func (c *Collector) getAuthLogs(query *types.LogQuery) (*types.AuthLogResult, error) {
	query = normalizeQuery(query)

	// Find available auth log file
	var logPath string
	for _, path := range authLogPaths {
		if _, err := os.Stat(path); err == nil {
			logPath = path
			break
		}
	}

	if logPath == "" {
		// Try journalctl as fallback
		journalctl, err := cmdexec.LookPath("journalctl")
		if err == nil {
			args := []string{
				"--no-pager",
				"--output=short-iso",
				fmt.Sprintf("--lines=%d", query.Lines),
				"_COMM=sshd",
			}
			// #nosec G204 -- arguments are validated
			cmd := cmdexec.Command(journalctl, args...)
			output, err := cmd.Output()
			if err == nil {
				entries := parseJournalOutput(output)
				if query.Grep != "" {
					entries = filterEntries(entries, query.Grep)
				}
				entries, truncated := truncateEntries(entries, query.Lines)
				failed, success := countAuthEvents(entries)

				return &types.AuthLogResult{
					LogResult: types.LogResult{
						Entries:   entries,
						Source:    "journald",
						Count:     len(entries),
						Truncated: truncated,
						Timestamp: time.Now(),
					},
					FailedLogins:     failed,
					SuccessfulLogins: success,
				}, nil
			}
		}

		return &types.AuthLogResult{
			LogResult: types.LogResult{
				Entries:   []types.LogEntry{},
				Source:    "auth",
				Count:     0,
				Timestamp: time.Now(),
			},
		}, nil
	}

	entries, err := readLogFile(logPath, query.Lines*2)
	if err != nil {
		return &types.AuthLogResult{
			LogResult: types.LogResult{
				Entries:   []types.LogEntry{},
				Source:    "auth",
				Count:     0,
				Timestamp: time.Now(),
			},
		}, nil
	}

	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}
	entries, truncated := truncateEntries(entries, query.Lines)
	failed, success := countAuthEvents(entries)

	return &types.AuthLogResult{
		LogResult: types.LogResult{
			Entries:   entries,
			Source:    filepath.Base(logPath),
			Count:     len(entries),
			Truncated: truncated,
			Timestamp: time.Now(),
		},
		FailedLogins:     failed,
		SuccessfulLogins: success,
	}, nil
}

// countAuthEvents counts failed and successful login attempts.
func countAuthEvents(entries []types.LogEntry) (failed, success int) {
	for _, e := range entries {
		msg := toLower(e.Message)
		if contains(msg, "failed") || contains(msg, "invalid") || contains(msg, "authentication failure") {
			failed++
		} else if contains(msg, "accepted") || contains(msg, "session opened") {
			success++
		}
	}
	return
}

// getAppLogs retrieves application-specific logs on Linux.
func (c *Collector) getAppLogs(query *types.AppLogQuery) (*types.LogResult, error) {
	if query == nil {
		query = &types.AppLogQuery{}
	}
	query.LogQuery = *normalizeQuery(&query.LogQuery)

	var entries []types.LogEntry

	// Handle specific paths
	if query.Path != "" {
		e, err := readLogFile(query.Path, query.Lines*2)
		if err == nil {
			entries = append(entries, e...)
		}
	}

	// Handle multiple paths
	for _, path := range query.Paths {
		e, err := readLogFile(path, query.Lines)
		if err == nil {
			entries = append(entries, e...)
		}
	}

	// Handle glob pattern
	if query.Pattern != "" {
		matches, err := filepath.Glob(query.Pattern)
		if err == nil {
			for _, path := range matches {
				e, err := readLogFile(path, query.Lines/len(matches)+1)
				if err == nil {
					entries = append(entries, e...)
				}
			}
		}
	}

	// Default: check common app log locations
	if query.Path == "" && len(query.Paths) == 0 && query.Pattern == "" {
		defaultPaths := []string{
			"/var/log/nginx/access.log",
			"/var/log/nginx/error.log",
			"/var/log/apache2/access.log",
			"/var/log/apache2/error.log",
			"/var/log/httpd/access_log",
			"/var/log/httpd/error_log",
		}
		for _, path := range defaultPaths {
			if _, err := os.Stat(path); err == nil {
				e, err := readLogFile(path, query.Lines/2)
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

// getEventLog returns empty result on Linux (Windows only).
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

// readLogFile reads the last N lines from a log file.
func readLogFile(path string, maxLines int) ([]types.LogEntry, error) {
	// #nosec G304 -- path is from configuration or controlled input
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read all lines (for small files) or tail
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > maxLines*2 {
			// Keep only last maxLines*2 lines to avoid memory issues
			lines = lines[len(lines)-maxLines*2:]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Take last maxLines
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	// Parse syslog format
	var entries []types.LogEntry
	// Pattern: Jan 15 10:30:45 hostname process[pid]: message
	pattern := regexp.MustCompile(`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)
	currentYear := time.Now().Year()

	for _, line := range lines {
		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			// If no match, add as raw entry
			if line != "" {
				entries = append(entries, types.LogEntry{
					Timestamp: time.Now(),
					Source:    filepath.Base(path),
					Message:   line,
				})
			}
			continue
		}

		// Parse timestamp (add current year)
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
