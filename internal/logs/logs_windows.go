//go:build windows

package logs

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Event represents a Windows Event Log entry (XML format).
type Event struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     int `xml:"EventID"`
		Level       int `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		Computer string `xml:"Computer"`
	} `xml:"System"`
	EventData struct {
		Data []string `xml:"Data"`
	} `xml:"EventData"`
	RenderingInfo struct {
		Message string `xml:"Message"`
		Level   string `xml:"Level"`
	} `xml:"RenderingInfo"`
}

// getJournalLogs returns empty result on Windows (Linux only).
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

// getSyslog returns empty result on Windows (Unix only).
func (c *Collector) getSyslog(query *types.LogQuery) (*types.LogResult, error) {
	return makeLogResult([]types.LogEntry{}, "syslog", false), nil
}

// getKernelLogs retrieves kernel-related events from System event log on Windows.
func (c *Collector) getKernelLogs(query *types.LogQuery) (*types.KernelLogResult, error) {
	query = normalizeQuery(query)

	// Query System log for kernel-related events
	eventQuery := &types.EventLogQuery{
		LogQuery: *query,
		Channel:  "System",
	}

	result, err := c.getEventLog(eventQuery)
	if err != nil {
		return &types.KernelLogResult{
			LogResult: types.LogResult{
				Entries:   []types.LogEntry{},
				Source:    "eventlog",
				Count:     0,
				Timestamp: time.Now(),
			},
		}, nil
	}

	return &types.KernelLogResult{
		LogResult: result.LogResult,
	}, nil
}

// getAuthLogs retrieves authentication events from Security event log on Windows.
func (c *Collector) getAuthLogs(query *types.LogQuery) (*types.AuthLogResult, error) {
	query = normalizeQuery(query)

	// Query Security log for logon events
	// Event IDs: 4624 (logon), 4625 (failed logon), 4634 (logoff)
	eventQuery := &types.EventLogQuery{
		LogQuery: *query,
		Channel:  "Security",
	}

	result, err := c.getEventLog(eventQuery)
	if err != nil {
		return &types.AuthLogResult{
			LogResult: types.LogResult{
				Entries:   []types.LogEntry{},
				Source:    "eventlog",
				Count:     0,
				Timestamp: time.Now(),
			},
		}, nil
	}

	failed, success := countAuthEventsWindows(result.Entries)

	return &types.AuthLogResult{
		LogResult:        result.LogResult,
		FailedLogins:     failed,
		SuccessfulLogins: success,
	}, nil
}

// countAuthEventsWindows counts failed and successful login attempts from Windows events.
func countAuthEventsWindows(entries []types.LogEntry) (failed, success int) {
	for _, e := range entries {
		// Check event ID in fields
		if eventID, ok := e.Fields["event_id"]; ok {
			switch eventID {
			case "4624": // Successful logon
				success++
			case "4625": // Failed logon
				failed++
			}
		}
		// Fallback to message content
		msg := toLower(e.Message)
		if contains(msg, "failed") || contains(msg, "failure") {
			failed++
		} else if contains(msg, "success") {
			success++
		}
	}
	return
}

// getAppLogs retrieves application event log entries on Windows.
func (c *Collector) getAppLogs(query *types.AppLogQuery) (*types.LogResult, error) {
	if query == nil {
		query = &types.AppLogQuery{}
	}
	query.LogQuery = *normalizeQuery(&query.LogQuery)

	var entries []types.LogEntry

	// Handle specific file paths (text log files)
	if query.Path != "" {
		e, err := readLogFileWindows(query.Path, query.Lines*2)
		if err == nil {
			entries = append(entries, e...)
		}
	}

	for _, path := range query.Paths {
		e, err := readLogFileWindows(path, query.Lines)
		if err == nil {
			entries = append(entries, e...)
		}
	}

	if query.Pattern != "" {
		matches, _ := filepath.Glob(query.Pattern)
		for _, path := range matches {
			e, err := readLogFileWindows(path, query.Lines/len(matches)+1)
			if err == nil {
				entries = append(entries, e...)
			}
		}
	}

	// Default: query Application event log
	if query.Path == "" && len(query.Paths) == 0 && query.Pattern == "" {
		eventQuery := &types.EventLogQuery{
			LogQuery: query.LogQuery,
			Channel:  "Application",
		}
		result, err := c.getEventLog(eventQuery)
		if err == nil {
			entries = result.Entries
		}
	}

	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}

	entries, truncated := truncateEntries(entries, query.Lines)
	return makeLogResult(entries, "app", truncated), nil
}

// getEventLog retrieves Windows Event Log entries.
func (c *Collector) getEventLog(query *types.EventLogQuery) (*types.EventLogResult, error) {
	if query == nil {
		query = &types.EventLogQuery{}
	}
	query.LogQuery = *normalizeQuery(&query.LogQuery)

	channel := query.Channel
	if channel == "" {
		channel = "System"
	}

	// Build wevtutil query
	args := []string{
		"qe", channel,
		"/c:" + strconv.Itoa(query.Lines),
		"/rd:true", // Reverse direction (newest first)
		"/f:xml",   // XML format
	}

	// Build XPath query for filtering
	var xpathFilters []string
	if query.Level > 0 && query.Level <= 5 {
		xpathFilters = append(xpathFilters, fmt.Sprintf("Level=%d", query.Level))
	}
	if query.EventID > 0 {
		xpathFilters = append(xpathFilters, fmt.Sprintf("EventID=%d", query.EventID))
	}
	if query.Provider != "" {
		xpathFilters = append(xpathFilters, fmt.Sprintf("Provider[@Name='%s']", query.Provider))
	}
	if !query.Since.IsZero() {
		xpathFilters = append(xpathFilters, fmt.Sprintf("TimeCreated[@SystemTime>='%s']", query.Since.UTC().Format(time.RFC3339)))
	}

	if len(xpathFilters) > 0 {
		xpath := fmt.Sprintf("*[System[%s]]", strings.Join(xpathFilters, " and "))
		args = append(args, "/q:"+xpath)
	}

	// #nosec G204 -- wevtutil path is from system
	cmd := cmdexec.Command("wevtutil", args...)
	output, err := cmd.Output()
	if err != nil {
		// Try PowerShell as fallback
		return c.getEventLogPowerShell(query, channel)
	}

	entries := parseEventLogXML(output, channel)
	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}
	entries, truncated := truncateEntries(entries, query.Lines)

	return &types.EventLogResult{
		LogResult: types.LogResult{
			Entries:   entries,
			Source:    "eventlog",
			Count:     len(entries),
			Truncated: truncated,
			Timestamp: time.Now(),
		},
		Channel: channel,
	}, nil
}

// parseEventLogXML parses wevtutil XML output.
func parseEventLogXML(output []byte, channel string) []types.LogEntry {
	var entries []types.LogEntry

	// Split by Event tags and parse each
	events := bytes.Split(output, []byte("</Event>"))
	for _, eventData := range events {
		if len(eventData) < 10 {
			continue
		}
		// Add closing tag back for parsing
		eventData = append(eventData, []byte("</Event>")...)

		// Find start of Event tag
		start := bytes.Index(eventData, []byte("<Event"))
		if start < 0 {
			continue
		}
		eventData = eventData[start:]

		var event Event
		if err := xml.Unmarshal(eventData, &event); err != nil {
			continue
		}

		timestamp, _ := time.Parse(time.RFC3339Nano, event.System.TimeCreated.SystemTime)

		message := event.RenderingInfo.Message
		if message == "" && len(event.EventData.Data) > 0 {
			message = strings.Join(event.EventData.Data, " | ")
		}

		level := levelToString(event.System.Level)
		if event.RenderingInfo.Level != "" {
			level = event.RenderingInfo.Level
		}

		entries = append(entries, types.LogEntry{
			Timestamp: timestamp,
			Source:    event.System.Provider.Name,
			Level:     level,
			Message:   message,
			Fields: map[string]string{
				"event_id": strconv.Itoa(event.System.EventID),
				"computer": event.System.Computer,
				"channel":  channel,
			},
		})
	}

	return entries
}

// levelToString converts Windows event level to string.
func levelToString(level int) string {
	switch level {
	case 1:
		return "critical"
	case 2:
		return "error"
	case 3:
		return "warning"
	case 4:
		return "info"
	case 5:
		return "verbose"
	default:
		return "unknown"
	}
}

// getEventLogPowerShell uses PowerShell as fallback.
func (c *Collector) getEventLogPowerShell(query *types.EventLogQuery, channel string) (*types.EventLogResult, error) {
	psCmd := fmt.Sprintf("Get-WinEvent -LogName '%s' -MaxEvents %d | Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message | ConvertTo-Json", channel, query.Lines)

	// #nosec G204 -- powershell path is from system
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return &types.EventLogResult{
			LogResult: types.LogResult{
				Entries:   []types.LogEntry{},
				Source:    "eventlog",
				Count:     0,
				Timestamp: time.Now(),
			},
			Channel: channel,
		}, nil
	}

	entries := parsePowerShellEventLog(output)
	if query.Grep != "" {
		entries = filterEntries(entries, query.Grep)
	}
	entries, truncated := truncateEntries(entries, query.Lines)

	return &types.EventLogResult{
		LogResult: types.LogResult{
			Entries:   entries,
			Source:    "eventlog",
			Count:     len(entries),
			Truncated: truncated,
			Timestamp: time.Now(),
		},
		Channel: channel,
	}, nil
}

// parsePowerShellEventLog parses PowerShell JSON output.
func parsePowerShellEventLog(output []byte) []types.LogEntry {
	// Simple JSON parsing for PowerShell output
	var entries []types.LogEntry

	// Handle both array and single object
	content := strings.TrimSpace(string(output))
	if content == "" || content == "null" {
		return entries
	}

	// Very basic parsing - look for patterns
	lines := strings.Split(content, "\n")
	var currentEntry types.LogEntry
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "TimeCreated") {
			// Extract timestamp
			if idx := strings.Index(line, ":"); idx > 0 {
				ts := strings.Trim(line[idx+1:], `", `)
				currentEntry.Timestamp, _ = time.Parse("2006-01-02T15:04:05", ts[:19])
			}
		} else if strings.Contains(line, "ProviderName") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentEntry.Source = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "LevelDisplayName") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentEntry.Level = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "Message") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentEntry.Message = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "}") {
			if currentEntry.Source != "" {
				entries = append(entries, currentEntry)
			}
			currentEntry = types.LogEntry{}
		}
	}

	return entries
}

// readLogFileWindows reads the last N lines from a text log file.
func readLogFileWindows(path string, maxLines int) ([]types.LogEntry, error) {
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

	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}

	var entries []types.LogEntry
	for _, line := range lines {
		if line == "" {
			continue
		}
		entries = append(entries, types.LogEntry{
			Timestamp: time.Now(),
			Source:    filepath.Base(path),
			Message:   line,
		})
	}

	return entries, nil
}
