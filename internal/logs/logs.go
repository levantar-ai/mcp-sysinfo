// Package logs provides log collection across platforms.
package logs

import (
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

const (
	// DefaultLines is the default number of log lines to return.
	DefaultLines = 100
	// MaxLines is the maximum number of log lines to return.
	MaxLines = 1000
)

// Collector collects log entries from various sources.
type Collector struct{}

// NewCollector creates a new log collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetJournalLogs retrieves systemd journal logs (Linux only).
// On other platforms, returns an empty result.
func (c *Collector) GetJournalLogs(query *types.LogQuery) (*types.JournalLogResult, error) {
	return c.getJournalLogs(query)
}

// GetSyslog retrieves traditional syslog entries (Linux/macOS).
// On Windows, returns an empty result.
func (c *Collector) GetSyslog(query *types.LogQuery) (*types.LogResult, error) {
	return c.getSyslog(query)
}

// GetKernelLogs retrieves kernel/dmesg logs.
func (c *Collector) GetKernelLogs(query *types.LogQuery) (*types.KernelLogResult, error) {
	return c.getKernelLogs(query)
}

// GetAuthLogs retrieves authentication logs (sensitive).
// This includes SSH logins, sudo usage, PAM events, etc.
func (c *Collector) GetAuthLogs(query *types.LogQuery) (*types.AuthLogResult, error) {
	return c.getAuthLogs(query)
}

// GetAppLogs retrieves application-specific logs.
func (c *Collector) GetAppLogs(query *types.AppLogQuery) (*types.LogResult, error) {
	return c.getAppLogs(query)
}

// GetEventLog retrieves Windows Event Log entries (Windows only).
// On other platforms, returns an empty result.
func (c *Collector) GetEventLog(query *types.EventLogQuery) (*types.EventLogResult, error) {
	return c.getEventLog(query)
}

// normalizeQuery sets default values for a log query.
func normalizeQuery(query *types.LogQuery) *types.LogQuery {
	if query == nil {
		query = &types.LogQuery{}
	}
	if query.Lines <= 0 {
		query.Lines = DefaultLines
	}
	if query.Lines > MaxLines {
		query.Lines = MaxLines
	}
	return query
}

// filterEntries applies grep filter to log entries.
func filterEntries(entries []types.LogEntry, grep string) []types.LogEntry {
	if grep == "" {
		return entries
	}
	filtered := make([]types.LogEntry, 0)
	for _, e := range entries {
		if containsIgnoreCase(e.Message, grep) ||
			containsIgnoreCase(e.Source, grep) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// containsIgnoreCase checks if s contains substr (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	if substr == "" {
		return true
	}
	// Simple case-insensitive contains
	sLower := toLower(s)
	substrLower := toLower(substr)
	return contains(sLower, substrLower)
}

// toLower converts a string to lowercase (ASCII only for speed).
func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (substr == "" || findSubstring(s, substr) >= 0)
}

// findSubstring finds the index of substr in s, or -1 if not found.
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// truncateEntries limits entries to maxLines and sets truncated flag.
func truncateEntries(entries []types.LogEntry, maxLines int) ([]types.LogEntry, bool) {
	if len(entries) <= maxLines {
		return entries, false
	}
	return entries[:maxLines], true
}

// makeLogResult creates a LogResult from entries.
func makeLogResult(entries []types.LogEntry, source string, truncated bool) *types.LogResult {
	return &types.LogResult{
		Entries:   entries,
		Source:    source,
		Count:     len(entries),
		Truncated: truncated,
		Timestamp: time.Now(),
	}
}
