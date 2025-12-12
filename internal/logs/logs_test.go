package logs

import (
	"testing"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestNormalizeQuery(t *testing.T) {
	tests := []struct {
		name     string
		input    *types.LogQuery
		expected int
	}{
		{
			name:     "nil query",
			input:    nil,
			expected: DefaultLines,
		},
		{
			name:     "zero lines",
			input:    &types.LogQuery{Lines: 0},
			expected: DefaultLines,
		},
		{
			name:     "negative lines",
			input:    &types.LogQuery{Lines: -10},
			expected: DefaultLines,
		},
		{
			name:     "exceeds max",
			input:    &types.LogQuery{Lines: 5000},
			expected: MaxLines,
		},
		{
			name:     "valid lines",
			input:    &types.LogQuery{Lines: 50},
			expected: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeQuery(tt.input)
			if result.Lines != tt.expected {
				t.Errorf("expected Lines=%d, got %d", tt.expected, result.Lines)
			}
		})
	}
}

func TestFilterEntries(t *testing.T) {
	entries := []types.LogEntry{
		{Message: "Error occurred in module", Source: "app"},
		{Message: "Warning: low memory", Source: "system"},
		{Message: "Info: startup complete", Source: "app"},
		{Message: "Error: connection failed", Source: "network"},
	}

	tests := []struct {
		name     string
		grep     string
		expected int
	}{
		{"empty grep", "", 4},
		{"match error", "error", 2},
		{"match warning", "warning", 1},
		{"match source", "network", 1},
		{"no match", "foobar", 0},
		{"case insensitive", "ERROR", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterEntries(entries, tt.grep)
			if len(result) != tt.expected {
				t.Errorf("expected %d entries, got %d", tt.expected, len(result))
			}
		})
	}
}

func TestTruncateEntries(t *testing.T) {
	entries := make([]types.LogEntry, 150)
	for i := range entries {
		entries[i] = types.LogEntry{Message: "test"}
	}

	tests := []struct {
		name          string
		maxLines      int
		expectedLen   int
		expectedTrunc bool
	}{
		{"no truncation needed", 200, 150, false},
		{"exact match", 150, 150, false},
		{"truncation required", 100, 100, true},
		{"small limit", 10, 10, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, truncated := truncateEntries(entries, tt.maxLines)
			if len(result) != tt.expectedLen {
				t.Errorf("expected len=%d, got %d", tt.expectedLen, len(result))
			}
			if truncated != tt.expectedTrunc {
				t.Errorf("expected truncated=%v, got %v", tt.expectedTrunc, truncated)
			}
		})
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s        string
		substr   string
		expected bool
	}{
		{"Hello World", "world", true},
		{"Hello World", "HELLO", true},
		{"Hello World", "foo", false},
		{"", "test", false},
		{"test", "", true},
		{"Error: Something failed", "error", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			result := containsIgnoreCase(tt.s, tt.substr)
			if result != tt.expected {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, result, tt.expected)
			}
		})
	}
}

func TestMakeLogResult(t *testing.T) {
	entries := []types.LogEntry{
		{Message: "test1"},
		{Message: "test2"},
	}

	result := makeLogResult(entries, "test-source", true)

	if result.Source != "test-source" {
		t.Errorf("expected source=test-source, got %s", result.Source)
	}
	if result.Count != 2 {
		t.Errorf("expected count=2, got %d", result.Count)
	}
	if !result.Truncated {
		t.Error("expected truncated=true")
	}
	if len(result.Entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(result.Entries))
	}
}

func TestGetJournalLogs(t *testing.T) {
	c := NewCollector()
	query := &types.LogQuery{Lines: 10}

	result, err := c.GetJournalLogs(query)
	if err != nil {
		t.Fatalf("GetJournalLogs failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetJournalLogs returned nil")
	}

	// Result might be empty on non-Linux or systems without journald
	// but should not error
	if result.Source != "journald" && result.Source != "" {
		t.Logf("Journal source: %s", result.Source)
	}
}

func TestGetSyslog(t *testing.T) {
	c := NewCollector()
	query := &types.LogQuery{Lines: 10}

	result, err := c.GetSyslog(query)
	if err != nil {
		t.Fatalf("GetSyslog failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetSyslog returned nil")
	}
}

func TestGetKernelLogs(t *testing.T) {
	c := NewCollector()
	query := &types.LogQuery{Lines: 10}

	result, err := c.GetKernelLogs(query)
	if err != nil {
		t.Fatalf("GetKernelLogs failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetKernelLogs returned nil")
	}
}

func TestGetAuthLogs(t *testing.T) {
	c := NewCollector()
	query := &types.LogQuery{Lines: 10}

	result, err := c.GetAuthLogs(query)
	if err != nil {
		t.Fatalf("GetAuthLogs failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetAuthLogs returned nil")
	}
}

func TestGetAppLogs(t *testing.T) {
	c := NewCollector()
	query := &types.AppLogQuery{
		LogQuery: types.LogQuery{Lines: 10},
	}

	result, err := c.GetAppLogs(query)
	if err != nil {
		t.Fatalf("GetAppLogs failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetAppLogs returned nil")
	}
}

func TestGetEventLog(t *testing.T) {
	c := NewCollector()
	query := &types.EventLogQuery{
		LogQuery: types.LogQuery{Lines: 10},
		Channel:  "System",
	}

	result, err := c.GetEventLog(query)
	if err != nil {
		t.Fatalf("GetEventLog failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetEventLog returned nil")
	}
}

func TestLogQueryTimeFilters(t *testing.T) {
	c := NewCollector()

	now := time.Now()
	query := &types.LogQuery{
		Lines: 10,
		Since: now.Add(-1 * time.Hour),
		Until: now,
	}

	// These should not panic
	_, _ = c.GetSyslog(query)
	_, _ = c.GetKernelLogs(query)
}

// Benchmark tests
func BenchmarkFilterEntries(b *testing.B) {
	entries := make([]types.LogEntry, 1000)
	for i := range entries {
		entries[i] = types.LogEntry{
			Message: "Error occurred in module during processing",
			Source:  "benchmark-source",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filterEntries(entries, "error")
	}
}

func BenchmarkGetSyslog(b *testing.B) {
	c := NewCollector()
	query := &types.LogQuery{Lines: 50}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetSyslog(query)
	}
}
