package uptime

import (
	"testing"
	"time"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Error("NewCollector returned nil")
	}
}

func TestCollector_Collect(t *testing.T) {
	c := NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if info == nil {
		t.Fatal("Collect returned nil")
	}

	// Uptime should be positive
	if info.Uptime <= 0 {
		t.Error("Uptime should be positive")
	}

	// Boot time should be in the past
	if info.BootTime.After(time.Now()) {
		t.Error("Boot time should be in the past")
	}

	// Uptime string should not be empty
	if info.UptimeStr == "" {
		t.Error("UptimeStr should not be empty")
	}

	t.Logf("Uptime: %v", info.Uptime)
	t.Logf("Boot Time: %v", info.BootTime)
	t.Logf("Uptime String: %s", info.UptimeStr)

	if info.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestCollector_Collect_Consistency(t *testing.T) {
	c := NewCollector()

	info1, err := c.Collect()
	if err != nil {
		t.Fatalf("First collect failed: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	info2, err := c.Collect()
	if err != nil {
		t.Fatalf("Second collect failed: %v", err)
	}

	// Uptime should have increased
	if info2.Uptime <= info1.Uptime {
		t.Error("Uptime should increase over time")
	}

	// Boot time should be nearly the same (within 1 second tolerance)
	diff := info2.BootTime.Sub(info1.BootTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Second {
		t.Errorf("Boot time changed too much: %v", diff)
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		contains string
	}{
		{
			name:     "seconds only",
			duration: 45 * time.Second,
			contains: "45 seconds",
		},
		{
			name:     "minutes and seconds",
			duration: 5*time.Minute + 30*time.Second,
			contains: "5 minutes",
		},
		{
			name:     "hours",
			duration: 3*time.Hour + 15*time.Minute,
			contains: "3 hours",
		},
		{
			name:     "days",
			duration: 2*24*time.Hour + 5*time.Hour,
			contains: "2 days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatUptime(tt.duration)
			if result == "" {
				t.Error("formatUptime returned empty string")
			}
			t.Logf("%v -> %s", tt.duration, result)
		})
	}
}

func TestCollector_Collect_MultipleRuns(t *testing.T) {
	c := NewCollector()

	for i := 0; i < 5; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if info.Uptime <= 0 {
			t.Errorf("Iteration %d: Invalid uptime", i)
		}
	}
}

// Benchmark tests
func BenchmarkCollector_Collect(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Collect()
	}
}
