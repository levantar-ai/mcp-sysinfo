package cpu

import (
	"testing"
	"time"
)

func TestCalculatePercent(t *testing.T) {
	tests := []struct {
		name     string
		prev     *cpuTimes
		curr     *cpuTimes
		elapsed  time.Duration
		expected float64
		delta    float64 // Allowed delta for floating point comparison
	}{
		{
			name:     "nil previous returns 0",
			prev:     nil,
			curr:     &cpuTimes{User: 100, System: 50, Idle: 850},
			elapsed:  time.Second,
			expected: 0,
			delta:    0,
		},
		{
			name:     "zero elapsed returns 0",
			prev:     &cpuTimes{User: 100, System: 50, Idle: 850},
			curr:     &cpuTimes{User: 200, System: 100, Idle: 900},
			elapsed:  0,
			expected: 0,
			delta:    0,
		},
		{
			name:     "50% CPU usage",
			prev:     &cpuTimes{User: 0, System: 0, Idle: 0},
			curr:     &cpuTimes{User: 250, System: 250, Idle: 500},
			elapsed:  time.Second,
			expected: 50,
			delta:    0.1,
		},
		{
			name:     "100% CPU usage",
			prev:     &cpuTimes{User: 0, System: 0, Idle: 0},
			curr:     &cpuTimes{User: 500, System: 500, Idle: 0},
			elapsed:  time.Second,
			expected: 100,
			delta:    0.1,
		},
		{
			name:     "0% CPU usage (all idle)",
			prev:     &cpuTimes{User: 0, System: 0, Idle: 0},
			curr:     &cpuTimes{User: 0, System: 0, Idle: 1000},
			elapsed:  time.Second,
			expected: 0,
			delta:    0.1,
		},
		{
			name:     "incremental usage",
			prev:     &cpuTimes{User: 1000, System: 500, Idle: 8500},
			curr:     &cpuTimes{User: 1200, System: 600, Idle: 8700},
			elapsed:  time.Second,
			expected: 60, // (200+100) / (200+100+200) = 300/500 = 60%
			delta:    0.1,
		},
		{
			name: "with all fields",
			prev: &cpuTimes{
				User: 1000, System: 500, Idle: 8000,
				Nice: 100, IOWait: 200, IRQ: 50, SoftIRQ: 50, Steal: 100,
			},
			curr: &cpuTimes{
				User: 1100, System: 550, Idle: 8100,
				Nice: 110, IOWait: 220, IRQ: 55, SoftIRQ: 55, Steal: 110,
			},
			elapsed:  time.Second,
			expected: 66.67, // (300-100)/300 = 200/300 = 66.67%
			delta:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculatePercent(tt.prev, tt.curr, tt.elapsed)
			if tt.delta == 0 {
				if result != tt.expected {
					t.Errorf("expected %v, got %v", tt.expected, result)
				}
			} else {
				diff := result - tt.expected
				if diff < 0 {
					diff = -diff
				}
				if diff > tt.delta {
					t.Errorf("expected %v (±%v), got %v", tt.expected, tt.delta, result)
				}
			}
		})
	}
}

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Error("NewCollector returned nil")
	}
	if c.previousTimes != nil {
		t.Error("previousTimes should be nil initially")
	}
}

func TestCollector_Collect(t *testing.T) {
	c := NewCollector()

	// First collection - establishes baseline
	info1, err := c.Collect(false)
	if err != nil {
		t.Fatalf("first Collect failed: %v", err)
	}

	if info1 == nil {
		t.Fatal("Collect returned nil")
	}

	// Verify required fields are present
	if info1.Count <= 0 {
		t.Errorf("expected Count > 0, got %d", info1.Count)
	}
	if info1.PhysicalCount <= 0 {
		t.Errorf("expected PhysicalCount > 0, got %d", info1.PhysicalCount)
	}
	if info1.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Wait a bit and collect again
	time.Sleep(100 * time.Millisecond)

	info2, err := c.Collect(false)
	if err != nil {
		t.Fatalf("second Collect failed: %v", err)
	}

	// Percent should be between 0 and 100
	if info2.Percent < 0 || info2.Percent > 100 {
		t.Errorf("Percent should be 0-100, got %v", info2.Percent)
	}

	// Timestamp should be after first
	if !info2.Timestamp.After(info1.Timestamp) {
		t.Error("second Timestamp should be after first")
	}
}

func TestCollector_Collect_PerCPU(t *testing.T) {
	c := NewCollector()

	info, err := c.Collect(true)
	if err != nil {
		t.Fatalf("Collect with perCPU failed: %v", err)
	}

	// If perCPU is supported, verify the slice
	if info.PerCPU != nil {
		if len(info.PerCPU) == 0 {
			t.Error("PerCPU slice is empty")
		}
		for i, p := range info.PerCPU {
			if p < 0 || p > 100 {
				t.Errorf("PerCPU[%d] should be 0-100, got %v", i, p)
			}
		}
	}
}

func TestCollector_GetCoreCount(t *testing.T) {
	c := NewCollector()

	logical, physical, err := c.GetCoreCount()
	if err != nil {
		t.Fatalf("GetCoreCount failed: %v", err)
	}

	if logical <= 0 {
		t.Errorf("expected logical > 0, got %d", logical)
	}
	if physical <= 0 {
		t.Errorf("expected physical > 0, got %d", physical)
	}
	if physical > logical {
		t.Errorf("physical (%d) should be <= logical (%d)", physical, logical)
	}
}

func TestCollector_GetFrequency(t *testing.T) {
	c := NewCollector()

	freq, err := c.GetFrequency()
	if err != nil {
		// Frequency might not be available on all systems
		t.Logf("GetFrequency returned error (may be expected): %v", err)
		return
	}

	if freq == nil {
		t.Log("GetFrequency returned nil (may be expected on some systems)")
		return
	}

	// If we got frequency, it should be reasonable (100 MHz to 10 GHz)
	if freq.Current > 0 && (freq.Current < 100 || freq.Current > 10000) {
		t.Logf("Unusual frequency value: %v MHz", freq.Current)
	}
}

// Benchmark tests
func BenchmarkCollector_Collect(b *testing.B) {
	c := NewCollector()

	// Warmup
	_, _ = c.Collect(false)
	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Collect(false)
	}
}

func BenchmarkCollector_Collect_PerCPU(b *testing.B) {
	c := NewCollector()

	// Warmup
	_, _ = c.Collect(true)
	time.Sleep(10 * time.Millisecond)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.Collect(true)
	}
}
