package disk

import (
	"testing"
)

func TestCalculatePercent(t *testing.T) {
	tests := []struct {
		name     string
		used     uint64
		total    uint64
		expected float64
	}{
		{
			name:     "zero total returns 0",
			used:     100,
			total:    0,
			expected: 0,
		},
		{
			name:     "zero used returns 0",
			used:     0,
			total:    1000,
			expected: 0,
		},
		{
			name:     "50% usage",
			used:     500,
			total:    1000,
			expected: 50,
		},
		{
			name:     "100% usage",
			used:     1000,
			total:    1000,
			expected: 100,
		},
		{
			name:     "realistic - 512GiB used of 1TiB",
			used:     512 * 1024 * 1024 * 1024,
			total:    1024 * 1024 * 1024 * 1024,
			expected: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculatePercent(tt.used, tt.total)
			delta := result - tt.expected
			if delta < 0 {
				delta = -delta
			}
			if delta > 0.01 {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBytesToHuman(t *testing.T) {
	tests := []struct {
		name          string
		bytes         uint64
		expectedValue float64
		expectedUnit  string
		delta         float64
	}{
		{
			name:          "bytes",
			bytes:         512,
			expectedValue: 512,
			expectedUnit:  "B",
			delta:         0,
		},
		{
			name:          "kilobytes",
			bytes:         1024,
			expectedValue: 1,
			expectedUnit:  "KB",
			delta:         0.01,
		},
		{
			name:          "gigabytes",
			bytes:         1024 * 1024 * 1024,
			expectedValue: 1,
			expectedUnit:  "GB",
			delta:         0.01,
		},
		{
			name:          "terabytes",
			bytes:         1024 * 1024 * 1024 * 1024,
			expectedValue: 1,
			expectedUnit:  "TB",
			delta:         0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, unit := bytesToHuman(tt.bytes)
			if unit != tt.expectedUnit {
				t.Errorf("expected unit %v, got %v", tt.expectedUnit, unit)
			}
			diff := value - tt.expectedValue
			if diff < 0 {
				diff = -diff
			}
			if diff > tt.delta {
				t.Errorf("expected value %v (±%v), got %v", tt.expectedValue, tt.delta, value)
			}
		})
	}
}

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

	// Should have at least one partition
	if len(info.Partitions) == 0 {
		t.Error("No partitions found")
	}

	// Check first partition
	for _, p := range info.Partitions {
		if p.Total == 0 {
			t.Errorf("Partition %s has 0 total", p.Device)
		}
		if p.UsedPercent < 0 || p.UsedPercent > 100 {
			t.Errorf("Partition %s has invalid UsedPercent: %v", p.Device, p.UsedPercent)
		}
		if p.Device == "" {
			t.Error("Partition has empty device name")
		}
		if p.Mountpoint == "" {
			t.Error("Partition has empty mountpoint")
		}

		t.Logf("Partition: %s on %s (%s) - %.1f%% used (%.2f GB / %.2f GB)",
			p.Device, p.Mountpoint, p.Fstype,
			p.UsedPercent,
			float64(p.Used)/(1024*1024*1024),
			float64(p.Total)/(1024*1024*1024))
	}

	if info.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestCollector_GetIOCounters(t *testing.T) {
	c := NewCollector()

	counters, err := c.GetIOCounters()
	if err != nil {
		t.Fatalf("GetIOCounters failed: %v", err)
	}

	if counters == nil {
		t.Fatal("GetIOCounters returned nil")
	}

	// Log I/O counters (may be empty on some platforms)
	for name, counter := range counters {
		t.Logf("Disk %s: Read=%d (%.2f MB), Write=%d (%.2f MB)",
			name,
			counter.ReadCount,
			float64(counter.ReadBytes)/(1024*1024),
			counter.WriteCount,
			float64(counter.WriteBytes)/(1024*1024))
	}
}

func TestCollector_Collect_MultipleRuns(t *testing.T) {
	c := NewCollector()

	// Run multiple times to ensure consistency
	for i := 0; i < 5; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if len(info.Partitions) == 0 {
			t.Errorf("Iteration %d: No partitions found", i)
		}
	}
}

// Benchmark tests
func BenchmarkCollector_Collect(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Collect()
	}
}

func BenchmarkCollector_GetIOCounters(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.GetIOCounters()
	}
}
