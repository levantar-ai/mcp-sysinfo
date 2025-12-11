package memory

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
			name:     "25% usage",
			used:     256,
			total:    1024,
			expected: 25,
		},
		{
			name:     "realistic values - 8GB total, 4GB used",
			used:     4 * 1024 * 1024 * 1024,
			total:    8 * 1024 * 1024 * 1024,
			expected: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculatePercent(tt.used, tt.total)
			if result != tt.expected {
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
			name:          "megabytes",
			bytes:         1024 * 1024,
			expectedValue: 1,
			expectedUnit:  "MB",
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
			name:          "8 gigabytes",
			bytes:         8 * 1024 * 1024 * 1024,
			expectedValue: 8,
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

	// Basic sanity checks
	if info.Total == 0 {
		t.Error("Total memory should not be 0")
	}

	if info.Total < info.Used {
		t.Errorf("Total (%d) should be >= Used (%d)", info.Total, info.Used)
	}

	if info.UsedPercent < 0 || info.UsedPercent > 100 {
		t.Errorf("UsedPercent should be 0-100, got %v", info.UsedPercent)
	}

	if info.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	t.Logf("Memory: Total=%d, Used=%d (%.1f%%), Available=%d, Free=%d",
		info.Total, info.Used, info.UsedPercent, info.Available, info.Free)
}

func TestCollector_GetSwap(t *testing.T) {
	c := NewCollector()

	swap, err := c.GetSwap()
	if err != nil {
		t.Fatalf("GetSwap failed: %v", err)
	}

	if swap == nil {
		t.Fatal("GetSwap returned nil")
	}

	// Swap may be 0 on some systems, but should be consistent
	if swap.Total > 0 {
		if swap.Total < swap.Used {
			t.Errorf("Swap Total (%d) should be >= Used (%d)", swap.Total, swap.Used)
		}
		if swap.UsedPercent < 0 || swap.UsedPercent > 100 {
			t.Errorf("Swap UsedPercent should be 0-100, got %v", swap.UsedPercent)
		}
	}

	t.Logf("Swap: Total=%d, Used=%d (%.1f%%), Free=%d",
		swap.Total, swap.Used, swap.UsedPercent, swap.Free)
}

func TestCollector_Collect_MultipleRuns(t *testing.T) {
	c := NewCollector()

	// Run multiple times to ensure consistency
	for i := 0; i < 5; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if info.Total == 0 {
			t.Errorf("Iteration %d: Total memory is 0", i)
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

func BenchmarkCollector_GetSwap(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.GetSwap()
	}
}
