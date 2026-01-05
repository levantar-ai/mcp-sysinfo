package gpu

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Error("NewCollector() returned nil")
	}
}

func TestGetGPUInfo(t *testing.T) {
	c := NewCollector()
	result, err := c.GetGPUInfo()
	if err != nil {
		t.Errorf("GetGPUInfo() error: %v", err)
		return
	}

	if result == nil {
		t.Error("GetGPUInfo() returned nil")
		return
	}

	// The result should have a timestamp
	if result.Timestamp.IsZero() {
		t.Error("GetGPUInfo() result has zero timestamp")
	}

	// Count should match GPUs slice length
	if result.Count != len(result.GPUs) {
		t.Errorf("GetGPUInfo() count mismatch: got %d, want %d", result.Count, len(result.GPUs))
	}

	// Verify GPU structure if any are found
	for i, gpu := range result.GPUs {
		if gpu.Index != i {
			// Re-indexed GPUs may not match
			t.Logf("GPU %d has index %d", i, gpu.Index)
		}

		// Vendor should be set
		if gpu.Vendor == "" && gpu.Name != "" {
			t.Logf("GPU %d has name but no vendor: %s", i, gpu.Name)
		}
	}
}

func TestParseMemory(t *testing.T) {
	tests := []struct {
		input    string
		expected uint64
	}{
		{"1024 MiB", 1024 * 1024 * 1024},
		{"8 GiB", 8 * 1024 * 1024 * 1024},
		{"1000 MB", 1000 * 1000 * 1000},
		{"1 GB", 1000 * 1000 * 1000},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseMemory(tt.input)
			if got != tt.expected {
				t.Errorf("parseMemory(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParsePercent(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"50 %", 50.0},
		{"100 %", 100.0},
		{"0 %", 0.0},
		{"33.5 %", 33.5},
		{"", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parsePercent(tt.input)
			if got != tt.expected {
				t.Errorf("parsePercent(%q) = %f, want %f", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseTemperature(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"65 C", 65.0},
		{"80 C", 80.0},
		{"45.5 C", 45.5},
		{"", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseTemperature(tt.input)
			if got != tt.expected {
				t.Errorf("parseTemperature(%q) = %f, want %f", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParsePower(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"150 W", 150.0},
		{"250 W", 250.0},
		{"85.5 W", 85.5},
		{"", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parsePower(tt.input)
			if got != tt.expected {
				t.Errorf("parsePower(%q) = %f, want %f", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseClock(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"1500 MHz", 1500},
		{"2000 MHz", 2000},
		{"850 MHz", 850},
		{"", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseClock(tt.input)
			if got != tt.expected {
				t.Errorf("parseClock(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestGetAMDDeviceName(t *testing.T) {
	tests := []struct {
		deviceID string
		contains string
	}{
		{"0x744c", "7900 XTX"},
		{"0x73df", "6700 XT"},
		{"0x1234", "AMD GPU"},
	}

	for _, tt := range tests {
		t.Run(tt.deviceID, func(t *testing.T) {
			got := getAMDDeviceName(tt.deviceID)
			if got == "" {
				t.Errorf("getAMDDeviceName(%q) returned empty string", tt.deviceID)
			}
		})
	}
}

func TestGetIntelDeviceName(t *testing.T) {
	tests := []struct {
		deviceID string
		contains string
	}{
		{"0x56a0", "Arc A770"},
		{"0x9a49", "Iris Xe"},
		{"0x1234", "Intel GPU"},
	}

	for _, tt := range tests {
		t.Run(tt.deviceID, func(t *testing.T) {
			got := getIntelDeviceName(tt.deviceID)
			if got == "" {
				t.Errorf("getIntelDeviceName(%q) returned empty string", tt.deviceID)
			}
		})
	}
}
