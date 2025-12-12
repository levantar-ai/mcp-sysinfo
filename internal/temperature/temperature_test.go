package temperature

import (
	"testing"
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

	// Temperature sensors may or may not be available
	t.Logf("Found %d temperature sensors", len(info.Sensors))

	for _, sensor := range info.Sensors {
		t.Logf("  %s: %.1f°C", sensor.Name, sensor.Temperature)
		if sensor.High > 0 {
			t.Logf("    High threshold: %.1f°C", sensor.High)
		}
		if sensor.Critical > 0 {
			t.Logf("    Critical threshold: %.1f°C", sensor.Critical)
		}
	}

	if info.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestCollector_Collect_ValidTemperatures(t *testing.T) {
	c := NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	for _, sensor := range info.Sensors {
		// Temperature should be in a reasonable range
		// Note: VMs and some systems may report unusual values
		if sensor.Temperature < -273 || sensor.Temperature > 500 {
			t.Errorf("Sensor %s has invalid temperature: %.1f°C",
				sensor.Name, sensor.Temperature)
		}

		// Log warning for unusual but not invalid temperatures
		if sensor.Temperature < -50 || sensor.Temperature > 150 {
			t.Logf("Warning: Sensor %s has unusual temperature: %.1f°C (may be VM/emulated)",
				sensor.Name, sensor.Temperature)
		}

		// If thresholds are set, they should be reasonable
		if sensor.High > 0 && sensor.High < sensor.Temperature {
			t.Logf("Info: Sensor %s temperature %.1f°C exceeds high threshold %.1f°C",
				sensor.Name, sensor.Temperature, sensor.High)
		}
	}
}

func TestCollector_Collect_MultipleRuns(t *testing.T) {
	c := NewCollector()

	for i := 0; i < 5; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if info == nil {
			t.Errorf("Iteration %d: Collect returned nil", i)
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
