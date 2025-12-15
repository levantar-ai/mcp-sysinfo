package osinfo

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetOSInfo(t *testing.T) {
	c := NewCollector()
	result, err := c.GetOSInfo()
	if err != nil {
		t.Fatalf("GetOSInfo failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetOSInfo returned nil result")
	}

	// Basic validation
	if result.Platform == "" {
		t.Error("Platform should not be empty")
	}

	if result.KernelVersion == "" {
		t.Error("KernelVersion should not be empty")
	}

	if result.KernelArch == "" {
		t.Error("KernelArch should not be empty")
	}

	if result.Hostname == "" {
		t.Error("Hostname should not be empty")
	}

	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Platform-specific validation
	validPlatforms := []string{"linux", "darwin", "windows"}
	found := false
	for _, p := range validPlatforms {
		if result.Platform == p {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Platform '%s' is not a valid platform", result.Platform)
	}

	// Boot mode validation
	if result.BootMode != "" && result.BootMode != "UEFI" && result.BootMode != "BIOS" {
		t.Errorf("Invalid BootMode: %s", result.BootMode)
	}
}

func TestGetSystemProfile(t *testing.T) {
	c := NewCollector()
	result, err := c.GetSystemProfile()
	if err != nil {
		t.Fatalf("GetSystemProfile failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetSystemProfile returned nil result")
	}

	// Validate CPU summary
	if result.CPU.LogicalCores <= 0 {
		t.Error("CPU LogicalCores should be positive")
	}

	// Validate Memory summary
	if result.Memory.TotalGB <= 0 {
		t.Error("Memory TotalGB should be positive")
	}

	if result.Memory.UsagePercent < 0 || result.Memory.UsagePercent > 100 {
		t.Errorf("Memory UsagePercent out of range: %f", result.Memory.UsagePercent)
	}

	// Validate Disk summary
	if result.Disk.TotalGB < 0 {
		t.Error("Disk TotalGB should not be negative")
	}

	// Validate Network summary
	if result.Network.Hostname == "" {
		t.Error("Network Hostname should not be empty")
	}

	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestGetServiceManagerInfo(t *testing.T) {
	c := NewCollector()
	result, err := c.GetServiceManagerInfo()
	if err != nil {
		t.Fatalf("GetServiceManagerInfo failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetServiceManagerInfo returned nil result")
	}

	// Service manager type should be set
	if result.Type == "" {
		t.Error("Service manager Type should not be empty")
	}

	// Valid service manager types
	validTypes := []string{"systemd", "launchd", "scm", "sysvinit"}
	found := false
	for _, st := range validTypes {
		if result.Type == st {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Unknown service manager type: %s", result.Type)
	}

	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestGetCloudEnvironment(t *testing.T) {
	c := NewCollector()
	result, err := c.GetCloudEnvironment()
	if err != nil {
		t.Fatalf("GetCloudEnvironment failed: %v", err)
	}

	if result == nil {
		t.Fatal("GetCloudEnvironment returned nil result")
	}

	// If cloud is detected, provider should be set
	if result.IsCloud && result.Provider == "" {
		t.Error("If IsCloud is true, Provider should be set")
	}

	// Valid cloud providers
	if result.Provider != "" {
		validProviders := []string{"aws", "gcp", "azure", "digitalocean", "oci"}
		found := false
		for _, p := range validProviders {
			if result.Provider == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Unknown cloud provider: %s", result.Provider)
		}
	}

	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}
