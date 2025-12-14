package security

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

func TestGetEnvVars(t *testing.T) {
	c := NewCollector()
	result, err := c.GetEnvVars()
	if err != nil {
		t.Fatalf("GetEnvVars failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetEnvVars returned nil")
	}
	if result.Count != len(result.Variables) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Variables))
	}
	// Should have at least PATH
	found := false
	for _, v := range result.Variables {
		if v.Name == "PATH" {
			found = true
			break
		}
	}
	if !found {
		t.Log("PATH not found in environment variables (may be expected in some environments)")
	}
}

func TestGetUserAccounts(t *testing.T) {
	c := NewCollector()
	result, err := c.GetUserAccounts()
	if err != nil {
		t.Fatalf("GetUserAccounts failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetUserAccounts returned nil")
	}
	if result.UserCount != len(result.Users) {
		t.Errorf("count mismatch: got %d, expected %d", result.UserCount, len(result.Users))
	}
}

func TestGetSudoConfig(t *testing.T) {
	c := NewCollector()
	result, err := c.GetSudoConfig()
	if err != nil {
		t.Fatalf("GetSudoConfig failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetSudoConfig returned nil")
	}
	if result.Count != len(result.Rules) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Rules))
	}
}

func TestGetSSHConfig(t *testing.T) {
	c := NewCollector()
	result, err := c.GetSSHConfig()
	if err != nil {
		t.Fatalf("GetSSHConfig failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetSSHConfig returned nil")
	}
}

func TestGetMACStatus(t *testing.T) {
	c := NewCollector()
	result, err := c.GetMACStatus()
	if err != nil {
		t.Fatalf("GetMACStatus failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetMACStatus returned nil")
	}
	if result.Type == "" {
		t.Error("Type should not be empty")
	}
}

func TestGetCertificates(t *testing.T) {
	c := NewCollector()
	result, err := c.GetCertificates()
	if err != nil {
		t.Fatalf("GetCertificates failed: %v", err)
	}
	if result == nil {
		t.Fatal("GetCertificates returned nil")
	}
	if result.Count != len(result.Certificates) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Certificates))
	}
}

// Benchmark tests
func BenchmarkGetEnvVars(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetEnvVars()
	}
}

func BenchmarkGetUserAccounts(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetUserAccounts()
	}
}

func BenchmarkGetCertificates(b *testing.B) {
	c := NewCollector()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = c.GetCertificates()
	}
}
