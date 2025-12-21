package windows

import (
	"testing"
	"time"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
}

// Test Registry Queries
func TestGetRegistryKey(t *testing.T) {
	c := NewCollector()
	result, err := c.GetRegistryKey("HKLM", "SOFTWARE\\Microsoft")
	if err != nil {
		t.Fatalf("GetRegistryKey returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetRegistryKey returned nil result")
	}
	if result.Hive != "HKLM" {
		t.Errorf("expected hive HKLM, got %s", result.Hive)
	}
	if result.Path != "SOFTWARE\\Microsoft" {
		t.Errorf("expected path SOFTWARE\\Microsoft, got %s", result.Path)
	}
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if result.Timestamp.After(time.Now()) {
		t.Error("Timestamp should not be in the future")
	}
}

func TestGetRegistryTree(t *testing.T) {
	c := NewCollector()
	result, err := c.GetRegistryTree("HKLM", "SOFTWARE", 2)
	if err != nil {
		t.Fatalf("GetRegistryTree returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetRegistryTree returned nil result")
	}
	if result.MaxDepth != 2 {
		t.Errorf("expected max depth 2, got %d", result.MaxDepth)
	}
}

func TestGetRegistrySecurity(t *testing.T) {
	c := NewCollector()
	result, err := c.GetRegistrySecurity("HKLM", "SOFTWARE")
	if err != nil {
		t.Fatalf("GetRegistrySecurity returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetRegistrySecurity returned nil result")
	}
	if result.DACL == nil {
		t.Error("DACL should not be nil")
	}
}

// Test DCOM/COM Queries
func TestGetDCOMApplications(t *testing.T) {
	c := NewCollector()
	result, err := c.GetDCOMApplications()
	if err != nil {
		t.Fatalf("GetDCOMApplications returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetDCOMApplications returned nil result")
	}
	if result.Applications == nil {
		t.Error("Applications should not be nil")
	}
}

func TestGetDCOMPermissions(t *testing.T) {
	c := NewCollector()
	result, err := c.GetDCOMPermissions("{00000000-0000-0000-0000-000000000000}")
	if err != nil {
		t.Fatalf("GetDCOMPermissions returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetDCOMPermissions returned nil result")
	}
}

func TestGetDCOMIdentities(t *testing.T) {
	c := NewCollector()
	result, err := c.GetDCOMIdentities()
	if err != nil {
		t.Fatalf("GetDCOMIdentities returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetDCOMIdentities returned nil result")
	}
	if result.Identities == nil {
		t.Error("Identities should not be nil")
	}
}

func TestGetCOMSecurityDefaults(t *testing.T) {
	c := NewCollector()
	result, err := c.GetCOMSecurityDefaults()
	if err != nil {
		t.Fatalf("GetCOMSecurityDefaults returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetCOMSecurityDefaults returned nil result")
	}
}

// Test IIS Queries
func TestGetIISSites(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIISSites()
	if err != nil {
		t.Fatalf("GetIISSites returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetIISSites returned nil result")
	}
	if result.Sites == nil {
		t.Error("Sites should not be nil")
	}
}

func TestGetIISAppPools(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIISAppPools()
	if err != nil {
		t.Fatalf("GetIISAppPools returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetIISAppPools returned nil result")
	}
	if result.AppPools == nil {
		t.Error("AppPools should not be nil")
	}
}

func TestGetIISBindings(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIISBindings()
	if err != nil {
		t.Fatalf("GetIISBindings returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetIISBindings returned nil result")
	}
	if result.Bindings == nil {
		t.Error("Bindings should not be nil")
	}
}

func TestGetIISVirtualDirs(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIISVirtualDirs()
	if err != nil {
		t.Fatalf("GetIISVirtualDirs returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetIISVirtualDirs returned nil result")
	}
	if result.Sites == nil {
		t.Error("Sites should not be nil")
	}
}

func TestGetIISHandlers(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIISHandlers()
	if err != nil {
		t.Fatalf("GetIISHandlers returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetIISHandlers returned nil result")
	}
	if result.Handlers == nil {
		t.Error("Handlers should not be nil")
	}
}

func TestGetIISModules(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIISModules()
	if err != nil {
		t.Fatalf("GetIISModules returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetIISModules returned nil result")
	}
	if result.GlobalModules == nil {
		t.Error("GlobalModules should not be nil")
	}
	if result.Modules == nil {
		t.Error("Modules should not be nil")
	}
}

func TestGetIISSSLCerts(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIISSSLCerts()
	if err != nil {
		t.Fatalf("GetIISSSLCerts returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetIISSSLCerts returned nil result")
	}
	if result.Certificates == nil {
		t.Error("Certificates should not be nil")
	}
}

func TestGetIISAuthConfig(t *testing.T) {
	c := NewCollector()
	result, err := c.GetIISAuthConfig()
	if err != nil {
		t.Fatalf("GetIISAuthConfig returned error: %v", err)
	}
	if result == nil {
		t.Fatal("GetIISAuthConfig returned nil result")
	}
	if result.Sites == nil {
		t.Error("Sites should not be nil")
	}
}
