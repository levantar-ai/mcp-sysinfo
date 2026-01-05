package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCertManager_EnsureCert(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "mcp-sysinfo-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create cert manager
	cm, err := NewCertManager(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create CertManager: %v", err)
	}

	// Ensure cert is generated
	certInfo, err := cm.EnsureCert([]string{"test.example.com", "192.168.1.1"})
	if err != nil {
		t.Fatalf("EnsureCert failed: %v", err)
	}

	// Verify paths
	if certInfo.CertPath != filepath.Join(tmpDir, "agent.crt") {
		t.Errorf("Unexpected cert path: %s", certInfo.CertPath)
	}
	if certInfo.KeyPath != filepath.Join(tmpDir, "agent.key") {
		t.Errorf("Unexpected key path: %s", certInfo.KeyPath)
	}

	// Verify files exist
	if _, err := os.Stat(certInfo.CertPath); os.IsNotExist(err) {
		t.Error("Certificate file was not created")
	}
	if _, err := os.Stat(certInfo.KeyPath); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Verify public cert is populated
	if certInfo.PublicCert == "" {
		t.Error("PublicCert is empty")
	}
	if certInfo.NotAfter.IsZero() {
		t.Error("NotAfter is zero")
	}

	// Ensure cert is reused on second call
	certInfo2, err := cm.EnsureCert([]string{"test.example.com"})
	if err != nil {
		t.Fatalf("Second EnsureCert failed: %v", err)
	}
	if certInfo.PublicCert != certInfo2.PublicCert {
		t.Error("Certificate was regenerated when it should have been reused")
	}
}

func TestCertManager_DefaultDir(t *testing.T) {
	// Test that empty configDir uses default
	cm, err := NewCertManager("")
	if err != nil {
		t.Fatalf("Failed to create CertManager with empty dir: %v", err)
	}

	home, _ := os.UserHomeDir()
	expected := filepath.Join(home, ".mcp-sysinfo")

	if cm.configDir != expected {
		t.Errorf("Expected configDir %s, got %s", expected, cm.configDir)
	}
}
