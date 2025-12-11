//go:build integration && darwin

package integration

import (
	"testing"
)

func TestCPUInfo_Darwin(t *testing.T) {
	// TODO: Implement macOS-specific CPU integration tests
	t.Skip("Not yet implemented")
}

func TestCPUInfo_Darwin_Sysctl(t *testing.T) {
	// TODO: Test reading CPU info via sysctl
	t.Skip("Not yet implemented")
}
