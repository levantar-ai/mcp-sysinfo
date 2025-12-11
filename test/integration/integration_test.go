//go:build integration

// Package integration contains integration tests that run against the real OS.
package integration

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Skip if not in integration test mode
	if os.Getenv("INTEGRATION_TEST") != "true" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}
