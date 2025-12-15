package container

import (
	"testing"
)

func TestNewCollector(t *testing.T) {
	c := NewCollector()
	if c == nil {
		t.Fatal("NewCollector returned nil")
	}
	if c.client == nil {
		t.Fatal("NewCollector client is nil")
	}
}

func TestGetDockerSocket(t *testing.T) {
	sock := getDockerSocket()
	if sock == "" {
		t.Fatal("getDockerSocket returned empty string")
	}
}

func TestShortenID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sha256:abc123def456789012345678901234567890", "abc123def456"},
		{"abc123def456789012345678901234567890", "abc123def456"},
		{"abc123", "abc123"},
		{"", ""},
		{"sha256:", ""},
	}

	for _, tc := range tests {
		result := shortenID(tc.input)
		if result != tc.expected {
			t.Errorf("shortenID(%q) = %q, expected %q", tc.input, result, tc.expected)
		}
	}
}

func TestGetDockerImages(t *testing.T) {
	c := NewCollector()
	result, err := c.GetDockerImages()

	// This test may fail if Docker/Podman is not running, which is expected
	if err != nil {
		t.Fatalf("GetDockerImages returned error: %v", err)
	}

	if result == nil {
		t.Fatal("GetDockerImages returned nil result")
	}

	// Result should always have a valid timestamp
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Count should match Images length
	if result.Count != len(result.Images) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Images))
	}
}

func TestGetDockerContainers(t *testing.T) {
	c := NewCollector()
	result, err := c.GetDockerContainers()

	// This test may fail if Docker/Podman is not running, which is expected
	if err != nil {
		t.Fatalf("GetDockerContainers returned error: %v", err)
	}

	if result == nil {
		t.Fatal("GetDockerContainers returned nil result")
	}

	// Result should always have a valid timestamp
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}

	// Count should match Containers length
	if result.Count != len(result.Containers) {
		t.Errorf("count mismatch: got %d, expected %d", result.Count, len(result.Containers))
	}

	// Running + Paused + Stopped should equal or be less than Count
	runningTotal := result.Running + result.Paused + result.Stopped
	if runningTotal > result.Count {
		t.Errorf("state counts exceed total: %d > %d", runningTotal, result.Count)
	}
}

func TestGetImageHistory_EmptyID(t *testing.T) {
	c := NewCollector()
	result, err := c.GetImageHistory("")

	if err != nil {
		t.Fatalf("GetImageHistory returned error: %v", err)
	}

	if result == nil {
		t.Fatal("GetImageHistory returned nil result")
	}

	// Should return an error in the result for empty image ID
	if result.Error == "" {
		t.Error("GetImageHistory with empty ID should return error in result")
	}
}
