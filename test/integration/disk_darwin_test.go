//go:build integration && darwin

package integration

import (
	"testing"

	"github.com/yourusername/mcp-sysinfo/internal/disk"
)

func TestDiskInfo_Darwin(t *testing.T) {
	c := disk.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	t.Logf("Found %d partitions", len(info.Partitions))

	for _, p := range info.Partitions {
		t.Logf("Partition: %s on %s (%s) - %.1f%% used",
			p.Device, p.Mountpoint, p.Fstype, p.UsedPercent)
	}

	if len(info.Partitions) == 0 {
		t.Error("No partitions found")
	}
}

func TestDiskInfo_Darwin_Root(t *testing.T) {
	c := disk.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	foundRoot := false
	for _, p := range info.Partitions {
		if p.Mountpoint == "/" {
			foundRoot = true
			t.Logf("Root filesystem: %s (%s)", p.Device, p.Fstype)
			break
		}
	}

	if !foundRoot {
		t.Error("Root filesystem not found")
	}
}
