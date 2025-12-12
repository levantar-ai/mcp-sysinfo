//go:build integration && windows

package integration

import (
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
)

func TestDiskInfo_Windows(t *testing.T) {
	c := disk.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	t.Logf("Found %d partitions", len(info.Partitions))

	for _, p := range info.Partitions {
		t.Logf("Partition: %s (%s) - %.1f%% used",
			p.Device, p.Fstype, p.UsedPercent)
	}

	if len(info.Partitions) == 0 {
		t.Error("No partitions found")
	}
}

func TestDiskInfo_Windows_CDrive(t *testing.T) {
	c := disk.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	foundC := false
	for _, p := range info.Partitions {
		if p.Mountpoint == "C:\\" {
			foundC = true
			t.Logf("C: drive: %s - %.2f GB total", p.Fstype, float64(p.Total)/(1024*1024*1024))
			break
		}
	}

	if !foundC {
		t.Error("C: drive not found")
	}
}
