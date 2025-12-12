//go:build integration && linux

package integration

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
)

func TestDiskInfo_Linux(t *testing.T) {
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

	// Should have at least root partition
	if len(info.Partitions) == 0 {
		t.Error("No partitions found")
	}
}

func TestDiskInfo_Linux_ProcMounts(t *testing.T) {
	// Verify /proc/mounts is readable
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		t.Fatalf("Cannot read /proc/mounts: %v", err)
	}

	if len(data) == 0 {
		t.Error("/proc/mounts is empty")
	}

	// Verify our collector finds at least one real filesystem
	c := disk.NewCollector()
	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Check for root filesystem
	foundRoot := false
	for _, p := range info.Partitions {
		if p.Mountpoint == "/" {
			foundRoot = true
			t.Logf("Root filesystem: %s (%s)", p.Device, p.Fstype)
			break
		}
	}

	if !foundRoot {
		t.Log("Warning: Root filesystem not found in partitions")
	}
}

func TestDiskInfo_Linux_DF(t *testing.T) {
	// Compare with df command
	out, err := exec.Command("df", "-B1", "/").Output()
	if err != nil {
		t.Logf("df command failed: %v", err)
		return
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		t.Fatalf("Unexpected df output: %s", out)
	}

	// Parse the second line (first line is header)
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		t.Fatalf("Cannot parse df output: %s", lines[1])
	}

	dfTotal, _ := strconv.ParseUint(fields[1], 10, 64)
	dfUsed, _ := strconv.ParseUint(fields[2], 10, 64)

	c := disk.NewCollector()
	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Find root partition
	for _, p := range info.Partitions {
		if p.Mountpoint == "/" {
			// Compare with df (allow small differences due to timing)
			totalDiff := int64(p.Total) - int64(dfTotal)
			if totalDiff < 0 {
				totalDiff = -totalDiff
			}
			// Allow up to 1% difference
			if float64(totalDiff)/float64(dfTotal) > 0.01 {
				t.Errorf("Total mismatch: got %d, df reports %d", p.Total, dfTotal)
			}

			t.Logf("Verified root partition: Total=%d, Used=%d (df: Total=%d, Used=%d)",
				p.Total, p.Used, dfTotal, dfUsed)
			return
		}
	}

	t.Log("Root partition not found for df comparison")
}

func TestDiskIOCounters_Linux(t *testing.T) {
	c := disk.NewCollector()

	counters, err := c.GetIOCounters()
	if err != nil {
		t.Fatalf("GetIOCounters failed: %v", err)
	}

	t.Logf("Found I/O counters for %d disks", len(counters))

	for name, counter := range counters {
		t.Logf("Disk %s: Reads=%d (%.2f MB), Writes=%d (%.2f MB), Time=%dms",
			name,
			counter.ReadCount,
			float64(counter.ReadBytes)/(1024*1024),
			counter.WriteCount,
			float64(counter.WriteBytes)/(1024*1024),
			counter.IoTime)
	}
}

func TestDiskIOCounters_Linux_ProcDiskstats(t *testing.T) {
	// Verify /proc/diskstats is readable
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		t.Fatalf("Cannot read /proc/diskstats: %v", err)
	}

	if len(data) == 0 {
		t.Error("/proc/diskstats is empty")
	}

	// Count disk entries
	lines := strings.Split(string(data), "\n")
	diskCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			diskCount++
		}
	}

	t.Logf("Found %d entries in /proc/diskstats", diskCount)

	// Our collector should return some counters
	c := disk.NewCollector()
	counters, err := c.GetIOCounters()
	if err != nil {
		t.Fatalf("GetIOCounters failed: %v", err)
	}

	// We filter to only whole disks, so count should be less
	t.Logf("Collector returned %d disk I/O counters", len(counters))
}

func TestDiskInfo_Linux_Consistency(t *testing.T) {
	c := disk.NewCollector()

	// Collect multiple times
	var lastPartitions int
	for i := 0; i < 5; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}

		if lastPartitions == 0 {
			lastPartitions = len(info.Partitions)
		} else if len(info.Partitions) != lastPartitions {
			t.Errorf("Partition count changed: %d -> %d", lastPartitions, len(info.Partitions))
		}
	}
}

func TestDiskInfo_Linux_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	c := disk.NewCollector()

	for i := 0; i < 100; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if len(info.Partitions) == 0 {
			t.Errorf("Iteration %d: No partitions found", i)
		}
	}
}
