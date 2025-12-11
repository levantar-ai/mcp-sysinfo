//go:build integration && linux

package integration

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yourusername/mcp-sysinfo/internal/cpu"
)

func TestCPUInfo_Linux(t *testing.T) {
	c := cpu.NewCollector()

	// First call to establish baseline
	_, err := c.Collect(false)
	if err != nil {
		t.Fatalf("First Collect failed: %v", err)
	}

	// Wait for some CPU activity
	time.Sleep(500 * time.Millisecond)

	// Second call to get actual usage
	info, err := c.Collect(false)
	if err != nil {
		t.Fatalf("Second Collect failed: %v", err)
	}

	t.Logf("CPU Info: Percent=%.2f%%, Cores=%d/%d",
		info.Percent, info.PhysicalCount, info.Count)

	// Verify against system
	if info.Percent < 0 || info.Percent > 100 {
		t.Errorf("CPU percent out of range: %.2f", info.Percent)
	}
}

func TestCPUInfo_Linux_ProcStat(t *testing.T) {
	// Verify /proc/stat is readable
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		t.Fatalf("Cannot read /proc/stat: %v", err)
	}

	if !strings.HasPrefix(string(data), "cpu ") {
		t.Error("/proc/stat does not start with 'cpu '")
	}

	// Verify our collector can parse it
	c := cpu.NewCollector()
	info, err := c.Collect(false)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if info.Count <= 0 {
		t.Error("Failed to detect CPU count")
	}
}

func TestCPUInfo_Linux_LoadAverage(t *testing.T) {
	c := cpu.NewCollector()

	loadAvg, err := c.GetLoadAverage()
	if err != nil {
		t.Fatalf("GetLoadAverage failed: %v", err)
	}

	if loadAvg == nil {
		t.Fatal("GetLoadAverage returned nil")
	}

	// Verify against /proc/loadavg
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		t.Fatalf("Cannot read /proc/loadavg: %v", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		t.Fatalf("Invalid /proc/loadavg format: %s", data)
	}

	expectedLoad1, _ := strconv.ParseFloat(fields[0], 64)

	// Allow small delta due to timing
	delta := loadAvg.Load1 - expectedLoad1
	if delta < 0 {
		delta = -delta
	}
	if delta > 0.1 {
		t.Errorf("Load1 mismatch: got %.2f, expected %.2f", loadAvg.Load1, expectedLoad1)
	}

	t.Logf("Load Average: %.2f %.2f %.2f", loadAvg.Load1, loadAvg.Load5, loadAvg.Load15)
}

func TestCPUInfo_Linux_CoreCount(t *testing.T) {
	c := cpu.NewCollector()

	logical, physical, err := c.GetCoreCount()
	if err != nil {
		t.Fatalf("GetCoreCount failed: %v", err)
	}

	// Verify against nproc command
	out, err := exec.Command("nproc").Output()
	if err != nil {
		t.Logf("nproc command failed: %v", err)
	} else {
		expectedLogical, _ := strconv.Atoi(strings.TrimSpace(string(out)))
		if logical != expectedLogical {
			t.Errorf("Logical core count mismatch: got %d, expected %d", logical, expectedLogical)
		}
	}

	t.Logf("Core Count: logical=%d, physical=%d", logical, physical)
}

func TestCPUInfo_Linux_Frequency(t *testing.T) {
	c := cpu.NewCollector()

	freq, err := c.GetFrequency()
	if err != nil {
		t.Logf("GetFrequency failed (may be expected in VM): %v", err)
		return
	}

	if freq == nil {
		t.Log("Frequency info not available (may be expected in VM)")
		return
	}

	t.Logf("CPU Frequency: current=%.0f MHz, min=%.0f MHz, max=%.0f MHz",
		freq.Current, freq.Min, freq.Max)

	// Sanity check - frequency should be reasonable
	if freq.Current > 0 && freq.Current < 100 {
		t.Logf("Warning: very low frequency reported: %.0f MHz", freq.Current)
	}
}

func TestCPUInfo_Linux_PerCPU(t *testing.T) {
	c := cpu.NewCollector()

	// First call
	_, err := c.Collect(true)
	if err != nil {
		t.Fatalf("First Collect failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Second call
	info, err := c.Collect(true)
	if err != nil {
		t.Fatalf("Second Collect failed: %v", err)
	}

	if info.PerCPU != nil {
		t.Logf("Per-CPU usage (%d cores):", len(info.PerCPU))
		for i, p := range info.PerCPU {
			t.Logf("  CPU%d: %.2f%%", i, p)
		}
	}
}

func TestCPUInfo_Linux_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	c := cpu.NewCollector()

	// Collect many times in rapid succession
	for i := 0; i < 100; i++ {
		info, err := c.Collect(false)
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if info.Percent < 0 || info.Percent > 100 {
			t.Errorf("Iteration %d: invalid percent %.2f", i, info.Percent)
		}
	}
}
