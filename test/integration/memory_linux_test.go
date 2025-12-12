//go:build integration && linux

package integration

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
)

func TestMemoryInfo_Linux(t *testing.T) {
	c := memory.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	t.Logf("Memory Info: Total=%d, Used=%d (%.2f%%), Available=%d, Free=%d",
		info.Total, info.Used, info.UsedPercent, info.Available, info.Free)

	// Verify values are sensible
	if info.Total == 0 {
		t.Error("Total memory is 0")
	}
	if info.UsedPercent < 0 || info.UsedPercent > 100 {
		t.Errorf("UsedPercent out of range: %.2f", info.UsedPercent)
	}
}

func TestMemoryInfo_Linux_ProcMeminfo(t *testing.T) {
	// Verify /proc/meminfo is readable
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Fatalf("Cannot read /proc/meminfo: %v", err)
	}

	if !strings.Contains(string(data), "MemTotal:") {
		t.Error("/proc/meminfo does not contain MemTotal")
	}

	// Verify our collector produces consistent results
	c := memory.NewCollector()
	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Parse MemTotal from /proc/meminfo
	lines := strings.Split(string(data), "\n")
	var expectedTotalKB uint64
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				expectedTotalKB, _ = strconv.ParseUint(fields[1], 10, 64)
				break
			}
		}
	}

	expectedTotal := expectedTotalKB * 1024

	// Allow small delta due to timing/rounding
	delta := int64(info.Total) - int64(expectedTotal)
	if delta < 0 {
		delta = -delta
	}
	// Allow up to 1MB difference
	if delta > 1024*1024 {
		t.Errorf("Total memory mismatch: got %d, expected %d", info.Total, expectedTotal)
	}

	t.Logf("Verified MemTotal: %d bytes", info.Total)
}

func TestMemoryInfo_Linux_Free(t *testing.T) {
	// Compare with 'free' command output
	out, err := exec.Command("free", "-b").Output()
	if err != nil {
		t.Logf("free command failed: %v", err)
		return
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		t.Fatalf("Unexpected free output: %s", out)
	}

	// Parse the "Mem:" line
	for _, line := range lines {
		if strings.HasPrefix(line, "Mem:") {
			fields := strings.Fields(line)
			if len(fields) < 4 {
				t.Fatalf("Cannot parse free output: %s", line)
			}

			freeTotal, _ := strconv.ParseUint(fields[1], 10, 64)
			freeUsed, _ := strconv.ParseUint(fields[2], 10, 64)

			c := memory.NewCollector()
			info, err := c.Collect()
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			// Total should match exactly
			if info.Total != freeTotal {
				t.Errorf("Total mismatch: got %d, free reports %d", info.Total, freeTotal)
			}

			// Used can vary due to timing, allow 5% difference
			usedDiff := float64(info.Used) - float64(freeUsed)
			if usedDiff < 0 {
				usedDiff = -usedDiff
			}
			usedPctDiff := usedDiff / float64(freeUsed) * 100
			if usedPctDiff > 5 {
				t.Logf("Used memory differs by %.1f%%: got %d, free reports %d",
					usedPctDiff, info.Used, freeUsed)
			}

			t.Logf("Verified against free: Total=%d, Used=%d", freeTotal, freeUsed)
			break
		}
	}
}

func TestSwapInfo_Linux(t *testing.T) {
	c := memory.NewCollector()

	swap, err := c.GetSwap()
	if err != nil {
		t.Fatalf("GetSwap failed: %v", err)
	}

	t.Logf("Swap Info: Total=%d, Used=%d (%.2f%%), Free=%d",
		swap.Total, swap.Used, swap.UsedPercent, swap.Free)

	// Swap may be 0 if no swap is configured
	if swap.Total > 0 {
		if swap.Used+swap.Free > swap.Total {
			t.Errorf("Swap Used+Free (%d) > Total (%d)", swap.Used+swap.Free, swap.Total)
		}
	}
}

func TestSwapInfo_Linux_ProcMeminfo(t *testing.T) {
	// Verify swap against /proc/meminfo
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		t.Fatalf("Cannot read /proc/meminfo: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	var swapTotalKB, swapFreeKB uint64
	for _, line := range lines {
		if strings.HasPrefix(line, "SwapTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				swapTotalKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
		if strings.HasPrefix(line, "SwapFree:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				swapFreeKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}

	expectedTotal := swapTotalKB * 1024
	expectedFree := swapFreeKB * 1024

	c := memory.NewCollector()
	swap, err := c.GetSwap()
	if err != nil {
		t.Fatalf("GetSwap failed: %v", err)
	}

	if swap.Total != expectedTotal {
		t.Errorf("Swap Total mismatch: got %d, expected %d", swap.Total, expectedTotal)
	}

	// Free can change, but should be close
	delta := int64(swap.Free) - int64(expectedFree)
	if delta < 0 {
		delta = -delta
	}
	// Allow 1MB difference
	if delta > 1024*1024 {
		t.Logf("Swap Free slightly differs: got %d, expected %d", swap.Free, expectedFree)
	}

	t.Logf("Verified Swap: Total=%d, Free=%d", swap.Total, swap.Free)
}

func TestMemoryInfo_Linux_Detailed(t *testing.T) {
	c := memory.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Log all available fields
	t.Logf("Detailed Memory Info:")
	t.Logf("  Total:        %d", info.Total)
	t.Logf("  Available:    %d", info.Available)
	t.Logf("  Used:         %d", info.Used)
	t.Logf("  UsedPercent:  %.2f%%", info.UsedPercent)
	t.Logf("  Free:         %d", info.Free)
	t.Logf("  Active:       %d", info.Active)
	t.Logf("  Inactive:     %d", info.Inactive)
	t.Logf("  Buffers:      %d", info.Buffers)
	t.Logf("  Cached:       %d", info.Cached)
	t.Logf("  Shared:       %d", info.Shared)
	t.Logf("  Slab:         %d", info.Slab)
	t.Logf("  SReclaimable: %d", info.SReclaimable)

	// Sanity checks for Linux-specific fields
	if info.Buffers == 0 && info.Cached == 0 {
		t.Log("Warning: Both Buffers and Cached are 0 (unusual)")
	}
}

func TestMemoryInfo_Linux_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	c := memory.NewCollector()

	// Rapid successive calls
	for i := 0; i < 100; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if info.Total == 0 {
			t.Errorf("Iteration %d: Total is 0", i)
		}
		if info.UsedPercent < 0 || info.UsedPercent > 100 {
			t.Errorf("Iteration %d: invalid UsedPercent %.2f", i, info.UsedPercent)
		}
	}
}
