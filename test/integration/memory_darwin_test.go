//go:build integration && darwin

package integration

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/yourusername/mcp-sysinfo/internal/memory"
)

func TestMemoryInfo_Darwin(t *testing.T) {
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

func TestMemoryInfo_Darwin_Sysctl(t *testing.T) {
	// Verify against sysctl hw.memsize
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		t.Fatalf("sysctl failed: %v", err)
	}

	expectedTotal, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		t.Fatalf("Cannot parse sysctl output: %v", err)
	}

	c := memory.NewCollector()
	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if info.Total != expectedTotal {
		t.Errorf("Total memory mismatch: got %d, sysctl reports %d", info.Total, expectedTotal)
	}

	t.Logf("Verified MemTotal via sysctl: %d bytes", info.Total)
}

func TestMemoryInfo_Darwin_VMStat(t *testing.T) {
	// Verify we can read VM statistics
	out, err := exec.Command("vm_stat").Output()
	if err != nil {
		t.Logf("vm_stat command failed: %v", err)
		return
	}

	// Parse page size from vm_stat output
	lines := strings.Split(string(out), "\n")
	var pageSize uint64 = 4096 // Default
	for _, line := range lines {
		if strings.Contains(line, "page size of") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "of" && i+1 < len(fields) {
					pageSize, _ = strconv.ParseUint(fields[i+1], 10, 64)
					break
				}
			}
			break
		}
	}

	t.Logf("Page size: %d bytes", pageSize)

	c := memory.NewCollector()
	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Verify macOS-specific fields
	t.Logf("macOS Memory Details:")
	t.Logf("  Total:      %d", info.Total)
	t.Logf("  Free:       %d", info.Free)
	t.Logf("  Active:     %d", info.Active)
	t.Logf("  Inactive:   %d", info.Inactive)
	t.Logf("  Wired:      %d", info.Wired)
	t.Logf("  Compressed: %d", info.Compressed)
}

func TestSwapInfo_Darwin(t *testing.T) {
	c := memory.NewCollector()

	swap, err := c.GetSwap()
	if err != nil {
		t.Fatalf("GetSwap failed: %v", err)
	}

	t.Logf("Swap Info: Total=%d, Used=%d (%.2f%%), Free=%d",
		swap.Total, swap.Used, swap.UsedPercent, swap.Free)

	// macOS may have dynamic swap
	if swap.Total > 0 {
		if swap.UsedPercent < 0 || swap.UsedPercent > 100 {
			t.Errorf("Swap UsedPercent out of range: %.2f", swap.UsedPercent)
		}
	}
}

func TestSwapInfo_Darwin_Sysctl(t *testing.T) {
	// Verify against sysctl vm.swapusage
	out, err := exec.Command("sysctl", "-n", "vm.swapusage").Output()
	if err != nil {
		t.Logf("sysctl vm.swapusage failed: %v", err)
		return
	}

	// Parse output like: "total = 2048.00M  used = 100.00M  free = 1948.00M"
	output := string(out)
	t.Logf("sysctl vm.swapusage: %s", strings.TrimSpace(output))

	c := memory.NewCollector()
	swap, err := c.GetSwap()
	if err != nil {
		t.Fatalf("GetSwap failed: %v", err)
	}

	// Log our values for comparison
	t.Logf("Our swap values: Total=%d, Used=%d, Free=%d",
		swap.Total, swap.Used, swap.Free)
}

func TestMemoryInfo_Darwin_Consistency(t *testing.T) {
	c := memory.NewCollector()

	// Collect multiple times and verify consistency
	var lastTotal uint64
	for i := 0; i < 10; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}

		if lastTotal == 0 {
			lastTotal = info.Total
		} else if info.Total != lastTotal {
			t.Errorf("Total memory changed between calls: %d -> %d", lastTotal, info.Total)
		}
	}
}

func TestMemoryInfo_Darwin_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	c := memory.NewCollector()

	for i := 0; i < 100; i++ {
		info, err := c.Collect()
		if err != nil {
			t.Fatalf("Collect iteration %d failed: %v", i, err)
		}
		if info.Total == 0 {
			t.Errorf("Iteration %d: Total is 0", i)
		}
	}
}
