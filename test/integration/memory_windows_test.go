//go:build integration && windows

package integration

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
)

func TestMemoryInfo_Windows(t *testing.T) {
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

func TestMemoryInfo_Windows_WMI(t *testing.T) {
	// Verify against wmic command
	out, err := exec.Command("wmic", "OS", "get", "TotalVisibleMemorySize", "/value").Output()
	if err != nil {
		t.Logf("wmic command failed: %v", err)
		return
	}

	// Parse output like: TotalVisibleMemorySize=16777216
	output := strings.TrimSpace(string(out))
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "TotalVisibleMemorySize=") {
			valueStr := strings.TrimPrefix(line, "TotalVisibleMemorySize=")
			valueStr = strings.TrimSpace(valueStr)
			totalKB, err := strconv.ParseUint(valueStr, 10, 64)
			if err != nil {
				t.Logf("Cannot parse wmic output: %v", err)
				return
			}

			expectedTotal := totalKB * 1024

			c := memory.NewCollector()
			info, err := c.Collect()
			if err != nil {
				t.Fatalf("Collect failed: %v", err)
			}

			if info.Total != expectedTotal {
				t.Errorf("Total memory mismatch: got %d, wmic reports %d", info.Total, expectedTotal)
			}

			t.Logf("Verified MemTotal via wmic: %d bytes", info.Total)
			return
		}
	}

	t.Log("Could not parse TotalVisibleMemorySize from wmic output")
}

func TestMemoryInfo_Windows_SystemInfo(t *testing.T) {
	// Alternative verification using systeminfo
	out, err := exec.Command("systeminfo").Output()
	if err != nil {
		t.Logf("systeminfo command failed: %v", err)
		return
	}

	// Just log it - parsing systeminfo is locale-dependent
	output := string(out)
	if strings.Contains(output, "Total Physical Memory:") {
		for _, line := range strings.Split(output, "\n") {
			if strings.Contains(line, "Total Physical Memory:") {
				t.Logf("systeminfo: %s", strings.TrimSpace(line))
			}
			if strings.Contains(line, "Available Physical Memory:") {
				t.Logf("systeminfo: %s", strings.TrimSpace(line))
			}
		}
	}

	c := memory.NewCollector()
	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	t.Logf("Our values: Total=%d, Available=%d", info.Total, info.Available)
}

func TestSwapInfo_Windows(t *testing.T) {
	c := memory.NewCollector()

	swap, err := c.GetSwap()
	if err != nil {
		t.Fatalf("GetSwap failed: %v", err)
	}

	t.Logf("Page File Info: Total=%d, Used=%d (%.2f%%), Free=%d",
		swap.Total, swap.Used, swap.UsedPercent, swap.Free)

	// Windows usually has a page file configured
	if swap.Total > 0 {
		if swap.UsedPercent < 0 || swap.UsedPercent > 100 {
			t.Errorf("Page file UsedPercent out of range: %.2f", swap.UsedPercent)
		}
	}
}

func TestSwapInfo_Windows_WMI(t *testing.T) {
	// Verify page file info via wmic
	out, err := exec.Command("wmic", "pagefile", "get", "AllocatedBaseSize,CurrentUsage", "/value").Output()
	if err != nil {
		t.Logf("wmic pagefile command failed: %v", err)
		return
	}

	t.Logf("wmic pagefile output: %s", strings.TrimSpace(string(out)))

	c := memory.NewCollector()
	swap, err := c.GetSwap()
	if err != nil {
		t.Fatalf("GetSwap failed: %v", err)
	}

	t.Logf("Our page file values: Total=%d, Used=%d, Free=%d",
		swap.Total, swap.Used, swap.Free)
}

func TestMemoryInfo_Windows_Consistency(t *testing.T) {
	c := memory.NewCollector()

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

func TestMemoryInfo_Windows_StressTest(t *testing.T) {
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

func TestMemoryInfo_Windows_MemoryLoad(t *testing.T) {
	c := memory.NewCollector()

	info, err := c.Collect()
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Windows GlobalMemoryStatusEx provides direct memory load percentage
	t.Logf("Memory Load: %.0f%%", info.UsedPercent)

	// Should be a reasonable value
	if info.UsedPercent == 0 {
		t.Log("Warning: Memory load is 0%% (unusual)")
	}
	if info.UsedPercent > 95 {
		t.Log("Warning: Memory load is very high (>95%%)")
	}
}
