//go:build windows

package memory

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	kernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx   = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetPerformanceInfo     = kernel32.NewProc("GetPerformanceInfo")
)

// MEMORYSTATUSEX structure
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// PERFORMANCE_INFORMATION structure
type performanceInfo struct {
	Size                  uint32
	CommitTotal           uint64
	CommitLimit           uint64
	CommitPeak            uint64
	PhysicalTotal         uint64
	PhysicalAvailable     uint64
	SystemCache           uint64
	KernelTotal           uint64
	KernelPaged           uint64
	KernelNonpaged        uint64
	PageSize              uint64
	HandleCount           uint32
	ProcessCount          uint32
	ThreadCount           uint32
}

// collect gathers memory information on Windows.
func (c *Collector) collect() (*types.MemoryInfo, error) {
	var memStatus memoryStatusEx
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))

	ret, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		return nil, fmt.Errorf("GlobalMemoryStatusEx failed: %w", err)
	}

	// Get additional info from GetPerformanceInfo
	var perfInfo performanceInfo
	perfInfo.Size = uint32(unsafe.Sizeof(perfInfo))

	procGetPerformanceInfo.Call(
		uintptr(unsafe.Pointer(&perfInfo)),
		uintptr(perfInfo.Size),
	)

	total := memStatus.TotalPhys
	available := memStatus.AvailPhys
	used := total - available

	// System cache from performance info (convert from pages to bytes)
	cached := perfInfo.SystemCache * perfInfo.PageSize

	return &types.MemoryInfo{
		Total:        total,
		Available:    available,
		Used:         used,
		UsedPercent:  float64(memStatus.MemoryLoad),
		Free:         available, // On Windows, available ≈ free
		Cached:       cached,
		Timestamp:    time.Now(),
	}, nil
}

// getSwap returns swap (page file) information on Windows.
func (c *Collector) getSwap() (*types.SwapInfo, error) {
	var memStatus memoryStatusEx
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))

	ret, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		return nil, fmt.Errorf("GlobalMemoryStatusEx failed: %w", err)
	}

	// Page file = virtual memory backing store
	// TotalPageFile includes physical memory, so we subtract it
	total := memStatus.TotalPageFile - memStatus.TotalPhys
	free := memStatus.AvailPageFile - memStatus.AvailPhys

	// Prevent underflow if values are unexpected
	if total > memStatus.TotalPageFile {
		total = memStatus.TotalPageFile
	}
	if free > memStatus.AvailPageFile {
		free = memStatus.AvailPageFile
	}

	used := total - free
	if used > total {
		used = 0
	}

	return &types.SwapInfo{
		Total:       total,
		Used:        used,
		Free:        free,
		UsedPercent: calculatePercent(used, total),
		Timestamp:   time.Now(),
	}, nil
}
