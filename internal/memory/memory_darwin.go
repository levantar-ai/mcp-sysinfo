//go:build darwin

package memory

/*
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>
#include <sys/mount.h>

// Get total physical memory
int getTotalMemory(uint64_t *total) {
    int mib[2] = {CTL_HW, HW_MEMSIZE};
    size_t len = sizeof(uint64_t);
    return sysctl(mib, 2, total, &len, NULL, 0);
}

// Get VM statistics
int getVMStats(vm_statistics64_data_t *vmstat) {
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    return host_statistics64(mach_host_self(), HOST_VM_INFO64,
                            (host_info64_t)vmstat, &count);
}

// Get page size
int getPageSize(vm_size_t *pageSize) {
    return host_page_size(mach_host_self(), pageSize);
}

// Get swap usage via sysctl
int getSwapUsage(uint64_t *total, uint64_t *used, uint64_t *free) {
    struct xsw_usage swapUsage;
    size_t len = sizeof(swapUsage);
    int mib[2] = {CTL_VM, VM_SWAPUSAGE};

    if (sysctl(mib, 2, &swapUsage, &len, NULL, 0) != 0) {
        return -1;
    }

    *total = swapUsage.xsu_total;
    *used = swapUsage.xsu_used;
    *free = swapUsage.xsu_avail;
    return 0;
}
*/
import "C"

import (
	"fmt"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers memory information on macOS using Mach APIs.
func (c *Collector) collect() (*types.MemoryInfo, error) {
	var total C.uint64_t
	if C.getTotalMemory(&total) != 0 {
		return nil, fmt.Errorf("failed to get total memory")
	}

	var vmstat C.vm_statistics64_data_t
	if C.getVMStats(&vmstat) != C.KERN_SUCCESS {
		return nil, fmt.Errorf("failed to get VM statistics")
	}

	var pageSize C.vm_size_t
	if C.getPageSize(&pageSize) != C.KERN_SUCCESS {
		return nil, fmt.Errorf("failed to get page size")
	}

	ps := uint64(pageSize)

	// Calculate memory values
	free := uint64(vmstat.free_count) * ps
	active := uint64(vmstat.active_count) * ps
	inactive := uint64(vmstat.inactive_count) * ps
	wired := uint64(vmstat.wire_count) * ps
	compressed := uint64(vmstat.compressor_page_count) * ps

	// Speculative pages are "free" but may contain data
	speculative := uint64(vmstat.speculative_count) * ps

	// Purgeable pages can be reclaimed
	purgeable := uint64(vmstat.purgeable_count) * ps

	// File-backed pages (cached)
	fileBacked := uint64(vmstat.external_page_count) * ps

	totalMem := uint64(total)

	// Used memory = total - free - inactive - speculative - purgeable
	// This is a simplification; macOS memory management is complex
	used := totalMem - free - inactive - speculative
	if used > totalMem {
		used = totalMem - free
	}

	// Available = free + inactive + purgeable + speculative (can be reclaimed)
	available := free + inactive + purgeable + speculative

	return &types.MemoryInfo{
		Total:        totalMem,
		Available:    available,
		Used:         used,
		UsedPercent:  calculatePercent(used, totalMem),
		Free:         free,
		Active:       active,
		Inactive:     inactive,
		Wired:        wired,
		Compressed:   compressed,
		Cached:       fileBacked,
		Timestamp:    time.Now(),
	}, nil
}

// getSwap returns swap memory information on macOS.
func (c *Collector) getSwap() (*types.SwapInfo, error) {
	var total, used, free C.uint64_t

	if C.getSwapUsage(&total, &used, &free) != 0 {
		return nil, fmt.Errorf("failed to get swap usage")
	}

	return &types.SwapInfo{
		Total:       uint64(total),
		Used:        uint64(used),
		Free:        uint64(free),
		UsedPercent: calculatePercent(uint64(used), uint64(total)),
		Timestamp:   time.Now(),
	}, nil
}
