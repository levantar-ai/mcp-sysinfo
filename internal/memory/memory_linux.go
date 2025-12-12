//go:build linux

package memory

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers memory information on Linux by parsing /proc/meminfo.
func (c *Collector) collect() (*types.MemoryInfo, error) {
	memInfo, err := parseMemInfo()
	if err != nil {
		return nil, fmt.Errorf("parsing meminfo: %w", err)
	}

	// Calculate used memory
	// Used = Total - Free - Buffers - Cached - SReclaimable
	used := memInfo["MemTotal"] - memInfo["MemFree"] - memInfo["Buffers"] -
		memInfo["Cached"] - memInfo["SReclaimable"]

	// Available memory (kernel 3.14+)
	available := memInfo["MemAvailable"]
	if available == 0 {
		// Fallback for older kernels
		available = memInfo["MemFree"] + memInfo["Buffers"] + memInfo["Cached"]
	}

	return &types.MemoryInfo{
		Total:        memInfo["MemTotal"],
		Available:    available,
		Used:         used,
		UsedPercent:  calculatePercent(used, memInfo["MemTotal"]),
		Free:         memInfo["MemFree"],
		Active:       memInfo["Active"],
		Inactive:     memInfo["Inactive"],
		Buffers:      memInfo["Buffers"],
		Cached:       memInfo["Cached"],
		Shared:       memInfo["Shmem"],
		Slab:         memInfo["Slab"],
		SReclaimable: memInfo["SReclaimable"],
		SUReClaimable: memInfo["SUnreclaim"],
		PageTables:   memInfo["PageTables"],
		SwapCached:   memInfo["SwapCached"],
		Timestamp:    time.Now(),
	}, nil
}

// getSwap returns swap memory information on Linux.
func (c *Collector) getSwap() (*types.SwapInfo, error) {
	memInfo, err := parseMemInfo()
	if err != nil {
		return nil, fmt.Errorf("parsing meminfo: %w", err)
	}

	total := memInfo["SwapTotal"]
	free := memInfo["SwapFree"]
	used := total - free

	return &types.SwapInfo{
		Total:       total,
		Used:        used,
		Free:        free,
		UsedPercent: calculatePercent(used, total),
		Sin:         0, // Would need to parse /proc/vmstat for these
		Sout:        0,
		Timestamp:   time.Now(),
	}, nil
}

// parseMemInfo reads and parses /proc/meminfo.
func parseMemInfo() (map[string]uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]uint64)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Remove the colon from field name
		key := strings.TrimSuffix(fields[0], ":")

		// Parse value
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		// Convert from KB to bytes if unit is present
		if len(fields) >= 3 && fields[2] == "kB" {
			value *= 1024
		}

		result[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
