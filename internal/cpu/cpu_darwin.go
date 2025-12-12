//go:build darwin

package cpu

/*
#include <mach/mach_host.h>
#include <mach/host_info.h>
#include <mach/mach_init.h>
#include <sys/sysctl.h>
#include <stdlib.h>

// Helper to get CPU times
int getCPUTimes(uint64_t *user, uint64_t *system, uint64_t *idle, uint64_t *nice) {
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    host_cpu_load_info_data_t cpuinfo;

    kern_return_t kr = host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                                       (host_info_t)&cpuinfo, &count);
    if (kr != KERN_SUCCESS) {
        return -1;
    }

    *user = cpuinfo.cpu_ticks[CPU_STATE_USER];
    *system = cpuinfo.cpu_ticks[CPU_STATE_SYSTEM];
    *idle = cpuinfo.cpu_ticks[CPU_STATE_IDLE];
    *nice = cpuinfo.cpu_ticks[CPU_STATE_NICE];

    return 0;
}

// Helper to get CPU count
int getCPUCount(int *logical, int *physical) {
    size_t len = sizeof(int);

    if (sysctlbyname("hw.logicalcpu", logical, &len, NULL, 0) != 0) {
        *logical = 1;
    }

    if (sysctlbyname("hw.physicalcpu", physical, &len, NULL, 0) != 0) {
        *physical = 1;
    }

    return 0;
}

// Helper to get CPU frequency
int getCPUFrequency(uint64_t *freq) {
    size_t len = sizeof(uint64_t);

    if (sysctlbyname("hw.cpufrequency", freq, &len, NULL, 0) != 0) {
        *freq = 0;
    }

    return 0;
}

// Helper to get load average
int getLoadAvg(double *load1, double *load5, double *load15) {
    double loadavg[3];
    if (getloadavg(loadavg, 3) == -1) {
        return -1;
    }
    *load1 = loadavg[0];
    *load5 = loadavg[1];
    *load15 = loadavg[2];
    return 0;
}
*/
import "C"

import (
	"fmt"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers CPU information on macOS.
func (c *Collector) collect(perCPU bool) (*types.CPUInfo, error) {
	times, err := getCPUTimesFromMach()
	if err != nil {
		return nil, fmt.Errorf("getting cpu times: %w", err)
	}

	now := time.Now()
	elapsed := now.Sub(c.previousTime)

	// Calculate CPU percentage
	percent := calculatePercent(c.previousTimes, times, elapsed)

	// Update previous times
	c.previousTimes = times
	c.previousTime = now

	// Get core counts
	logical, physical, _ := c.getCoreCount()

	// Get frequency
	freq, _ := c.getFrequency()

	// Get load average
	loadAvg, _ := c.getLoadAverage()

	return &types.CPUInfo{
		Percent:       percent,
		PerCPU:        nil, // TODO: per-CPU on macOS requires more work
		Count:         logical,
		PhysicalCount: physical,
		Frequency:     freq,
		LoadAverage:   loadAvg,
		Timestamp:     now,
	}, nil
}

// getCPUTimesFromMach gets CPU times using Mach APIs.
func getCPUTimesFromMach() (*cpuTimes, error) {
	var user, system, idle, nice C.uint64_t

	ret := C.getCPUTimes(&user, &system, &idle, &nice)
	if ret != 0 {
		return nil, fmt.Errorf("failed to get CPU times")
	}

	return &cpuTimes{
		User:   uint64(user),
		System: uint64(system),
		Idle:   uint64(idle),
		Nice:   uint64(nice),
	}, nil
}

// getLoadAverage returns load average on macOS.
func (c *Collector) getLoadAverage() (*types.LoadAverage, error) {
	var load1, load5, load15 C.double

	ret := C.getLoadAvg(&load1, &load5, &load15)
	if ret != 0 {
		return nil, fmt.Errorf("failed to get load average")
	}

	return &types.LoadAverage{
		Load1:  float64(load1),
		Load5:  float64(load5),
		Load15: float64(load15),
	}, nil
}

// getFrequency returns CPU frequency on macOS.
func (c *Collector) getFrequency() (*types.FrequencyInfo, error) {
	var freq C.uint64_t
	C.getCPUFrequency(&freq)

	// Convert Hz to MHz
	freqMHz := float64(freq) / 1000000

	return &types.FrequencyInfo{
		Current: freqMHz,
		Min:     0, // Not easily available on macOS
		Max:     freqMHz,
	}, nil
}

// getCoreCount returns logical and physical core counts on macOS.
func (c *Collector) getCoreCount() (logical int, physical int, err error) {
	var logicalC, physicalC C.int
	C.getCPUCount(&logicalC, &physicalC)

	return int(logicalC), int(physicalC), nil
}
