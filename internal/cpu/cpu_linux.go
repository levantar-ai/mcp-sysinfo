//go:build linux

package cpu

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

const (
	procStat     = "/proc/stat"
	procCPUInfo  = "/proc/cpuinfo"
	procLoadAvg  = "/proc/loadavg"
	sysCPUPath   = "/sys/devices/system/cpu"
)

// collect gathers CPU information on Linux.
func (c *Collector) collect(perCPU bool) (*types.CPUInfo, error) {
	times, perCPUTimes, err := readCPUTimes(perCPU)
	if err != nil {
		return nil, fmt.Errorf("reading cpu times: %w", err)
	}

	now := time.Now()
	elapsed := now.Sub(c.previousTime)

	// Calculate overall CPU percentage
	percent := calculatePercent(c.previousTimes, times, elapsed)

	// Calculate per-CPU percentages if requested
	var perCPUPercent []float64
	if perCPU && perCPUTimes != nil {
		perCPUPercent = make([]float64, len(perCPUTimes))
		// For per-CPU, we'd need to store previous per-CPU times
		// For now, we'll return 0 on first call
		for i := range perCPUTimes {
			perCPUPercent[i] = 0 // TODO: implement per-CPU tracking
		}
	}

	// Update previous times for next calculation
	c.previousTimes = times
	c.previousTime = now

	// Get core counts
	logical, physical, err := c.getCoreCount()
	if err != nil {
		logical = 1
		physical = 1
	}

	// Get frequency
	freq, _ := c.getFrequency()

	// Get load average
	loadAvg, _ := c.getLoadAverage()

	return &types.CPUInfo{
		Percent:       percent,
		PerCPU:        perCPUPercent,
		Count:         logical,
		PhysicalCount: physical,
		Frequency:     freq,
		LoadAverage:   loadAvg,
		Timestamp:     now,
	}, nil
}

// readCPUTimes reads CPU times from /proc/stat.
func readCPUTimes(perCPU bool) (*cpuTimes, []*cpuTimes, error) {
	file, err := os.Open(procStat)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	var overall *cpuTimes
	var perCPUList []*cpuTimes

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "cpu ") {
			// Overall CPU stats
			overall, err = parseCPULine(line)
			if err != nil {
				return nil, nil, err
			}
		} else if perCPU && strings.HasPrefix(line, "cpu") {
			// Per-CPU stats (cpu0, cpu1, etc.)
			times, err := parseCPULine(line)
			if err != nil {
				continue
			}
			perCPUList = append(perCPUList, times)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	if overall == nil {
		return nil, nil, fmt.Errorf("cpu line not found in %s", procStat)
	}

	return overall, perCPUList, nil
}

// parseCPULine parses a cpu line from /proc/stat.
// Format: cpu  user nice system idle iowait irq softirq steal guest guest_nice
func parseCPULine(line string) (*cpuTimes, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return nil, fmt.Errorf("invalid cpu line: %s", line)
	}

	times := &cpuTimes{}
	var err error

	// Skip the "cpu" or "cpuN" prefix
	values := fields[1:]

	if len(values) > 0 {
		times.User, err = strconv.ParseUint(values[0], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if len(values) > 1 {
		times.Nice, err = strconv.ParseUint(values[1], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if len(values) > 2 {
		times.System, err = strconv.ParseUint(values[2], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if len(values) > 3 {
		times.Idle, err = strconv.ParseUint(values[3], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if len(values) > 4 {
		times.IOWait, err = strconv.ParseUint(values[4], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if len(values) > 5 {
		times.IRQ, err = strconv.ParseUint(values[5], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if len(values) > 6 {
		times.SoftIRQ, err = strconv.ParseUint(values[6], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if len(values) > 7 {
		times.Steal, err = strconv.ParseUint(values[7], 10, 64)
		if err != nil {
			return nil, err
		}
	}
	if len(values) > 8 {
		times.Guest, err = strconv.ParseUint(values[8], 10, 64)
		if err != nil {
			return nil, err
		}
	}

	return times, nil
}

// getLoadAverage reads load average from /proc/loadavg.
func (c *Collector) getLoadAverage() (*types.LoadAverage, error) {
	data, err := os.ReadFile(procLoadAvg)
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid loadavg format")
	}

	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil, err
	}
	load5, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return nil, err
	}
	load15, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return nil, err
	}

	return &types.LoadAverage{
		Load1:  load1,
		Load5:  load5,
		Load15: load15,
	}, nil
}

// getFrequency reads CPU frequency from sysfs.
func (c *Collector) getFrequency() (*types.FrequencyInfo, error) {
	freq := &types.FrequencyInfo{}

	// Try to read current frequency
	currentPath := filepath.Join(sysCPUPath, "cpu0/cpufreq/scaling_cur_freq")
	if data, err := os.ReadFile(currentPath); err == nil {
		if val, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
			freq.Current = val / 1000 // Convert kHz to MHz
		}
	}

	// Try to read min frequency
	minPath := filepath.Join(sysCPUPath, "cpu0/cpufreq/scaling_min_freq")
	if data, err := os.ReadFile(minPath); err == nil {
		if val, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
			freq.Min = val / 1000
		}
	}

	// Try to read max frequency
	maxPath := filepath.Join(sysCPUPath, "cpu0/cpufreq/scaling_max_freq")
	if data, err := os.ReadFile(maxPath); err == nil {
		if val, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64); err == nil {
			freq.Max = val / 1000
		}
	}

	// If we couldn't get current from cpufreq, try /proc/cpuinfo
	if freq.Current == 0 {
		freq.Current = getFrequencyFromCPUInfo()
	}

	return freq, nil
}

// getFrequencyFromCPUInfo reads CPU frequency from /proc/cpuinfo.
func getFrequencyFromCPUInfo() float64 {
	file, err := os.Open(procCPUInfo)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu MHz") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				if val, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
					return val
				}
			}
		}
	}
	return 0
}

// getCoreCount returns logical and physical core counts.
func (c *Collector) getCoreCount() (logical int, physical int, err error) {
	// Count logical cores by counting cpu directories
	entries, err := os.ReadDir(sysCPUPath)
	if err != nil {
		return 0, 0, err
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "cpu") && len(entry.Name()) > 3 {
			// Check if it's cpu0, cpu1, etc.
			if _, err := strconv.Atoi(entry.Name()[3:]); err == nil {
				logical++
			}
		}
	}

	// Get physical core count from /proc/cpuinfo
	physical = getPhysicalCoreCount()
	if physical == 0 {
		physical = logical // Fallback
	}

	return logical, physical, nil
}

// getPhysicalCoreCount reads physical core count from /proc/cpuinfo.
func getPhysicalCoreCount() int {
	file, err := os.Open(procCPUInfo)
	if err != nil {
		return 0
	}
	defer file.Close()

	coreIDs := make(map[string]struct{})
	physicalIDs := make(map[string]struct{})

	var currentPhysicalID, currentCoreID string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "physical id") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				currentPhysicalID = strings.TrimSpace(parts[1])
				physicalIDs[currentPhysicalID] = struct{}{}
			}
		} else if strings.HasPrefix(line, "core id") {
			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				currentCoreID = strings.TrimSpace(parts[1])
				// Use combination of physical_id and core_id as unique identifier
				key := currentPhysicalID + ":" + currentCoreID
				coreIDs[key] = struct{}{}
			}
		}
	}

	if len(coreIDs) > 0 {
		return len(coreIDs)
	}
	return 0
}
