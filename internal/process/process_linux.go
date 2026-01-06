//go:build linux

package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// System clock ticks per second
var clkTck = getClkTck()

func getClkTck() float64 {
	// Default on most Linux systems
	return 100
}

// collect gathers all running processes on Linux.
func (c *Collector) collect() (*types.ProcessList, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}

	var processes []types.ProcessInfo

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue // Not a PID directory
		}

		proc, err := c.getProcess(int32(pid))
		if err != nil {
			continue // Process may have exited
		}

		processes = append(processes, *proc)
	}

	return &types.ProcessList{
		Processes: processes,
		Total:     len(processes),
		Timestamp: time.Now(),
	}, nil
}

// getProcess returns information about a specific process.
func (c *Collector) getProcess(pid int32) (*types.ProcessInfo, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	// Read /proc/[pid]/stat
	// #nosec G304 -- reading from procfs, pid from system directory listing
	statData, err := os.ReadFile(filepath.Join(procPath, "stat"))
	if err != nil {
		return nil, err
	}

	stat, err := parseStat(string(statData))
	if err != nil {
		return nil, err
	}

	// Read /proc/[pid]/status for memory info
	// #nosec G304 -- reading from procfs, pid from system directory listing
	statusData, err := os.ReadFile(filepath.Join(procPath, "status"))
	if err != nil {
		return nil, err
	}

	status := parseStatus(string(statusData))

	// Read cmdline
	// #nosec G304 -- reading from procfs, pid from system directory listing
	cmdlineData, _ := os.ReadFile(filepath.Join(procPath, "cmdline"))
	cmdline := strings.ReplaceAll(string(cmdlineData), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	// Get username from UID
	username := status["Uid"]
	if uid, ok := status["Uid"]; ok {
		username = lookupUser(uid)
	}

	// Calculate CPU percent (snapshot - would need delta for accurate measure)
	cpuPercent := 0.0

	// Safe conversion for RSS (avoid negative values)
	var memRSS uint64
	if stat.rss > 0 {
		memRSS = uint64(stat.rss) * uint64(os.Getpagesize()) //#nosec G115 -- rss is checked positive
	}

	// Safe conversion for memory percent
	var memPercent float32
	totalMem := getTotalMemory()
	if stat.rss > 0 && totalMem > 0 {
		memPercent = float32(stat.rss) * 100.0 / float32(totalMem)
	}

	// Safe conversion for start time (clkTck is always positive, starttime is uint64)
	startTimeSec := stat.starttime / uint64(clkTck)
	// Cap to max int64 to prevent overflow (far future date, but safe)
	if startTimeSec > uint64(1<<62) {
		startTimeSec = uint64(1 << 62)
	}

	return &types.ProcessInfo{
		PID:        pid,
		Name:       stat.name,
		Username:   username,
		CPUPercent: cpuPercent,
		MemPercent: memPercent,
		MemRSS:     memRSS,
		Status:     stat.state,
		CreateTime: time.Unix(int64(startTimeSec), 0), //#nosec G115 -- startTimeSec is capped above
		Cmdline:    cmdline,
	}, nil
}

// getTopProcesses returns top N processes sorted by CPU or memory.
func (c *Collector) getTopProcesses(n int, sortBy string) ([]types.ProcessInfo, error) {
	list, err := c.collect()
	if err != nil {
		return nil, err
	}

	processes := list.Processes

	switch sortBy {
	case "memory", "mem":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].MemRSS > processes[j].MemRSS
		})
	case "cpu":
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].CPUPercent > processes[j].CPUPercent
		})
	default:
		// Default to memory
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].MemRSS > processes[j].MemRSS
		})
	}

	if n > len(processes) {
		n = len(processes)
	}

	return processes[:n], nil
}

// statInfo holds parsed /proc/[pid]/stat data.
type statInfo struct {
	name      string
	state     string
	ppid      int32
	utime     uint64
	stime     uint64
	starttime uint64
	rss       int64
}

// parseStat parses /proc/[pid]/stat.
func parseStat(data string) (*statInfo, error) {
	// Find process name (in parentheses)
	start := strings.Index(data, "(")
	end := strings.LastIndex(data, ")")
	if start == -1 || end == -1 {
		return nil, fmt.Errorf("invalid stat format")
	}

	name := data[start+1 : end]
	fields := strings.Fields(data[end+2:])

	if len(fields) < 22 {
		return nil, fmt.Errorf("insufficient stat fields")
	}

	state := fields[0]
	ppid, _ := strconv.ParseInt(fields[1], 10, 32)
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)
	starttime, _ := strconv.ParseUint(fields[19], 10, 64)
	rss, _ := strconv.ParseInt(fields[21], 10, 64)

	return &statInfo{
		name:      name,
		state:     stateToString(state),
		ppid:      int32(ppid),
		utime:     utime,
		stime:     stime,
		starttime: starttime,
		rss:       rss,
	}, nil
}

// parseStatus parses /proc/[pid]/status into a map.
func parseStatus(data string) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			// For Uid, take just the first value (real UID)
			if key == "Uid" || key == "Gid" {
				fields := strings.Fields(value)
				if len(fields) > 0 {
					value = fields[0]
				}
			}
			result[key] = value
		}
	}

	return result
}

// stateToString converts single-char state to readable string.
func stateToString(state string) string {
	states := map[string]string{
		"R": "running",
		"S": "sleeping",
		"D": "disk-sleep",
		"Z": "zombie",
		"T": "stopped",
		"t": "tracing-stop",
		"W": "paging",
		"X": "dead",
		"x": "dead",
		"K": "wakekill",
		"P": "parked",
		"I": "idle",
	}
	if s, ok := states[state]; ok {
		return s
	}
	return state
}

// lookupUser converts UID to username.
func lookupUser(uid string) string {
	// Simple lookup from /etc/passwd
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return uid
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == uid {
			return fields[0]
		}
	}

	return uid
}

// getTotalMemory returns total system memory in pages.
func getTotalMemory() uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 1 // Avoid divide by zero
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, _ := strconv.ParseUint(fields[1], 10, 64)
				// Convert KB to pages
				// #nosec G115 -- page size is always positive
				pageSize := uint64(os.Getpagesize())
				return kb * 1024 / pageSize
			}
		}
	}

	return 1
}

// collectSampled gathers processes with accurate CPU percentage via time-delta sampling.
// sampleDurationMs is the time to wait between measurements (default 1000ms recommended).
func (c *Collector) collectSampled(sampleDurationMs int) (*types.ProcessList, error) {
	if sampleDurationMs < 100 {
		sampleDurationMs = 100
	}
	if sampleDurationMs > 5000 {
		sampleDurationMs = 5000
	}

	// First snapshot: get CPU times for all processes
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("reading /proc: %w", err)
	}

	type cpuSnapshot struct {
		utime     uint64
		stime     uint64
		timestamp time.Time
	}

	type procData struct {
		pid      int32
		name     string
		cpu1     cpuSnapshot
		memRSS   uint64
		memPct   float32
		status   string
		username string
		cmdline  string
	}

	procMap := make(map[int32]*procData)
	totalMemPages := getTotalMemory()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		procPath := fmt.Sprintf("/proc/%d", pid)

		// Read stat for CPU times
		// #nosec G304 -- reading from procfs
		statData, err := os.ReadFile(filepath.Join(procPath, "stat"))
		if err != nil {
			continue
		}
		stat, err := parseStat(string(statData))
		if err != nil {
			continue
		}

		// Read status for memory
		// #nosec G304 -- reading from procfs
		statusData, _ := os.ReadFile(filepath.Join(procPath, "status"))
		status := parseStatus(string(statusData))

		// Read cmdline
		// #nosec G304 -- reading from procfs
		cmdlineData, _ := os.ReadFile(filepath.Join(procPath, "cmdline"))
		cmdline := strings.ReplaceAll(string(cmdlineData), "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)

		// Get username
		username := status["Uid"]
		if uid, ok := status["Uid"]; ok {
			username = lookupUser(uid)
		}

		// Calculate memory
		var memRSS uint64
		var memPct float32
		if stat.rss > 0 {
			memRSS = uint64(stat.rss) * uint64(os.Getpagesize()) // #nosec G115 - rss is always positive
			if totalMemPages > 0 {
				memPct = float32(stat.rss) * 100.0 / float32(totalMemPages)
			}
		}

		procMap[int32(pid)] = &procData{
			pid:  int32(pid),
			name: stat.name,
			cpu1: cpuSnapshot{
				utime:     stat.utime,
				stime:     stat.stime,
				timestamp: time.Now(),
			},
			memRSS:   memRSS,
			memPct:   memPct,
			status:   stat.state,
			username: username,
			cmdline:  cmdline,
		}
	}

	// Wait for sample duration
	time.Sleep(time.Duration(sampleDurationMs) * time.Millisecond)

	// Second snapshot: calculate CPU delta
	var processes []types.ProcessInfo
	sampleDuration := float64(sampleDurationMs) / 1000.0

	for pid, data := range procMap {
		procPath := fmt.Sprintf("/proc/%d", pid)

		// #nosec G304 -- reading from procfs
		statData, err := os.ReadFile(filepath.Join(procPath, "stat"))
		if err != nil {
			continue // Process exited
		}
		stat, err := parseStat(string(statData))
		if err != nil {
			continue
		}

		// Calculate CPU percentage
		utimeDelta := stat.utime - data.cpu1.utime
		stimeDelta := stat.stime - data.cpu1.stime
		totalTicks := float64(utimeDelta + stimeDelta)

		// Convert ticks to seconds, then to percentage
		cpuTimeSec := totalTicks / clkTck
		cpuPercent := (cpuTimeSec / sampleDuration) * 100.0

		if cpuPercent < 0 {
			cpuPercent = 0
		}

		processes = append(processes, types.ProcessInfo{
			PID:        pid,
			Name:       data.name,
			Username:   data.username,
			CPUPercent: cpuPercent,
			MemPercent: data.memPct,
			MemRSS:     data.memRSS,
			Status:     data.status,
			Cmdline:    data.cmdline,
		})
	}

	return &types.ProcessList{
		Processes: processes,
		Total:     len(processes),
		Timestamp: time.Now(),
	}, nil
}
