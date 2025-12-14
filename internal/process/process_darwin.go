//go:build darwin

package process

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers all running processes on macOS using ps command.
func (c *Collector) collect() (*types.ProcessList, error) {
	// Use ps to get process list
	out, err := cmdexec.Command("ps", "-axo", "pid,ppid,user,pcpu,pmem,rss,state,lstart,comm").Output()
	if err != nil {
		return nil, fmt.Errorf("ps command failed: %w", err)
	}

	var processes []types.ProcessInfo
	lines := strings.Split(string(out), "\n")

	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // Skip header
		}

		proc, err := parsePsLine(line)
		if err != nil {
			continue
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
	out, err := cmdexec.Command("ps", "-p", strconv.Itoa(int(pid)), "-o", "pid,ppid,user,pcpu,pmem,rss,state,lstart,comm").Output()
	if err != nil {
		return nil, fmt.Errorf("ps command failed: %w", err)
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return nil, fmt.Errorf("process not found")
	}

	return parsePsLine(lines[1])
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
		sort.Slice(processes, func(i, j int) bool {
			return processes[i].MemRSS > processes[j].MemRSS
		})
	}

	if n > len(processes) {
		n = len(processes)
	}

	return processes[:n], nil
}

// parsePsLine parses a line from ps output.
func parsePsLine(line string) (*types.ProcessInfo, error) {
	fields := strings.Fields(line)
	if len(fields) < 9 {
		return nil, fmt.Errorf("insufficient fields")
	}

	pid, _ := strconv.ParseInt(fields[0], 10, 32)
	user := fields[2]
	cpuPct, _ := strconv.ParseFloat(fields[3], 64)
	memPct, _ := strconv.ParseFloat(fields[4], 64)
	rss, _ := strconv.ParseUint(fields[5], 10, 64)
	state := fields[6]

	// lstart is 5 fields: "Mon Jan 1 00:00:00 2024"
	// Command is everything after
	name := fields[len(fields)-1]

	return &types.ProcessInfo{
		PID:        int32(pid),
		Name:       name,
		Username:   user,
		CPUPercent: cpuPct,
		MemPercent: float32(memPct),
		MemRSS:     rss * 1024, // ps reports in KB
		Status:     stateToString(state),
		CreateTime: time.Now(), // Would need to parse lstart properly
	}, nil
}

// stateToString converts macOS process state to readable string.
func stateToString(state string) string {
	if len(state) == 0 {
		return "unknown"
	}

	states := map[byte]string{
		'R': "running",
		'S': "sleeping",
		'I': "idle",
		'T': "stopped",
		'U': "uninterruptible",
		'Z': "zombie",
	}

	if s, ok := states[state[0]]; ok {
		return s
	}
	return state
}
