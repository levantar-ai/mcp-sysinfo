//go:build windows

package process

import (
	"fmt"
	"sort"
	"syscall"
	"time"
	"unsafe"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
)

// PROCESSENTRY32W structure
type processEntry32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

// collect gathers all running processes on Windows.
func (c *Collector) collect() (*types.ProcessList, error) {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var processes []types.ProcessInfo

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32First failed")
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])

		processes = append(processes, types.ProcessInfo{
			PID:    int32(entry.ProcessID),
			Name:   name,
			Status: "running",
		})

		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return &types.ProcessList{
		Processes: processes,
		Total:     len(processes),
		Timestamp: time.Now(),
	}, nil
}

// getProcess returns information about a specific process.
func (c *Collector) getProcess(pid int32) (*types.ProcessInfo, error) {
	list, err := c.collect()
	if err != nil {
		return nil, err
	}

	for _, proc := range list.Processes {
		if proc.PID == pid {
			return &proc, nil
		}
	}

	return nil, fmt.Errorf("process %d not found", pid)
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
