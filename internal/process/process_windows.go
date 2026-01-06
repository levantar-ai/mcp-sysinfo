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
	psapi                        = windows.NewLazySystemDLL("psapi.dll")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procGetProcessTimes          = kernel32.NewProc("GetProcessTimes")
	procGetProcessMemoryInfo     = psapi.NewProc("GetProcessMemoryInfo")
	procGlobalMemoryStatusEx     = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemInfo            = kernel32.NewProc("GetSystemInfo")
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

// PROCESS_MEMORY_COUNTERS structure for GetProcessMemoryInfo
type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

// MEMORYSTATUSEX structure for GlobalMemoryStatusEx
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

// SYSTEM_INFO structure for GetSystemInfo
type systemInfo struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

// cpuSnapshot holds CPU time data for delta calculation
type cpuSnapshot struct {
	kernelTime int64
	userTime   int64
	timestamp  time.Time
}

// getProcessMemory retrieves memory information for a process.
func getProcessMemory(pid uint32) (workingSet uint64, err error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)

	var memInfo processMemoryCounters
	memInfo.CB = uint32(unsafe.Sizeof(memInfo))

	ret, _, err := procGetProcessMemoryInfo.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&memInfo)),
		uintptr(memInfo.CB),
	)
	if ret == 0 {
		return 0, err
	}

	return uint64(memInfo.WorkingSetSize), nil
}

// getProcessCPUTimes retrieves CPU time for a process.
func getProcessCPUTimes(pid uint32) (cpuSnapshot, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return cpuSnapshot{}, err
	}
	defer windows.CloseHandle(handle)

	var creationTime, exitTime, kernelTime, userTime windows.Filetime

	ret, _, err := procGetProcessTimes.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&creationTime)),
		uintptr(unsafe.Pointer(&exitTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if ret == 0 {
		return cpuSnapshot{}, err
	}

	return cpuSnapshot{
		kernelTime: int64(kernelTime.HighDateTime)<<32 | int64(kernelTime.LowDateTime),
		userTime:   int64(userTime.HighDateTime)<<32 | int64(userTime.LowDateTime),
		timestamp:  time.Now(),
	}, nil
}

// getTotalPhysicalMemory returns total system memory in bytes.
func getTotalPhysicalMemory() uint64 {
	var memStatus memoryStatusEx
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		return 1 // Avoid divide by zero
	}
	return memStatus.TotalPhys
}

// collect gathers all running processes on Windows with memory info.
func (c *Collector) collect() (*types.ProcessList, error) {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	var processes []types.ProcessInfo
	totalMem := getTotalPhysicalMemory()

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, fmt.Errorf("Process32First failed")
	}

	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		pid := entry.ProcessID

		// Get memory info (may fail for protected processes)
		var memRSS uint64
		var memPercent float32
		if workingSet, err := getProcessMemory(pid); err == nil {
			memRSS = workingSet
			if totalMem > 0 {
				memPercent = float32(workingSet) * 100.0 / float32(totalMem)
			}
		}

		processes = append(processes, types.ProcessInfo{
			PID:        int32(pid),
			Name:       name,
			Status:     "running",
			MemRSS:     memRSS,
			MemPercent: memPercent,
			CPUPercent: 0.0, // Requires sampling - see get_processes_sampled
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

// collectSampled gathers processes with accurate CPU percentage via time-delta sampling.
// sampleDurationMs is the time to wait between measurements (default 1000ms recommended).
func (c *Collector) collectSampled(sampleDurationMs int) (*types.ProcessList, error) {
	if sampleDurationMs < 100 {
		sampleDurationMs = 100 // Minimum 100ms for meaningful measurement
	}
	if sampleDurationMs > 5000 {
		sampleDurationMs = 5000 // Maximum 5 seconds
	}

	// Get number of CPU cores for percentage calculation
	var sysInfo systemInfo
	procGetSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))
	numCPU := int(sysInfo.NumberOfProcessors)
	if numCPU < 1 {
		numCPU = 1
	}

	// First snapshot: get all process CPU times
	snapshot1, _, err := procCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if snapshot1 == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	type procData struct {
		name     string
		pid      uint32
		cpuTime1 cpuSnapshot
		memRSS   uint64
		memPct   float32
	}

	procMap := make(map[uint32]*procData)
	totalMem := getTotalPhysicalMemory()

	ret, _, _ := procProcess32First.Call(snapshot1, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		windows.CloseHandle(windows.Handle(snapshot1))
		return nil, fmt.Errorf("Process32First failed")
	}

	for {
		pid := entry.ProcessID
		name := windows.UTF16ToString(entry.ExeFile[:])

		// Get first CPU snapshot
		if cpuSnap, err := getProcessCPUTimes(pid); err == nil {
			// Get memory info
			var memRSS uint64
			var memPct float32
			if ws, err := getProcessMemory(pid); err == nil {
				memRSS = ws
				if totalMem > 0 {
					memPct = float32(ws) * 100.0 / float32(totalMem)
				}
			}

			procMap[pid] = &procData{
				name:     name,
				pid:      pid,
				cpuTime1: cpuSnap,
				memRSS:   memRSS,
				memPct:   memPct,
			}
		}

		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32Next.Call(snapshot1, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}
	windows.CloseHandle(windows.Handle(snapshot1))

	// Wait for sample duration
	time.Sleep(time.Duration(sampleDurationMs) * time.Millisecond)

	// Second snapshot: calculate CPU delta
	var processes []types.ProcessInfo
	sampleDuration := float64(sampleDurationMs) / 1000.0 // Convert to seconds

	for pid, data := range procMap {
		cpuSnap2, err := getProcessCPUTimes(pid)
		if err != nil {
			// Process may have exited
			continue
		}

		// Calculate CPU percentage
		// Windows FILETIME is in 100-nanosecond intervals
		kernelDelta := cpuSnap2.kernelTime - data.cpuTime1.kernelTime
		userDelta := cpuSnap2.userTime - data.cpuTime1.userTime
		totalCPUTime := float64(kernelDelta+userDelta) / 10000000.0 // Convert to seconds

		// CPU percent = (CPU time used / elapsed time) * 100 / numCPU
		cpuPercent := (totalCPUTime / sampleDuration) * 100.0

		// Clamp to reasonable range (0-100 per core, but total can exceed 100%)
		if cpuPercent < 0 {
			cpuPercent = 0
		}
		if cpuPercent > float64(numCPU)*100 {
			cpuPercent = float64(numCPU) * 100
		}

		processes = append(processes, types.ProcessInfo{
			PID:        int32(pid),
			Name:       data.name,
			Status:     "running",
			MemRSS:     data.memRSS,
			MemPercent: data.memPct,
			CPUPercent: cpuPercent,
		})
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
