//go:build windows

package cpu

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/yourusername/mcp-sysinfo/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	kernel32                = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes      = kernel32.NewProc("GetSystemTimes")
	procGetSystemInfo       = kernel32.NewProc("GetSystemInfo")
	procGetLogicalProcessorInformationEx = kernel32.NewProc("GetLogicalProcessorInformationEx")
)

// FILETIME represents a Windows FILETIME structure.
type fileTime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// toUint64 converts FILETIME to uint64 (100-nanosecond intervals).
func (ft *fileTime) toUint64() uint64 {
	return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
}

// SYSTEM_INFO structure
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

// collect gathers CPU information on Windows.
func (c *Collector) collect(perCPU bool) (*types.CPUInfo, error) {
	times, err := getSystemTimes()
	if err != nil {
		return nil, fmt.Errorf("getting system times: %w", err)
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

	return &types.CPUInfo{
		Percent:       percent,
		PerCPU:        nil, // TODO: per-CPU on Windows
		Count:         logical,
		PhysicalCount: physical,
		Frequency:     freq,
		LoadAverage:   nil, // Windows doesn't have load average
		Timestamp:     now,
	}, nil
}

// getSystemTimes retrieves system CPU times.
func getSystemTimes() (*cpuTimes, error) {
	var idleTime, kernelTime, userTime fileTime

	ret, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("GetSystemTimes failed: %w", err)
	}

	// Note: kernelTime includes idleTime on Windows
	idle := idleTime.toUint64()
	kernel := kernelTime.toUint64()
	user := userTime.toUint64()

	// System time = kernel - idle
	system := kernel - idle

	return &cpuTimes{
		User:   user,
		System: system,
		Idle:   idle,
	}, nil
}

// getLoadAverage returns nil on Windows (not supported).
func (c *Collector) getLoadAverage() (*types.LoadAverage, error) {
	// Windows doesn't have a direct equivalent to Unix load average
	return nil, nil
}

// getFrequency returns CPU frequency on Windows using registry.
func (c *Collector) getFrequency() (*types.FrequencyInfo, error) {
	// Open the registry key for CPU info
	key, err := windows.OpenKey(
		windows.HKEY_LOCAL_MACHINE,
		`HARDWARE\DESCRIPTION\System\CentralProcessor\0`,
		windows.KEY_READ,
	)
	if err != nil {
		return nil, fmt.Errorf("opening registry key: %w", err)
	}
	defer windows.CloseKey(key)

	// Read MHz value
	var mhz uint32
	var dtype uint32
	var buf [4]byte
	n := uint32(len(buf))

	err = windows.RegQueryValueEx(
		key,
		syscall.StringToUTF16Ptr("~MHz"),
		nil,
		&dtype,
		&buf[0],
		&n,
	)
	if err != nil {
		return nil, fmt.Errorf("reading MHz: %w", err)
	}

	mhz = *(*uint32)(unsafe.Pointer(&buf[0]))

	return &types.FrequencyInfo{
		Current: float64(mhz),
		Min:     0,
		Max:     float64(mhz),
	}, nil
}

// getCoreCount returns logical and physical core counts on Windows.
func (c *Collector) getCoreCount() (logical int, physical int, err error) {
	var sysInfo systemInfo
	procGetSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))

	logical = int(sysInfo.NumberOfProcessors)

	// Get physical core count using GetLogicalProcessorInformationEx
	physical = getPhysicalCoreCountWindows()
	if physical == 0 {
		physical = logical
	}

	return logical, physical, nil
}

// getPhysicalCoreCountWindows gets physical core count.
func getPhysicalCoreCountWindows() int {
	// First call to get required buffer size
	var returnLength uint32
	procGetLogicalProcessorInformationEx.Call(
		0, // RelationProcessorCore
		0,
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if returnLength == 0 {
		return 0
	}

	// Allocate buffer
	buffer := make([]byte, returnLength)

	ret, _, _ := procGetLogicalProcessorInformationEx.Call(
		0, // RelationProcessorCore
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(&returnLength)),
	)

	if ret == 0 {
		return 0
	}

	// Count the number of PROCESSOR_RELATIONSHIP structures
	// Each one represents a physical core
	coreCount := 0
	offset := uint32(0)

	for offset < returnLength {
		// Size is at offset 4 in the structure
		size := *(*uint32)(unsafe.Pointer(&buffer[offset+4]))
		coreCount++
		offset += size
	}

	return coreCount
}
