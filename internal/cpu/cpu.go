// Package cpu provides CPU metrics collection across platforms.
package cpu

import (
	"time"

	"github.com/yourusername/mcp-sysinfo/pkg/types"
)

// Collector collects CPU metrics.
type Collector struct {
	// previousTimes stores previous CPU times for percentage calculation
	previousTimes *cpuTimes
	previousTime  time.Time
}

// cpuTimes represents CPU time counters.
type cpuTimes struct {
	User    uint64
	System  uint64
	Idle    uint64
	Nice    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
	Guest   uint64
}

// NewCollector creates a new CPU collector.
func NewCollector() *Collector {
	return &Collector{}
}

// Collect gathers CPU information.
// This is the main entry point - platform-specific implementations
// are in cpu_linux.go, cpu_darwin.go, cpu_windows.go
func (c *Collector) Collect(perCPU bool) (*types.CPUInfo, error) {
	return c.collect(perCPU)
}

// GetLoadAverage returns system load average (Unix-like systems only).
// On Windows, this returns nil.
func (c *Collector) GetLoadAverage() (*types.LoadAverage, error) {
	return c.getLoadAverage()
}

// GetFrequency returns CPU frequency information.
func (c *Collector) GetFrequency() (*types.FrequencyInfo, error) {
	return c.getFrequency()
}

// GetCoreCount returns the number of logical and physical CPU cores.
func (c *Collector) GetCoreCount() (logical int, physical int, err error) {
	return c.getCoreCount()
}

// calculatePercent calculates CPU usage percentage from time deltas.
func calculatePercent(prev, curr *cpuTimes, elapsed time.Duration) float64 {
	if prev == nil || elapsed == 0 {
		return 0
	}

	prevTotal := prev.User + prev.System + prev.Idle + prev.Nice + prev.IOWait + prev.IRQ + prev.SoftIRQ + prev.Steal
	currTotal := curr.User + curr.System + curr.Idle + curr.Nice + curr.IOWait + curr.IRQ + curr.SoftIRQ + curr.Steal

	totalDelta := currTotal - prevTotal
	if totalDelta == 0 {
		return 0
	}

	idleDelta := curr.Idle - prev.Idle
	usedDelta := totalDelta - idleDelta

	return float64(usedDelta) / float64(totalDelta) * 100
}
