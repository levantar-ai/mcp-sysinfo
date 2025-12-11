//go:build linux

package uptime

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yourusername/mcp-sysinfo/pkg/types"
)

// collect gathers system uptime on Linux.
func (c *Collector) collect() (*types.UptimeInfo, error) {
	// Read /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return nil, fmt.Errorf("reading /proc/uptime: %w", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return nil, fmt.Errorf("invalid /proc/uptime format")
	}

	uptimeSeconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil, fmt.Errorf("parsing uptime: %w", err)
	}

	uptime := time.Duration(uptimeSeconds * float64(time.Second))
	bootTime := time.Now().Add(-uptime)

	return &types.UptimeInfo{
		BootTime:  bootTime,
		Uptime:    uptime,
		UptimeStr: formatUptime(uptime),
		Timestamp: time.Now(),
	}, nil
}
