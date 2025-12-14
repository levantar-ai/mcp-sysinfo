//go:build windows

package uptime

import (
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64 = kernel32.NewProc("GetTickCount64")
)

// collect gathers system uptime on Windows.
func (c *Collector) collect() (*types.UptimeInfo, error) {
	ret, _, _ := procGetTickCount64.Call()

	uptimeMs := uint64(ret)
	uptime := time.Duration(uptimeMs) * time.Millisecond
	bootTime := time.Now().Add(-uptime)

	return &types.UptimeInfo{
		BootTime:  bootTime,
		Uptime:    uptime,
		UptimeStr: formatUptime(uptime),
		Timestamp: time.Now(),
	}, nil
}
