//go:build darwin

package uptime

/*
#include <sys/sysctl.h>
#include <sys/time.h>

int getBootTime(struct timeval *tv) {
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    size_t size = sizeof(struct timeval);
    return sysctl(mib, 2, tv, &size, NULL, 0);
}
*/
import "C"

import (
	"fmt"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers system uptime on macOS.
func (c *Collector) collect() (*types.UptimeInfo, error) {
	var tv C.struct_timeval

	if C.getBootTime(&tv) != 0 {
		return nil, fmt.Errorf("sysctl KERN_BOOTTIME failed")
	}

	bootTime := time.Unix(int64(tv.tv_sec), int64(tv.tv_usec)*1000)
	uptime := time.Since(bootTime)

	return &types.UptimeInfo{
		BootTime:  bootTime,
		Uptime:    uptime,
		UptimeStr: formatUptime(uptime),
		Timestamp: time.Now(),
	}, nil
}
