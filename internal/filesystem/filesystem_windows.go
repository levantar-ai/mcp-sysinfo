//go:build windows

package filesystem

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetLogicalDrives      = kernel32.NewProc("GetLogicalDrives")
	procGetDiskFreeSpaceExW   = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetVolumeInformationW = kernel32.NewProc("GetVolumeInformationW")
)

// getMounts retrieves mounted filesystems on Windows.
func (c *Collector) getMounts() (*types.MountsResult, error) {
	var mounts []types.MountInfo

	// Get logical drives
	ret, _, _ := procGetLogicalDrives.Call()
	drives := uint32(ret)

	for i := 0; i < 26; i++ {
		if drives&(1<<uint(i)) == 0 {
			continue
		}

		drive := string(rune('A'+i)) + ":\\"
		drivePtr, _ := windows.UTF16PtrFromString(drive)

		// Get volume info
		var volumeNameBuf [256]uint16
		var fsNameBuf [256]uint16
		var serialNumber, maxCompLen, fsFlags uint32

		ret, _, _ = procGetVolumeInformationW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&volumeNameBuf[0])),
			uintptr(len(volumeNameBuf)),
			uintptr(unsafe.Pointer(&serialNumber)),
			uintptr(unsafe.Pointer(&maxCompLen)),
			uintptr(unsafe.Pointer(&fsFlags)),
			uintptr(unsafe.Pointer(&fsNameBuf[0])),
			uintptr(len(fsNameBuf)),
		)

		if ret == 0 {
			continue
		}

		fstype := windows.UTF16ToString(fsNameBuf[:])

		mount := types.MountInfo{
			Device:     drive,
			Mountpoint: drive,
			Fstype:     fstype,
		}

		// Get disk space
		var freeBytesAvailable, totalBytes, totalFreeBytes uint64
		ret, _, _ = procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)),
		)

		if ret != 0 {
			mount.Total = totalBytes
			mount.Free = totalFreeBytes
			mount.Used = totalBytes - totalFreeBytes
			if totalBytes > 0 {
				mount.UsedPct = float64(mount.Used) / float64(totalBytes) * 100
			}
		}

		mounts = append(mounts, mount)
	}

	return &types.MountsResult{
		Mounts:    mounts,
		Count:     len(mounts),
		Timestamp: time.Now(),
	}, nil
}

// getDiskIO retrieves disk I/O statistics on Windows.
func (c *Collector) getDiskIO() (*types.DiskIOResult, error) {
	var devices []types.DiskIOStats

	// Use wmic to get disk performance
	// #nosec G204 -- wmic is a system tool
	cmd := exec.Command("wmic", "diskdrive", "get", "Name,Size,BytesPerSector", "/format:csv")
	output, err := cmd.Output()
	if err != nil {
		// Try PowerShell as fallback
		return c.getDiskIOPowerShell()
	}

	devices = parseWmicDisk(output)

	return &types.DiskIOResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// parseWmicDisk parses wmic disk output.
func parseWmicDisk(output []byte) []types.DiskIOStats {
	var devices []types.DiskIOStats
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Skip header
	scanner.Scan()
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}

		name := strings.TrimSpace(fields[1])
		if name == "" {
			continue
		}

		devices = append(devices, types.DiskIOStats{
			Device: name,
		})
	}

	return devices
}

// getDiskIOPowerShell uses PowerShell to get disk I/O stats.
func (c *Collector) getDiskIOPowerShell() (*types.DiskIOResult, error) {
	var devices []types.DiskIOStats

	psCmd := `Get-Counter '\PhysicalDisk(*)\*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Select-Object Path,CookedValue | ConvertTo-Json`
	// #nosec G204 -- PowerShell is a system tool
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	_, err := cmd.Output()
	if err != nil {
		return &types.DiskIOResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// For now, return empty - full parsing would be complex
	return &types.DiskIOResult{
		Devices:   devices,
		Count:     0,
		Timestamp: time.Now(),
	}, nil
}

// getOpenFiles retrieves open file handles on Windows.
func (c *Collector) getOpenFiles() (*types.OpenFilesResult, error) {
	var files []types.OpenFile

	// Use handle.exe or PowerShell
	// For now, return basic info using handle count from processes
	psCmd := `Get-Process | Select-Object ProcessName,Id,HandleCount | ConvertTo-Json`
	// #nosec G204 -- PowerShell is a system tool
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return &types.OpenFilesResult{
			Files:     files,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// Parse JSON output
	content := string(output)
	lines := strings.Split(content, "\n")
	var currentPID int32
	var currentName string
	var handleCount int

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "\"ProcessName\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentName = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "\"Id\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				pidStr := strings.Trim(line[idx+1:], `", `)
				if p, err := strconv.Atoi(pidStr); err == nil {
					currentPID = int32(p)
				}
			}
		} else if strings.Contains(line, "\"HandleCount\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				hcStr := strings.Trim(line[idx+1:], `", `)
				handleCount, _ = strconv.Atoi(hcStr)
			}
		} else if strings.Contains(line, "}") {
			if currentName != "" && handleCount > 0 {
				// Add one entry per process summarizing handles
				files = append(files, types.OpenFile{
					PID:         currentPID,
					ProcessName: currentName,
					FD:          handleCount,
					Path:        "(handle count)",
					Type:        "summary",
				})
			}
			currentName = ""
			currentPID = 0
			handleCount = 0
		}
	}

	return &types.OpenFilesResult{
		Files:     files,
		Count:     len(files),
		Timestamp: time.Now(),
	}, nil
}

// getInodeUsage returns empty on Windows (no inodes).
func (c *Collector) getInodeUsage() (*types.InodeUsageResult, error) {
	// Windows doesn't have inodes
	return &types.InodeUsageResult{
		Filesystems: []types.InodeUsage{},
		Count:       0,
		Timestamp:   time.Now(),
	}, nil
}
