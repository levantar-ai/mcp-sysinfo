//go:build windows

package disk

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetLogicalDrives      = kernel32.NewProc("GetLogicalDrives")
	procGetDiskFreeSpaceExW   = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetVolumeInformationW = kernel32.NewProc("GetVolumeInformationW")
	procGetDriveTypeW         = kernel32.NewProc("GetDriveTypeW")
)

const (
	DRIVE_UNKNOWN     = 0
	DRIVE_NO_ROOT_DIR = 1
	DRIVE_REMOVABLE   = 2
	DRIVE_FIXED       = 3
	DRIVE_REMOTE      = 4
	DRIVE_CDROM       = 5
	DRIVE_RAMDISK     = 6
)

// collect gathers disk partition information on Windows.
func (c *Collector) collect() (*types.DiskInfo, error) {
	partitions, err := getPartitions()
	if err != nil {
		return nil, fmt.Errorf("getting partitions: %w", err)
	}

	return &types.DiskInfo{
		Partitions: partitions,
		Timestamp:  time.Now(),
	}, nil
}

// getPartitions gets mounted drives on Windows.
func getPartitions() ([]types.PartitionInfo, error) {
	// Get bitmask of logical drives
	ret, _, _ := procGetLogicalDrives.Call()
	if ret == 0 {
		return nil, fmt.Errorf("GetLogicalDrives failed")
	}

	drives := uint32(ret)
	var partitions []types.PartitionInfo

	for i := 0; i < 26; i++ {
		if drives&(1<<i) == 0 {
			continue
		}

		drive := string(rune('A'+i)) + ":\\"

		// Get drive type
		drivePtr, _ := windows.UTF16PtrFromString(drive)
		driveType, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr)))

		// Skip CD-ROM and unknown drives
		if driveType == DRIVE_CDROM || driveType == DRIVE_UNKNOWN || driveType == DRIVE_NO_ROOT_DIR {
			continue
		}

		// Get disk space
		var freeBytesAvailable, totalBytes, totalFreeBytes uint64
		ret, _, _ := procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(drivePtr)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&totalFreeBytes)),
		)

		if ret == 0 {
			continue // Skip if we can't get disk space (e.g., empty removable drive)
		}

		// Get filesystem type
		fstype := getFilesystemType(drive)
		used := totalBytes - totalFreeBytes

		partitions = append(partitions, types.PartitionInfo{
			Device:      drive,
			Mountpoint:  drive,
			Fstype:      fstype,
			Total:       totalBytes,
			Used:        used,
			Free:        freeBytesAvailable,
			UsedPercent: calculatePercent(used, totalBytes),
		})
	}

	return partitions, nil
}

// getFilesystemType gets the filesystem type for a drive.
func getFilesystemType(drive string) string {
	drivePtr, _ := windows.UTF16PtrFromString(drive)

	var volumeNameBuffer [256]uint16
	var fsNameBuffer [256]uint16
	var serialNumber, maxComponentLen, fsFlags uint32

	ret, _, _ := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(drivePtr)),
		uintptr(unsafe.Pointer(&volumeNameBuffer[0])),
		uintptr(len(volumeNameBuffer)),
		uintptr(unsafe.Pointer(&serialNumber)),
		uintptr(unsafe.Pointer(&maxComponentLen)),
		uintptr(unsafe.Pointer(&fsFlags)),
		uintptr(unsafe.Pointer(&fsNameBuffer[0])),
		uintptr(len(fsNameBuffer)),
	)

	if ret == 0 {
		return "unknown"
	}

	return strings.TrimRight(windows.UTF16ToString(fsNameBuffer[:]), "\x00")
}

// getIOCounters returns disk I/O statistics on Windows.
// This would require PDH (Performance Data Helper) or WMI access.
func (c *Collector) getIOCounters() (map[string]*types.DiskIOCounters, error) {
	// TODO: Implement using PDH or WMI for disk I/O statistics
	// For now, return empty map
	return make(map[string]*types.DiskIOCounters), nil
}
