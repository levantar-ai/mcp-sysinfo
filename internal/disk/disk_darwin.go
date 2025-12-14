//go:build darwin

package disk

/*
#include <sys/mount.h>
#include <sys/param.h>
#include <stdlib.h>

// Get filesystem statistics
int getStatfs(const char *path, struct statfs *buf) {
    return statfs(path, buf);
}

// Get all mounted filesystems
int getMountedFilesystems(struct statfs **buf, int *count) {
    *count = getmntinfo(buf, MNT_NOWAIT);
    return *count > 0 ? 0 : -1;
}
*/
import "C"

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers disk partition information on macOS.
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

// getPartitions gets mounted filesystems on macOS.
func getPartitions() ([]types.PartitionInfo, error) {
	var mntbuf *C.struct_statfs
	var count C.int

	if C.getMountedFilesystems(&mntbuf, &count) != 0 {
		return nil, fmt.Errorf("getmntinfo failed")
	}

	var partitions []types.PartitionInfo

	// Convert to Go slice
	mounts := (*[1 << 20]C.struct_statfs)(unsafe.Pointer(mntbuf))[:count:count]

	for i := 0; i < int(count); i++ {
		mount := mounts[i]

		fstype := C.GoString(&mount.f_fstypename[0])
		device := C.GoString(&mount.f_mntfromname[0])
		mountpoint := C.GoString(&mount.f_mntonname[0])

		// Skip pseudo filesystems
		if !isRealFilesystem(fstype) {
			continue
		}

		blockSize := uint64(mount.f_bsize)
		total := uint64(mount.f_blocks) * blockSize
		free := uint64(mount.f_bfree) * blockSize
		available := uint64(mount.f_bavail) * blockSize
		used := total - free

		partitions = append(partitions, types.PartitionInfo{
			Device:      device,
			Mountpoint:  mountpoint,
			Fstype:      fstype,
			Total:       total,
			Used:        used,
			Free:        available,
			UsedPercent: calculatePercent(used, total),
		})
	}

	return partitions, nil
}

// isRealFilesystem returns true if the filesystem is a real disk.
func isRealFilesystem(fstype string) bool {
	pseudoFS := map[string]bool{
		"devfs":   true,
		"autofs":  true,
		"volfs":   true,
		"nullfs":  true,
		"synthfs": true,
		"vmhgfs":  true,
	}

	return !pseudoFS[fstype]
}

// getIOCounters returns disk I/O statistics on macOS.
// Note: macOS doesn't provide per-disk I/O stats as easily as Linux.
// This would require IOKit framework access.
func (c *Collector) getIOCounters() (map[string]*types.DiskIOCounters, error) {
	// TODO: Implement using IOKit for disk I/O statistics
	// For now, return empty map
	return make(map[string]*types.DiskIOCounters), nil
}
