//go:build linux

package disk

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers disk partition information on Linux.
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

// getPartitions reads mounted filesystems from /proc/mounts.
func getPartitions() ([]types.PartitionInfo, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var partitions []types.PartitionInfo
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		device := fields[0]
		mountpoint := fields[1]
		fstype := fields[2]

		// Skip pseudo filesystems
		if !isRealFilesystem(device, fstype) {
			continue
		}

		// Get disk usage
		var stat syscall.Statfs_t
		err := syscall.Statfs(mountpoint, &stat)
		if err != nil {
			continue // Skip if we can't stat
		}

		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bfree * uint64(stat.Bsize)
		available := stat.Bavail * uint64(stat.Bsize)
		used := total - free

		partitions = append(partitions, types.PartitionInfo{
			Device:      device,
			Mountpoint:  mountpoint,
			Fstype:      fstype,
			Total:       total,
			Used:        used,
			Free:        available, // Report available (user-accessible) space
			UsedPercent: calculatePercent(used, total),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return partitions, nil
}

// isRealFilesystem returns true if the filesystem is a real disk.
func isRealFilesystem(device, fstype string) bool {
	// Skip pseudo filesystems
	pseudoFS := map[string]bool{
		"sysfs":       true,
		"proc":        true,
		"devtmpfs":    true,
		"devpts":      true,
		"tmpfs":       true,
		"securityfs":  true,
		"cgroup":      true,
		"cgroup2":     true,
		"pstore":      true,
		"debugfs":     true,
		"hugetlbfs":   true,
		"mqueue":      true,
		"fusectl":     true,
		"configfs":    true,
		"binfmt_misc": true,
		"autofs":      true,
		"rpc_pipefs":  true,
		"nfsd":        true,
		"overlay":     true,
		"nsfs":        true,
		"tracefs":     true,
		"bpf":         true,
	}

	if pseudoFS[fstype] {
		return false
	}

	// Skip if device doesn't look like a real device
	if !strings.HasPrefix(device, "/dev/") {
		// Allow certain paths like network mounts
		if !strings.Contains(device, ":/") && !strings.HasPrefix(device, "//") {
			return false
		}
	}

	return true
}

// getIOCounters returns disk I/O statistics from /proc/diskstats.
func (c *Collector) getIOCounters() (map[string]*types.DiskIOCounters, error) {
	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	result := make(map[string]*types.DiskIOCounters)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		name := fields[2]

		// Skip partitions (we want whole disks)
		// Partitions typically have numbers at the end like sda1, nvme0n1p1
		if isPartition(name) {
			continue
		}

		readCompleted, _ := strconv.ParseUint(fields[3], 10, 64)
		readMerged, _ := strconv.ParseUint(fields[4], 10, 64)
		readSectors, _ := strconv.ParseUint(fields[5], 10, 64)
		readTime, _ := strconv.ParseUint(fields[6], 10, 64)
		writeCompleted, _ := strconv.ParseUint(fields[7], 10, 64)
		writeMerged, _ := strconv.ParseUint(fields[8], 10, 64)
		writeSectors, _ := strconv.ParseUint(fields[9], 10, 64)
		writeTime, _ := strconv.ParseUint(fields[10], 10, 64)
		iopsInProgress, _ := strconv.ParseUint(fields[11], 10, 64)
		ioTime, _ := strconv.ParseUint(fields[12], 10, 64)
		weightedIOTime, _ := strconv.ParseUint(fields[13], 10, 64)

		// Sector size is typically 512 bytes
		const sectorSize = 512

		result[name] = &types.DiskIOCounters{
			ReadCount:      readCompleted,
			WriteCount:     writeCompleted,
			ReadBytes:      readSectors * sectorSize,
			WriteBytes:     writeSectors * sectorSize,
			ReadTime:       readTime,
			WriteTime:      writeTime,
			ReadMerged:     readMerged,
			WriteMerged:    writeMerged,
			IopsInProgress: iopsInProgress,
			IoTime:         ioTime,
			WeightedIoTime: weightedIOTime,
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// isPartition checks if a device name looks like a partition.
func isPartition(name string) bool {
	// NVMe partitions: nvme0n1p1
	if strings.Contains(name, "nvme") && strings.Contains(name, "p") {
		return true
	}
	// Standard partitions: sda1, vda1
	if len(name) > 0 {
		lastChar := name[len(name)-1]
		if lastChar >= '0' && lastChar <= '9' {
			// Check if it ends with letters followed by numbers (e.g., sda1)
			for i := len(name) - 1; i >= 0; i-- {
				if name[i] < '0' || name[i] > '9' {
					// Found a letter
					if i > 0 && (strings.HasPrefix(name, "sd") || strings.HasPrefix(name, "vd") || strings.HasPrefix(name, "hd")) {
						return true
					}
					break
				}
			}
		}
	}
	return false
}
