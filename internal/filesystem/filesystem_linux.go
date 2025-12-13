//go:build linux

package filesystem

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getMounts retrieves mounted filesystems from /proc/mounts.
func (c *Collector) getMounts() (*types.MountsResult, error) {
	var mounts []types.MountInfo

	// #nosec G304 -- reading from procfs
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return &types.MountsResult{
			Mounts:    mounts,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		device := fields[0]
		mountpoint := fields[1]
		fstype := fields[2]
		options := strings.Split(fields[3], ",")

		// Skip pseudo filesystems
		if strings.HasPrefix(fstype, "proc") || fstype == "sysfs" ||
			fstype == "devpts" || fstype == "cgroup" || fstype == "cgroup2" ||
			fstype == "securityfs" || fstype == "debugfs" || fstype == "fusectl" ||
			fstype == "configfs" || fstype == "hugetlbfs" || fstype == "mqueue" ||
			fstype == "bpf" || fstype == "tracefs" {
			continue
		}

		mount := types.MountInfo{
			Device:     device,
			Mountpoint: mountpoint,
			Fstype:     fstype,
			Options:    options,
		}

		// Get disk usage
		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err == nil {
			// #nosec G115 -- Bsize is always positive on Linux filesystems
			bsize := uint64(stat.Bsize)
			mount.Total = stat.Blocks * bsize
			mount.Free = stat.Bfree * bsize
			mount.Used = mount.Total - mount.Free
			if mount.Total > 0 {
				mount.UsedPct = float64(mount.Used) / float64(mount.Total) * 100
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

// getDiskIO retrieves disk I/O statistics from /proc/diskstats.
func (c *Collector) getDiskIO() (*types.DiskIOResult, error) {
	var devices []types.DiskIOStats

	// #nosec G304 -- reading from procfs
	content, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return &types.DiskIOResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}

		device := fields[2]

		// Skip partition numbers (like sda1, sda2) and virtual devices
		if strings.HasPrefix(device, "loop") || strings.HasPrefix(device, "ram") ||
			strings.HasPrefix(device, "dm-") {
			continue
		}

		// Parse stats
		readCount, _ := strconv.ParseUint(fields[3], 10, 64)
		readMerged, _ := strconv.ParseUint(fields[4], 10, 64)
		// #nosec G115 -- readSectors fits in uint64
		readSectors, _ := strconv.ParseUint(fields[5], 10, 64)
		readTime, _ := strconv.ParseUint(fields[6], 10, 64)
		writeCount, _ := strconv.ParseUint(fields[7], 10, 64)
		writeMerged, _ := strconv.ParseUint(fields[8], 10, 64)
		// #nosec G115 -- writeSectors fits in uint64
		writeSectors, _ := strconv.ParseUint(fields[9], 10, 64)
		writeTime, _ := strconv.ParseUint(fields[10], 10, 64)
		ioInProgress, _ := strconv.ParseUint(fields[11], 10, 64)
		ioTime, _ := strconv.ParseUint(fields[12], 10, 64)
		weightedIOTime, _ := strconv.ParseUint(fields[13], 10, 64)

		devices = append(devices, types.DiskIOStats{
			Device:         device,
			ReadCount:      readCount,
			WriteCount:     writeCount,
			ReadBytes:      readSectors * 512, // Sector size is typically 512 bytes
			WriteBytes:     writeSectors * 512,
			ReadTime:       readTime,
			WriteTime:      writeTime,
			IOTime:         ioTime,
			WeightedIOTime: weightedIOTime,
			IOInProgress:   ioInProgress,
			ReadMerged:     readMerged,
			WriteMerged:    writeMerged,
		})
	}

	return &types.DiskIOResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// getOpenFiles retrieves open file descriptors from /proc.
func (c *Collector) getOpenFiles() (*types.OpenFilesResult, error) {
	var files []types.OpenFile
	var limit int

	// Get system limit
	// #nosec G304 -- reading from procfs
	if content, err := os.ReadFile("/proc/sys/fs/file-max"); err == nil {
		limit, _ = strconv.Atoi(strings.TrimSpace(string(content)))
	}

	// Read /proc for each process
	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return &types.OpenFilesResult{
			Files:     files,
			Count:     0,
			Limit:     limit,
			Timestamp: time.Now(),
		}, nil
	}

	// Limit to avoid too many files
	maxFiles := 1000
	for _, entry := range entries {
		if len(files) >= maxFiles {
			break
		}

		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Get process name
		var procName string
		commPath := filepath.Join(procDir, entry.Name(), "comm")
		// #nosec G304 -- reading from procfs
		if comm, err := os.ReadFile(commPath); err == nil {
			procName = strings.TrimSpace(string(comm))
		}

		// List file descriptors
		fdDir := filepath.Join(procDir, entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			if len(files) >= maxFiles {
				break
			}

			fdNum, _ := strconv.Atoi(fd.Name())
			fdPath := filepath.Join(fdDir, fd.Name())

			// Read symlink to get file path
			target, err := os.Readlink(fdPath)
			if err != nil {
				continue
			}

			// Determine type
			fileType := "file"
			if strings.HasPrefix(target, "socket:") {
				fileType = "socket"
			} else if strings.HasPrefix(target, "pipe:") {
				fileType = "pipe"
			} else if strings.HasPrefix(target, "/dev/") {
				fileType = "device"
			} else if strings.HasPrefix(target, "anon_inode:") {
				fileType = "anon"
			}

			// #nosec G109,G115 -- PID values on Linux fit in int32 (max PID is 4194304)
			files = append(files, types.OpenFile{
				PID:         int32(pid),
				ProcessName: procName,
				FD:          fdNum,
				Path:        target,
				Type:        fileType,
			})
		}
	}

	return &types.OpenFilesResult{
		Files:     files,
		Count:     len(files),
		Limit:     limit,
		Timestamp: time.Now(),
	}, nil
}

// getInodeUsage retrieves inode usage from df -i.
func (c *Collector) getInodeUsage() (*types.InodeUsageResult, error) {
	var filesystems []types.InodeUsage

	// Read /proc/mounts to get filesystems
	// #nosec G304 -- reading from procfs
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return &types.InodeUsageResult{
			Filesystems: filesystems,
			Count:       0,
			Timestamp:   time.Now(),
		}, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mountpoint := fields[1]
		fstype := fields[2]

		// Skip pseudo filesystems
		if strings.HasPrefix(fstype, "proc") || fstype == "sysfs" ||
			fstype == "devpts" || fstype == "cgroup" || fstype == "cgroup2" ||
			fstype == "tmpfs" || fstype == "devtmpfs" {
			continue
		}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountpoint, &stat); err != nil {
			continue
		}

		// Skip if no inodes
		if stat.Files == 0 {
			continue
		}

		used := stat.Files - stat.Ffree
		usedPct := float64(used) / float64(stat.Files) * 100

		filesystems = append(filesystems, types.InodeUsage{
			Filesystem: device,
			Mountpoint: mountpoint,
			Total:      stat.Files,
			Used:       used,
			Free:       stat.Ffree,
			UsedPct:    usedPct,
		})
	}

	return &types.InodeUsageResult{
		Filesystems: filesystems,
		Count:       len(filesystems),
		Timestamp:   time.Now(),
	}, nil
}
