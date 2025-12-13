//go:build darwin

package filesystem

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getMounts retrieves mounted filesystems on macOS.
func (c *Collector) getMounts() (*types.MountsResult, error) {
	var mounts []types.MountInfo

	// Use mount command
	cmd := exec.Command("/sbin/mount")
	output, err := cmd.Output()
	if err != nil {
		return &types.MountsResult{
			Mounts:    mounts,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	mounts = parseMountOutput(output)

	return &types.MountsResult{
		Mounts:    mounts,
		Count:     len(mounts),
		Timestamp: time.Now(),
	}, nil
}

// parseMountOutput parses macOS mount command output.
func parseMountOutput(output []byte) []types.MountInfo {
	var mounts []types.MountInfo
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Format: /dev/disk1s1 on / (apfs, local, read-only, journaled)
	for scanner.Scan() {
		line := scanner.Text()

		// Parse "device on mountpoint (fstype, options)"
		onIdx := strings.Index(line, " on ")
		if onIdx < 0 {
			continue
		}

		device := line[:onIdx]
		rest := line[onIdx+4:]

		parenIdx := strings.Index(rest, " (")
		if parenIdx < 0 {
			continue
		}

		mountpoint := rest[:parenIdx]
		optionsStr := rest[parenIdx+2:]
		optionsStr = strings.TrimSuffix(optionsStr, ")")

		// Parse fstype and options
		parts := strings.Split(optionsStr, ", ")
		fstype := ""
		var options []string
		if len(parts) > 0 {
			fstype = parts[0]
			options = parts[1:]
		}

		// Skip virtual filesystems
		if fstype == "devfs" || fstype == "autofs" || fstype == "nullfs" {
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
			// #nosec G115 -- block size fits in uint64
			mount.Total = uint64(stat.Blocks) * uint64(stat.Bsize)
			// #nosec G115 -- block size fits in uint64
			mount.Free = uint64(stat.Bfree) * uint64(stat.Bsize)
			mount.Used = mount.Total - mount.Free
			if mount.Total > 0 {
				mount.UsedPct = float64(mount.Used) / float64(mount.Total) * 100
			}
		}

		mounts = append(mounts, mount)
	}

	return mounts
}

// getDiskIO retrieves disk I/O statistics on macOS.
func (c *Collector) getDiskIO() (*types.DiskIOResult, error) {
	var devices []types.DiskIOStats

	// Use iostat command
	cmd := exec.Command("/usr/sbin/iostat", "-d", "-c", "2", "-w", "1")
	output, err := cmd.Output()
	if err != nil {
		return &types.DiskIOResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	devices = parseIOStatDarwin(output)

	return &types.DiskIOResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// parseIOStatDarwin parses macOS iostat output.
func parseIOStatDarwin(output []byte) []types.DiskIOStats {
	var devices []types.DiskIOStats
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var headers []string
	lineCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) == 0 {
			continue
		}

		// Skip header lines
		if strings.Contains(line, "disk") && strings.Contains(line, "KB/t") {
			// Parse headers
			for i := 0; i < len(fields); i += 3 {
				if i < len(fields) {
					headers = append(headers, fields[i])
				}
			}
			continue
		}

		lineCount++
		// Use second iteration for more accurate values
		if lineCount < 2 {
			continue
		}

		// Parse device stats (3 fields per device: KB/t, tps, MB/s)
		for i := 0; i < len(headers) && (i*3)+2 < len(fields); i++ {
			tps, _ := strconv.ParseFloat(fields[i*3+1], 64)
			mbps, _ := strconv.ParseFloat(fields[i*3+2], 64)

			devices = append(devices, types.DiskIOStats{
				Device:     headers[i],
				ReadBytes:  uint64(mbps * 1024 * 1024 / 2), // Estimate
				WriteBytes: uint64(mbps * 1024 * 1024 / 2), // Estimate
				ReadCount:  uint64(tps / 2),                // Estimate
				WriteCount: uint64(tps / 2),                // Estimate
			})
		}
		break // Only need one iteration
	}

	return devices
}

// getOpenFiles retrieves open file descriptors on macOS.
func (c *Collector) getOpenFiles() (*types.OpenFilesResult, error) {
	var files []types.OpenFile

	// Use lsof command
	cmd := exec.Command("/usr/sbin/lsof", "-F", "pcftn")
	output, err := cmd.Output()
	if err != nil {
		return &types.OpenFilesResult{
			Files:     files,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	files = parseLsofOutput(output)

	// Get limit
	var rlimit syscall.Rlimit
	limit := 0
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err == nil {
		// #nosec G115 -- rlimit fits in int
		limit = int(rlimit.Max)
	}

	return &types.OpenFilesResult{
		Files:     files,
		Count:     len(files),
		Limit:     limit,
		Timestamp: time.Now(),
	}, nil
}

// parseLsofOutput parses lsof -F output.
func parseLsofOutput(output []byte) []types.OpenFile {
	var files []types.OpenFile
	scanner := bufio.NewScanner(bytes.NewReader(output))

	var currentPID int32
	var currentName string
	var currentFD int
	var currentType, currentPath string

	maxFiles := 1000

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 2 {
			continue
		}

		if len(files) >= maxFiles {
			break
		}

		prefix := line[0]
		value := line[1:]

		switch prefix {
		case 'p':
			// New process
			if p, err := strconv.Atoi(value); err == nil {
				currentPID = int32(p)
			}
		case 'c':
			currentName = value
		case 'f':
			// File descriptor
			if currentPath != "" {
				files = append(files, types.OpenFile{
					PID:         currentPID,
					ProcessName: currentName,
					FD:          currentFD,
					Path:        currentPath,
					Type:        currentType,
				})
			}
			if fd, err := strconv.Atoi(value); err == nil {
				currentFD = fd
			} else {
				currentFD = 0
			}
			currentPath = ""
			currentType = ""
		case 't':
			currentType = value
		case 'n':
			currentPath = value
		}
	}

	// Add last entry
	if currentPath != "" && len(files) < maxFiles {
		files = append(files, types.OpenFile{
			PID:         currentPID,
			ProcessName: currentName,
			FD:          currentFD,
			Path:        currentPath,
			Type:        currentType,
		})
	}

	return files
}

// getInodeUsage retrieves inode usage on macOS.
func (c *Collector) getInodeUsage() (*types.InodeUsageResult, error) {
	var filesystems []types.InodeUsage

	// Use df -i
	cmd := exec.Command("/bin/df", "-i")
	output, err := cmd.Output()
	if err != nil {
		return &types.InodeUsageResult{
			Filesystems: filesystems,
			Count:       0,
			Timestamp:   time.Now(),
		}, nil
	}

	filesystems = parseDfInodes(output)

	return &types.InodeUsageResult{
		Filesystems: filesystems,
		Count:       len(filesystems),
		Timestamp:   time.Now(),
	}, nil
}

// parseDfInodes parses df -i output.
func parseDfInodes(output []byte) []types.InodeUsage {
	var filesystems []types.InodeUsage
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 9 {
			continue
		}

		filesystem := fields[0]
		mountpoint := fields[8]

		// Skip virtual filesystems
		if strings.HasPrefix(filesystem, "/dev/") == false && filesystem != "map" {
			continue
		}

		iused, _ := strconv.ParseUint(fields[5], 10, 64)
		ifree, _ := strconv.ParseUint(fields[6], 10, 64)
		total := iused + ifree

		usedPct := float64(0)
		if total > 0 {
			usedPct = float64(iused) / float64(total) * 100
		}

		filesystems = append(filesystems, types.InodeUsage{
			Filesystem: filesystem,
			Mountpoint: mountpoint,
			Total:      total,
			Used:       iused,
			Free:       ifree,
			UsedPct:    usedPct,
		})
	}

	return filesystems
}
