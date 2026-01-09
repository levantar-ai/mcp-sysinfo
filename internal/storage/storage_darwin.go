//go:build darwin

package storage

import (
	"bufio"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getSMARTHealth retrieves SMART health data on macOS.
func (c *Collector) getSMARTHealth() (*types.SMARTHealthResult, error) {
	var disks []types.SMARTDisk

	// Try smartctl (via Homebrew)
	smartctlPath, err := cmdexec.LookPath("smartctl")
	if err != nil {
		// Fall back to diskutil
		return getSMARTFromDiskutil()
	}

	// Get list of disks
	output, err := cmdexec.Command("diskutil", "list", "-plist").Output()
	if err != nil {
		return &types.SMARTHealthResult{
			Disks:     disks,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// Parse disk names from diskutil output
	devices := extractDiskNames(string(output))

	for _, device := range devices {
		disk := getSMARTForDeviceDarwin(device, smartctlPath)
		if disk != nil {
			disks = append(disks, *disk)
		}
	}

	return &types.SMARTHealthResult{
		Disks:     disks,
		Count:     len(disks),
		Timestamp: time.Now(),
	}, nil
}

// extractDiskNames extracts disk device names.
func extractDiskNames(output string) []string {
	var devices []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "/dev/disk") && !strings.Contains(line, "s") {
			// Extract disk0, disk1, etc.
			start := strings.Index(line, "/dev/disk")
			if start >= 0 {
				end := start + 10
				for end < len(line) && (line[end] >= '0' && line[end] <= '9') {
					end++
				}
				device := line[start:end]
				if !contains(devices, device) {
					devices = append(devices, device)
				}
			}
		}
	}
	return devices
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// getSMARTFromDiskutil uses diskutil for basic disk info when smartctl isn't available.
func getSMARTFromDiskutil() (*types.SMARTHealthResult, error) {
	var disks []types.SMARTDisk

	output, err := cmdexec.Command("diskutil", "info", "-all").Output()
	if err != nil {
		return &types.SMARTHealthResult{
			Disks:     disks,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	var currentDisk *types.SMARTDisk
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Device Identifier:") {
			if currentDisk != nil {
				disks = append(disks, *currentDisk)
			}
			currentDisk = &types.SMARTDisk{
				Healthy: true,
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				currentDisk.Device = "/dev/" + strings.TrimSpace(parts[1])
			}
		} else if currentDisk != nil {
			if strings.HasPrefix(line, "Device / Media Name:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					currentDisk.Model = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "Solid State:") {
				if strings.Contains(line, "Yes") {
					currentDisk.Type = "SSD"
				} else {
					currentDisk.Type = "HDD"
				}
			} else if strings.HasPrefix(line, "Protocol:") {
				if strings.Contains(line, "NVMe") {
					currentDisk.Type = "NVMe"
				}
			}
		}
	}

	if currentDisk != nil {
		disks = append(disks, *currentDisk)
	}

	// Filter to only physical disks
	var physicalDisks []types.SMARTDisk
	for _, d := range disks {
		if !strings.Contains(d.Device, "s") { // Skip partitions
			physicalDisks = append(physicalDisks, d)
		}
	}

	return &types.SMARTHealthResult{
		Disks:     physicalDisks,
		Count:     len(physicalDisks),
		Timestamp: time.Now(),
	}, nil
}

// getSMARTForDeviceDarwin gets SMART data for a device using smartctl.
func getSMARTForDeviceDarwin(device, smartctlPath string) *types.SMARTDisk {
	disk := &types.SMARTDisk{
		Device:  device,
		Healthy: true,
	}

	output, err := cmdexec.Command(smartctlPath, "-a", "-j", device).Output()
	if err != nil {
		disk.Error = "smartctl failed for device"
		return disk
	}

	var smartData struct {
		ModelName       string `json:"model_name"`
		SerialNumber    string `json:"serial_number"`
		FirmwareVersion string `json:"firmware_version"`
		SmartStatus     struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		Temperature struct {
			Current int `json:"current"`
		} `json:"temperature"`
	}

	if err := json.Unmarshal(output, &smartData); err != nil {
		disk.Error = "failed to parse SMART data"
		return disk
	}

	disk.Model = smartData.ModelName
	disk.Serial = smartData.SerialNumber
	disk.Firmware = smartData.FirmwareVersion
	disk.Healthy = smartData.SmartStatus.Passed
	disk.Temperature = smartData.Temperature.Current

	return disk
}

// getIOLatency retrieves I/O latency statistics on macOS.
func (c *Collector) getIOLatency() (*types.IOLatencyResult, error) {
	var devices []types.IOLatencyDevice

	// Use iostat for basic I/O stats
	output, err := cmdexec.Command("iostat", "-d", "-c", "1").Output()
	if err != nil {
		return &types.IOLatencyResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	lines := strings.Split(string(output), "\n")
	headerFound := false

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		// Look for header line
		if fields[0] == "disk0" || strings.HasPrefix(fields[0], "disk") {
			headerFound = true
		}

		if headerFound && strings.HasPrefix(fields[0], "disk") {
			if len(fields) >= 3 {
				kbPerT, _ := strconv.ParseFloat(fields[1], 64)
				tps, _ := strconv.ParseFloat(fields[2], 64)

				devices = append(devices, types.IOLatencyDevice{
					Device:          "/dev/" + fields[0],
					ReadIOPS:        tps / 2, // Approximate split
					WriteIOPS:       tps / 2,
					ReadThroughput:  uint64(kbPerT * 1024 * tps / 2),
					WriteThroughput: uint64(kbPerT * 1024 * tps / 2),
				})
			}
		}
	}

	return &types.IOLatencyResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// getVolumeStatus retrieves volume status on macOS (APFS, ZFS if installed).
func (c *Collector) getVolumeStatus() (*types.VolumeStatusResult, error) {
	result := &types.VolumeStatusResult{
		Timestamp: time.Now(),
	}

	// Check for ZFS (if installed via OpenZFS)
	if zpoolPath, err := cmdexec.LookPath("zpool"); err == nil {
		if pools, err := getZFSPoolsDarwin(zpoolPath); err == nil && len(pools) > 0 {
			result.ZFSPools = pools
			result.Count += len(pools)
		}
	}

	// Check for Apple RAID
	if arrays, err := getAppleRAID(); err == nil && len(arrays) > 0 {
		result.RAIDArrays = arrays
		result.Count += len(arrays)
	}

	return result, nil
}

// getZFSPoolsDarwin retrieves ZFS pools on macOS.
func getZFSPoolsDarwin(zpoolPath string) ([]types.ZFSPool, error) {
	var pools []types.ZFSPool

	output, err := cmdexec.Command(zpoolPath, "list", "-H", "-o", "name,size,alloc,free,frag,health").Output()
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}

		pool := types.ZFSPool{
			Name:   fields[0],
			Health: fields[5],
			State:  fields[5],
		}

		pools = append(pools, pool)
	}

	return pools, nil
}

// getAppleRAID retrieves Apple RAID information.
func getAppleRAID() ([]types.RAIDArray, error) {
	var arrays []types.RAIDArray

	output, err := cmdexec.Command("diskutil", "appleRAID", "list").Output()
	if err != nil {
		return nil, err
	}

	// Parse Apple RAID output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "RAID Set") {
			// Extract RAID info
			arrays = append(arrays, types.RAIDArray{
				Device: "AppleRAID",
				State:  "active",
			})
		}
	}

	return arrays, nil
}

// getMountChanges retrieves current mounts on macOS.
func (c *Collector) getMountChanges() (*types.MountChangesResult, error) {
	var mounts []types.MountInfo

	output, err := cmdexec.Command("mount").Output()
	if err != nil {
		return &types.MountChangesResult{
			CurrentMounts: mounts,
			Count:         0,
			Timestamp:     time.Now(),
		}, nil
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Format: /dev/disk1s1 on / (apfs, local, journaled)
		if !strings.Contains(line, " on ") {
			continue
		}

		parts := strings.SplitN(line, " on ", 2)
		if len(parts) < 2 {
			continue
		}

		device := parts[0]
		rest := parts[1]

		// Extract mountpoint and options
		parenIdx := strings.Index(rest, " (")
		if parenIdx < 0 {
			continue
		}

		mountpoint := rest[:parenIdx]
		optionsStr := strings.Trim(rest[parenIdx+2:], ")")
		options := strings.Split(optionsStr, ", ")

		// Skip devfs and other pseudo filesystems
		if device == "devfs" || device == "map" {
			continue
		}

		fstype := ""
		if len(options) > 0 {
			fstype = options[0]
		}

		mounts = append(mounts, types.MountInfo{
			Device:     device,
			Mountpoint: mountpoint,
			Fstype:     fstype,
			Options:    options,
		})
	}

	return &types.MountChangesResult{
		CurrentMounts: mounts,
		Count:         len(mounts),
		Timestamp:     time.Now(),
	}, nil
}

// getFSEvents returns filesystem event monitoring info on macOS.
func (c *Collector) getFSEvents() (*types.FSEventsResult, error) {
	return &types.FSEventsResult{
		Supported: true,
		Message:   "Filesystem events available via FSEvents framework. Use fsnotify library for real-time monitoring.",
		Timestamp: time.Now(),
	}, nil
}
