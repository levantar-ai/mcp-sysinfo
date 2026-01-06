//go:build linux

package storage

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getSMARTHealth retrieves SMART health data on Linux.
func (c *Collector) getSMARTHealth() (*types.SMARTHealthResult, error) {
	var disks []types.SMARTDisk

	// Find block devices
	devices, err := findBlockDevices()
	if err != nil {
		return &types.SMARTHealthResult{
			Disks:     disks,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	for _, device := range devices {
		disk := getSMARTForDevice(device)
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

// findBlockDevices finds physical block devices.
func findBlockDevices() ([]string, error) {
	var devices []string

	// Read /sys/block for block devices
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		name := entry.Name()
		// Skip virtual devices
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "sr") {
			continue
		}
		devices = append(devices, "/dev/"+name)
	}

	return devices, nil
}

// getSMARTForDevice gets SMART data for a single device.
func getSMARTForDevice(device string) *types.SMARTDisk {
	disk := &types.SMARTDisk{
		Device:  device,
		Healthy: true,
	}

	// Try smartctl with JSON output
	smartctlPath, err := cmdexec.LookPath("smartctl")
	if err != nil {
		// smartctl not available, try basic info from sysfs
		return getSysfsDeviceInfo(device)
	}

	// Get SMART data in JSON format
	output, err := cmdexec.Command(smartctlPath, "-a", "-j", device).Output()
	if err != nil {
		// Try without JSON for older smartctl
		return getSMARTFromText(device, smartctlPath)
	}

	var smartData struct {
		Device struct {
			Name     string `json:"name"`
			Type     string `json:"type"`
			Protocol string `json:"protocol"`
		} `json:"device"`
		ModelName    string `json:"model_name"`
		SerialNumber string `json:"serial_number"`
		FirmwareVersion string `json:"firmware_version"`
		SmartStatus struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		Temperature struct {
			Current int `json:"current"`
		} `json:"temperature"`
		PowerOnTime struct {
			Hours int `json:"hours"`
		} `json:"power_on_time"`
		PowerCycleCount int `json:"power_cycle_count"`
		NvmeSmartHealthInformationLog *struct {
			PercentageUsed     int `json:"percentage_used"`
			AvailableSpare     int `json:"available_spare"`
			AvailableSpareThreshold int `json:"available_spare_threshold"`
			DataUnitsRead      uint64 `json:"data_units_read"`
			DataUnitsWritten   uint64 `json:"data_units_written"`
			MediaErrors        uint64 `json:"media_errors"`
			CriticalWarning    int `json:"critical_warning"`
		} `json:"nvme_smart_health_information_log"`
		AtaSmartAttributes struct {
			Table []struct {
				ID        int    `json:"id"`
				Name      string `json:"name"`
				Value     int    `json:"value"`
				Worst     int    `json:"worst"`
				Thresh    int    `json:"thresh"`
				Raw       struct {
					Value uint64 `json:"value"`
				} `json:"raw"`
			} `json:"table"`
		} `json:"ata_smart_attributes"`
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
	disk.PowerOnHours = uint64(smartData.PowerOnTime.Hours)
	disk.PowerCycles = uint64(smartData.PowerCycleCount)

	// Determine disk type
	if smartData.Device.Protocol == "NVMe" || strings.Contains(device, "nvme") {
		disk.Type = "NVMe"
		if smartData.NvmeSmartHealthInformationLog != nil {
			disk.NVMeHealth = &types.NVMeHealthInfo{
				PercentageUsed:   smartData.NvmeSmartHealthInformationLog.PercentageUsed,
				AvailableSpare:   smartData.NvmeSmartHealthInformationLog.AvailableSpare,
				SpareThreshold:   smartData.NvmeSmartHealthInformationLog.AvailableSpareThreshold,
				DataUnitsRead:    smartData.NvmeSmartHealthInformationLog.DataUnitsRead,
				DataUnitsWritten: smartData.NvmeSmartHealthInformationLog.DataUnitsWritten,
				MediaErrors:      smartData.NvmeSmartHealthInformationLog.MediaErrors,
				CriticalWarning:  smartData.NvmeSmartHealthInformationLog.CriticalWarning,
			}
		}
	} else {
		// Check for SSD vs HDD
		disk.Type = "HDD"
		for _, attr := range smartData.AtaSmartAttributes.Table {
			if attr.Name == "SSD_Life_Left" || attr.Name == "Wear_Leveling_Count" ||
				attr.Name == "Media_Wearout_Indicator" {
				disk.Type = "SSD"
				break
			}
		}
	}

	// Parse ATA SMART attributes
	for _, attr := range smartData.AtaSmartAttributes.Table {
		status := "ok"
		if attr.Value <= attr.Thresh && attr.Thresh > 0 {
			status = "critical"
			disk.Warnings = append(disk.Warnings, attr.Name+" below threshold")
		} else if attr.Worst <= attr.Thresh && attr.Thresh > 0 {
			status = "warning"
		}

		disk.Attributes = append(disk.Attributes, types.SMARTAttribute{
			ID:        attr.ID,
			Name:      attr.Name,
			Value:     attr.Value,
			Worst:     attr.Worst,
			Threshold: attr.Thresh,
			RawValue:  attr.Raw.Value,
			Status:    status,
		})
	}

	return disk
}

// getSMARTFromText parses smartctl text output (fallback for older versions).
func getSMARTFromText(device, smartctlPath string) *types.SMARTDisk {
	disk := &types.SMARTDisk{
		Device:  device,
		Healthy: true,
		Type:    "Unknown",
	}

	output, err := cmdexec.Command(smartctlPath, "-a", device).Output()
	if err != nil {
		disk.Error = "smartctl failed"
		return disk
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Model Family:") || strings.HasPrefix(line, "Device Model:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				disk.Model = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Serial Number:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				disk.Serial = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "SMART overall-health") {
			if strings.Contains(line, "PASSED") {
				disk.Healthy = true
			} else {
				disk.Healthy = false
			}
		}
	}

	return disk
}

// getSysfsDeviceInfo gets basic device info from sysfs when smartctl isn't available.
func getSysfsDeviceInfo(device string) *types.SMARTDisk {
	disk := &types.SMARTDisk{
		Device:  device,
		Healthy: true,
		Type:    "Unknown",
	}

	baseName := filepath.Base(device)
	sysPath := "/sys/block/" + baseName + "/device"

	// Try to read model
	if data, err := os.ReadFile(sysPath + "/model"); err == nil {
		disk.Model = strings.TrimSpace(string(data))
	}

	// Determine type from device name
	if strings.HasPrefix(baseName, "nvme") {
		disk.Type = "NVMe"
	} else if strings.HasPrefix(baseName, "sd") || strings.HasPrefix(baseName, "hd") {
		disk.Type = "HDD/SSD"
	}

	disk.Error = "smartctl not available, limited info"
	return disk
}

// getIOLatency retrieves I/O latency statistics on Linux.
func (c *Collector) getIOLatency() (*types.IOLatencyResult, error) {
	var devices []types.IOLatencyDevice

	// Read /proc/diskstats
	// #nosec G304 -- reading from procfs
	content, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return &types.IOLatencyResult{
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

		name := fields[2]

		// Skip partitions
		if isPartition(name) {
			continue
		}

		// Parse stats
		readCompleted, _ := strconv.ParseUint(fields[3], 10, 64)
		readTime, _ := strconv.ParseUint(fields[6], 10, 64) // ms
		writeCompleted, _ := strconv.ParseUint(fields[7], 10, 64)
		writeTime, _ := strconv.ParseUint(fields[10], 10, 64) // ms
		iopsInProgress, _ := strconv.ParseUint(fields[11], 10, 64)
		ioTime, _ := strconv.ParseUint(fields[12], 10, 64) // ms

		// Calculate latencies (ms)
		var readLatency, writeLatency float64
		if readCompleted > 0 {
			readLatency = float64(readTime) / float64(readCompleted)
		}
		if writeCompleted > 0 {
			writeLatency = float64(writeTime) / float64(writeCompleted)
		}

		// Parse sectors for throughput
		readSectors, _ := strconv.ParseUint(fields[5], 10, 64)
		writeSectors, _ := strconv.ParseUint(fields[9], 10, 64)
		const sectorSize = 512

		devices = append(devices, types.IOLatencyDevice{
			Device:          "/dev/" + name,
			ReadLatencyMs:   readLatency,
			WriteLatencyMs:  writeLatency,
			ReadIOPS:        float64(readCompleted),
			WriteIOPS:       float64(writeCompleted),
			ReadThroughput:  readSectors * sectorSize,
			WriteThroughput: writeSectors * sectorSize,
			QueueDepth:      iopsInProgress,
			Utilization:     float64(ioTime) / 10, // ioTime is in ms, convert to %
		})
	}

	return &types.IOLatencyResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// isPartition checks if a device name looks like a partition.
func isPartition(name string) bool {
	// NVMe partitions: nvme0n1p1
	if strings.Contains(name, "nvme") && strings.Contains(name, "p") {
		parts := strings.Split(name, "p")
		if len(parts) > 1 {
			_, err := strconv.Atoi(parts[len(parts)-1])
			return err == nil
		}
	}
	// Standard partitions: sda1, vda1
	re := regexp.MustCompile(`^(sd|vd|hd|xvd)[a-z]+\d+$`)
	return re.MatchString(name)
}

// getVolumeStatus retrieves ZFS, LVM, and RAID status on Linux.
func (c *Collector) getVolumeStatus() (*types.VolumeStatusResult, error) {
	result := &types.VolumeStatusResult{
		Timestamp: time.Now(),
	}

	// Check ZFS
	if pools, err := getZFSPools(); err == nil && len(pools) > 0 {
		result.ZFSPools = pools
		result.Count += len(pools)
	}

	// Check LVM
	if groups, err := getLVMGroups(); err == nil && len(groups) > 0 {
		result.LVMGroups = groups
		result.Count += len(groups)
	}

	// Check MD RAID
	if arrays, err := getMDRAIDArrays(); err == nil && len(arrays) > 0 {
		result.RAIDArrays = arrays
		result.Count += len(arrays)
	}

	return result, nil
}

// getZFSPools retrieves ZFS pool information.
func getZFSPools() ([]types.ZFSPool, error) {
	var pools []types.ZFSPool

	zpoolPath, err := cmdexec.LookPath("zpool")
	if err != nil {
		return nil, err
	}

	// Get pool list
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
			Name:          fields[0],
			Size:          parseZFSSize(fields[1]),
			Allocated:     parseZFSSize(fields[2]),
			Free:          parseZFSSize(fields[3]),
			Fragmentation: parsePercent(fields[4]),
			Health:        fields[5],
			State:         fields[5],
		}

		pools = append(pools, pool)
	}

	return pools, nil
}

// parseZFSSize parses ZFS size strings like "1.5T", "500G".
func parseZFSSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "-" {
		return 0
	}

	multipliers := map[byte]uint64{
		'K': 1024,
		'M': 1024 * 1024,
		'G': 1024 * 1024 * 1024,
		'T': 1024 * 1024 * 1024 * 1024,
		'P': 1024 * 1024 * 1024 * 1024 * 1024,
	}

	if len(s) == 0 {
		return 0
	}

	lastChar := s[len(s)-1]
	if mult, ok := multipliers[lastChar]; ok {
		numStr := s[:len(s)-1]
		val, _ := strconv.ParseFloat(numStr, 64)
		return uint64(val * float64(mult))
	}

	val, _ := strconv.ParseUint(s, 10, 64)
	return val
}

// parsePercent parses percentage strings like "45%".
func parsePercent(s string) int {
	s = strings.TrimSuffix(strings.TrimSpace(s), "%")
	if s == "-" {
		return 0
	}
	val, _ := strconv.Atoi(s)
	return val
}

// getLVMGroups retrieves LVM volume group information.
func getLVMGroups() ([]types.LVMGroup, error) {
	var groups []types.LVMGroup

	vgsPath, err := cmdexec.LookPath("vgs")
	if err != nil {
		return nil, err
	}

	output, err := cmdexec.Command(vgsPath, "--reportformat", "json", "-o", "vg_name,vg_size,vg_free,pv_count,lv_count").Output()
	if err != nil {
		// Try without JSON
		return getLVMGroupsText(vgsPath)
	}

	var vgsData struct {
		Report []struct {
			Vg []struct {
				VgName  string `json:"vg_name"`
				VgSize  string `json:"vg_size"`
				VgFree  string `json:"vg_free"`
				PvCount string `json:"pv_count"`
				LvCount string `json:"lv_count"`
			} `json:"vg"`
		} `json:"report"`
	}

	if err := json.Unmarshal(output, &vgsData); err != nil {
		return nil, err
	}

	for _, report := range vgsData.Report {
		for _, vg := range report.Vg {
			pvCount, _ := strconv.Atoi(vg.PvCount)
			lvCount, _ := strconv.Atoi(vg.LvCount)
			groups = append(groups, types.LVMGroup{
				Name:    vg.VgName,
				Size:    parseLVMSize(vg.VgSize),
				Free:    parseLVMSize(vg.VgFree),
				PVCount: pvCount,
				LVCount: lvCount,
			})
		}
	}

	return groups, nil
}

// getLVMGroupsText parses LVM output in text format.
func getLVMGroupsText(vgsPath string) ([]types.LVMGroup, error) {
	var groups []types.LVMGroup

	output, err := cmdexec.Command(vgsPath, "--noheadings", "-o", "vg_name,vg_size,vg_free,pv_count,lv_count").Output()
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}

		pvCount, _ := strconv.Atoi(fields[3])
		lvCount, _ := strconv.Atoi(fields[4])
		groups = append(groups, types.LVMGroup{
			Name:    fields[0],
			Size:    parseLVMSize(fields[1]),
			Free:    parseLVMSize(fields[2]),
			PVCount: pvCount,
			LVCount: lvCount,
		})
	}

	return groups, nil
}

// parseLVMSize parses LVM size strings.
func parseLVMSize(s string) uint64 {
	s = strings.TrimSpace(s)
	// Remove trailing unit letters
	s = strings.TrimRight(s, "bBkKmMgGtTpP")
	// LVM sizes are typically in bytes or with suffix
	val, _ := strconv.ParseFloat(s, 64)
	return uint64(val)
}

// getMDRAIDArrays retrieves MD RAID array information from /proc/mdstat.
func getMDRAIDArrays() ([]types.RAIDArray, error) {
	var arrays []types.RAIDArray

	// #nosec G304 -- reading from procfs
	content, err := os.ReadFile("/proc/mdstat")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	var currentArray *types.RAIDArray

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// New array line: md0 : active raid1 sda1[0] sdb1[1]
		if strings.HasPrefix(line, "md") && strings.Contains(line, " : ") {
			if currentArray != nil {
				arrays = append(arrays, *currentArray)
			}

			parts := strings.SplitN(line, " : ", 2)
			if len(parts) < 2 {
				continue
			}

			device := "/dev/" + parts[0]
			rest := strings.Fields(parts[1])

			state := "unknown"
			level := ""
			if len(rest) > 0 {
				state = rest[0]
			}
			if len(rest) > 1 {
				level = rest[1]
			}

			currentArray = &types.RAIDArray{
				Device: device,
				Level:  level,
				State:  state,
			}

			// Parse member disks
			for _, part := range rest[2:] {
				if strings.Contains(part, "[") {
					diskName := strings.Split(part, "[")[0]
					role := "active"
					if strings.Contains(part, "(S)") {
						role = "spare"
					} else if strings.Contains(part, "(F)") {
						role = "faulty"
					}
					currentArray.Members = append(currentArray.Members, types.RAIDMember{
						Device: "/dev/" + diskName,
						Role:   role,
						State:  "active",
					})
				}
			}
			currentArray.Disks = len(currentArray.Members)
		}

		// Size line: 1234567 blocks super 1.2 [2/2] [UU]
		if currentArray != nil && strings.Contains(line, "blocks") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				blocks, _ := strconv.ParseUint(fields[0], 10, 64)
				currentArray.Size = blocks * 1024 // blocks to bytes
			}

			// Parse [2/2] for disk counts
			for _, f := range fields {
				if strings.HasPrefix(f, "[") && strings.Contains(f, "/") {
					f = strings.Trim(f, "[]")
					parts := strings.Split(f, "/")
					if len(parts) == 2 {
						currentArray.ActiveDisks, _ = strconv.Atoi(parts[0])
						currentArray.Disks, _ = strconv.Atoi(parts[1])
					}
				}
			}

			// Check sync progress
			if strings.Contains(line, "recovery") || strings.Contains(line, "resync") {
				currentArray.State = "rebuilding"
			}
		}

		// Sync progress line
		if currentArray != nil && strings.Contains(line, "recovery =") {
			re := regexp.MustCompile(`recovery\s*=\s*(\d+\.?\d*%)`)
			if matches := re.FindStringSubmatch(line); len(matches) > 1 {
				currentArray.SyncProgress = matches[1]
			}
		}
	}

	if currentArray != nil {
		arrays = append(arrays, *currentArray)
	}

	return arrays, nil
}

// getMountChanges retrieves current mounts on Linux.
func (c *Collector) getMountChanges() (*types.MountChangesResult, error) {
	var mounts []types.MountInfo

	// #nosec G304 -- reading from procfs
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return &types.MountChangesResult{
			CurrentMounts: mounts,
			Count:         0,
			Timestamp:     time.Now(),
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
		if isPseudoFS(fstype) {
			continue
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

// isPseudoFS returns true if the filesystem is a pseudo filesystem.
func isPseudoFS(fstype string) bool {
	pseudoFS := map[string]bool{
		"sysfs": true, "proc": true, "devtmpfs": true, "devpts": true,
		"tmpfs": true, "securityfs": true, "cgroup": true, "cgroup2": true,
		"pstore": true, "debugfs": true, "hugetlbfs": true, "mqueue": true,
		"fusectl": true, "configfs": true, "binfmt_misc": true, "autofs": true,
		"rpc_pipefs": true, "nfsd": true, "nsfs": true, "tracefs": true, "bpf": true,
	}
	return pseudoFS[fstype]
}

// getFSEvents returns filesystem event monitoring info on Linux.
func (c *Collector) getFSEvents() (*types.FSEventsResult, error) {
	// Check if inotify is available
	supported := false
	if _, err := os.Stat("/proc/sys/fs/inotify"); err == nil {
		supported = true
	}

	return &types.FSEventsResult{
		Supported: supported,
		Message:   "Filesystem events available via inotify. Use fsnotify library for real-time monitoring.",
		Timestamp: time.Now(),
	}, nil
}
