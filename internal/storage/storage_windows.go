//go:build windows

package storage

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getSMARTHealth retrieves SMART health data on Windows.
func (c *Collector) getSMARTHealth() (*types.SMARTHealthResult, error) {
	var disks []types.SMARTDisk

	// Try WMI for disk information
	disksFromWMI, err := getSMARTFromWMI()
	if err == nil {
		disks = disksFromWMI
	}

	// Try smartctl if available (via Chocolatey or manual install)
	if smartctlPath, err := cmdexec.LookPath("smartctl"); err == nil {
		for i := range disks {
			enrichDiskWithSmartctl(&disks[i], smartctlPath)
		}
	}

	return &types.SMARTHealthResult{
		Disks:     disks,
		Count:     len(disks),
		Timestamp: time.Now(),
	}, nil
}

// getSMARTFromWMI retrieves disk info via WMI.
func getSMARTFromWMI() ([]types.SMARTDisk, error) {
	var disks []types.SMARTDisk

	// Use PowerShell to query WMI
	psScript := `Get-WmiObject -Class Win32_DiskDrive | Select-Object DeviceID, Model, SerialNumber, Size, MediaType, Status | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-Command", psScript).Output()
	if err != nil {
		return nil, err
	}

	// Handle both single disk and array results
	var diskData interface{}
	if err := json.Unmarshal(output, &diskData); err != nil {
		return nil, err
	}

	var diskArray []map[string]interface{}
	switch v := diskData.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				diskArray = append(diskArray, m)
			}
		}
	case map[string]interface{}:
		diskArray = append(diskArray, v)
	}

	for _, d := range diskArray {
		disk := types.SMARTDisk{
			Healthy: true,
		}

		if deviceID, ok := d["DeviceID"].(string); ok {
			disk.Device = deviceID
		}
		if model, ok := d["Model"].(string); ok {
			disk.Model = model
		}
		if serial, ok := d["SerialNumber"].(string); ok {
			disk.Serial = strings.TrimSpace(serial)
		}
		if status, ok := d["Status"].(string); ok {
			disk.Healthy = status == "OK"
		}
		if mediaType, ok := d["MediaType"].(string); ok {
			if strings.Contains(strings.ToLower(mediaType), "ssd") {
				disk.Type = "SSD"
			} else if strings.Contains(strings.ToLower(mediaType), "nvme") {
				disk.Type = "NVMe"
			} else {
				disk.Type = "HDD"
			}
		}

		disks = append(disks, disk)
	}

	return disks, nil
}

// enrichDiskWithSmartctl adds SMART details using smartctl.
func enrichDiskWithSmartctl(disk *types.SMARTDisk, smartctlPath string) {
	// Convert Windows device path to smartctl format
	devicePath := disk.Device
	if strings.HasPrefix(devicePath, "\\\\.\\") {
		// Already in correct format
	} else {
		devicePath = "\\\\.\\PhysicalDrive0" // Default to first drive
	}

	output, err := cmdexec.Command(smartctlPath, "-a", "-j", devicePath).Output()
	if err != nil {
		return
	}

	var smartData struct {
		SmartStatus struct {
			Passed bool `json:"passed"`
		} `json:"smart_status"`
		Temperature struct {
			Current int `json:"current"`
		} `json:"temperature"`
		PowerOnTime struct {
			Hours int `json:"hours"`
		} `json:"power_on_time"`
	}

	if err := json.Unmarshal(output, &smartData); err != nil {
		return
	}

	disk.Healthy = smartData.SmartStatus.Passed
	disk.Temperature = smartData.Temperature.Current
	disk.PowerOnHours = uint64(smartData.PowerOnTime.Hours)
}

// getIOLatency retrieves I/O latency statistics on Windows.
func (c *Collector) getIOLatency() (*types.IOLatencyResult, error) {
	var devices []types.IOLatencyDevice

	// Use PowerShell to get disk performance counters
	psScript := `Get-Counter '\PhysicalDisk(*)\*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CounterSamples | Where-Object {$_.InstanceName -ne '_total'} | Group-Object InstanceName | ForEach-Object { $disk = $_.Name; $counters = @{}; $_.Group | ForEach-Object { $counterName = ($_.Path -split '\\')[-1]; $counters[$counterName] = $_.CookedValue }; [PSCustomObject]@{Disk=$disk; ReadLatency=$counters['Avg. Disk sec/Read']*1000; WriteLatency=$counters['Avg. Disk sec/Write']*1000; ReadIOPS=$counters['Disk Reads/sec']; WriteIOPS=$counters['Disk Writes/sec']; ReadThroughput=$counters['Disk Read Bytes/sec']; WriteThroughput=$counters['Disk Write Bytes/sec']; QueueLength=$counters['Current Disk Queue Length']} } | ConvertTo-Json`

	output, err := cmdexec.Command("powershell", "-Command", psScript).Output()
	if err != nil {
		// Fallback to simpler query
		return getIOLatencySimple()
	}

	var perfData interface{}
	if err := json.Unmarshal(output, &perfData); err != nil {
		return getIOLatencySimple()
	}

	var perfArray []map[string]interface{}
	switch v := perfData.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				perfArray = append(perfArray, m)
			}
		}
	case map[string]interface{}:
		perfArray = append(perfArray, v)
	}

	for _, p := range perfArray {
		device := types.IOLatencyDevice{}

		if disk, ok := p["Disk"].(string); ok {
			device.Device = disk
		}
		if v, ok := p["ReadLatency"].(float64); ok {
			device.ReadLatencyMs = v
		}
		if v, ok := p["WriteLatency"].(float64); ok {
			device.WriteLatencyMs = v
		}
		if v, ok := p["ReadIOPS"].(float64); ok {
			device.ReadIOPS = v
		}
		if v, ok := p["WriteIOPS"].(float64); ok {
			device.WriteIOPS = v
		}
		if v, ok := p["ReadThroughput"].(float64); ok {
			device.ReadThroughput = uint64(v)
		}
		if v, ok := p["WriteThroughput"].(float64); ok {
			device.WriteThroughput = uint64(v)
		}
		if v, ok := p["QueueLength"].(float64); ok {
			device.QueueDepth = uint64(v)
		}

		devices = append(devices, device)
	}

	return &types.IOLatencyResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// getIOLatencySimple provides basic I/O stats as fallback.
func getIOLatencySimple() (*types.IOLatencyResult, error) {
	var devices []types.IOLatencyDevice

	psScript := `Get-WmiObject Win32_PerfFormattedData_PerfDisk_PhysicalDisk | Where-Object {$_.Name -ne '_Total'} | Select-Object Name, AvgDiskSecPerRead, AvgDiskSecPerWrite, DiskReadBytesPersec, DiskWriteBytesPersec | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-Command", psScript).Output()
	if err != nil {
		return &types.IOLatencyResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	var perfData interface{}
	if err := json.Unmarshal(output, &perfData); err != nil {
		return &types.IOLatencyResult{
			Devices:   devices,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	var perfArray []map[string]interface{}
	switch v := perfData.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				perfArray = append(perfArray, m)
			}
		}
	case map[string]interface{}:
		perfArray = append(perfArray, v)
	}

	for _, p := range perfArray {
		device := types.IOLatencyDevice{}

		if name, ok := p["Name"].(string); ok {
			device.Device = name
		}
		if v, ok := p["AvgDiskSecPerRead"].(float64); ok {
			device.ReadLatencyMs = v * 1000
		}
		if v, ok := p["AvgDiskSecPerWrite"].(float64); ok {
			device.WriteLatencyMs = v * 1000
		}
		if v, ok := p["DiskReadBytesPersec"].(float64); ok {
			device.ReadThroughput = uint64(v)
		}
		if v, ok := p["DiskWriteBytesPersec"].(float64); ok {
			device.WriteThroughput = uint64(v)
		}

		devices = append(devices, device)
	}

	return &types.IOLatencyResult{
		Devices:   devices,
		Count:     len(devices),
		Timestamp: time.Now(),
	}, nil
}

// getVolumeStatus retrieves Storage Spaces status on Windows.
func (c *Collector) getVolumeStatus() (*types.VolumeStatusResult, error) {
	result := &types.VolumeStatusResult{
		Timestamp: time.Now(),
	}

	// Get Storage Spaces pools
	pools, err := getStoragePools()
	if err == nil && len(pools) > 0 {
		result.StoragePools = pools
		result.Count = len(pools)
	}

	return result, nil
}

// getStoragePools retrieves Windows Storage Spaces pools.
func getStoragePools() ([]types.StoragePool, error) {
	var pools []types.StoragePool

	psScript := `Get-StoragePool | Where-Object {$_.IsPrimordial -eq $false} | Select-Object FriendlyName, HealthStatus, OperationalStatus, Size, AllocatedSize, ResiliencySettingNameDefault | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-Command", psScript).Output()
	if err != nil {
		return nil, err
	}

	if len(output) == 0 {
		return pools, nil
	}

	var poolData interface{}
	if err := json.Unmarshal(output, &poolData); err != nil {
		return nil, err
	}

	var poolArray []map[string]interface{}
	switch v := poolData.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				poolArray = append(poolArray, m)
			}
		}
	case map[string]interface{}:
		poolArray = append(poolArray, v)
	}

	for _, p := range poolArray {
		pool := types.StoragePool{}

		if name, ok := p["FriendlyName"].(string); ok {
			pool.FriendlyName = name
			pool.Name = name
		}
		if health, ok := p["HealthStatus"].(float64); ok {
			switch int(health) {
			case 0:
				pool.HealthStatus = "Healthy"
			case 1:
				pool.HealthStatus = "Warning"
			case 2:
				pool.HealthStatus = "Unhealthy"
			default:
				pool.HealthStatus = strconv.Itoa(int(health))
			}
		}
		if status, ok := p["OperationalStatus"].(float64); ok {
			switch int(status) {
			case 0:
				pool.OperationalStatus = "Unknown"
			case 1:
				pool.OperationalStatus = "Other"
			case 2:
				pool.OperationalStatus = "OK"
			case 3:
				pool.OperationalStatus = "Degraded"
			default:
				pool.OperationalStatus = strconv.Itoa(int(status))
			}
		}
		if size, ok := p["Size"].(float64); ok {
			pool.Size = uint64(size)
		}
		if alloc, ok := p["AllocatedSize"].(float64); ok {
			pool.AllocatedSize = uint64(alloc)
		}
		if resiliency, ok := p["ResiliencySettingNameDefault"].(string); ok {
			pool.ResiliencyType = resiliency
		}

		pools = append(pools, pool)
	}

	return pools, nil
}

// getMountChanges retrieves current mounts (volumes) on Windows.
func (c *Collector) getMountChanges() (*types.MountChangesResult, error) {
	var mounts []types.MountInfo

	psScript := `Get-Volume | Where-Object {$_.DriveLetter -ne $null} | Select-Object DriveLetter, FileSystemLabel, FileSystem, Size, SizeRemaining | ConvertTo-Json`
	output, err := cmdexec.Command("powershell", "-Command", psScript).Output()
	if err != nil {
		return &types.MountChangesResult{
			CurrentMounts: mounts,
			Count:         0,
			Timestamp:     time.Now(),
		}, nil
	}

	var volData interface{}
	if err := json.Unmarshal(output, &volData); err != nil {
		return &types.MountChangesResult{
			CurrentMounts: mounts,
			Count:         0,
			Timestamp:     time.Now(),
		}, nil
	}

	var volArray []map[string]interface{}
	switch v := volData.(type) {
	case []interface{}:
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				volArray = append(volArray, m)
			}
		}
	case map[string]interface{}:
		volArray = append(volArray, v)
	}

	for _, v := range volArray {
		mount := types.MountInfo{}

		if letter, ok := v["DriveLetter"].(string); ok {
			mount.Mountpoint = letter + ":\\"
			mount.Device = letter + ":"
		}
		if fs, ok := v["FileSystem"].(string); ok {
			mount.Fstype = fs
		}
		if label, ok := v["FileSystemLabel"].(string); ok {
			mount.Options = []string{"label=" + label}
		}
		if size, ok := v["Size"].(float64); ok {
			mount.Total = uint64(size)
		}
		if remaining, ok := v["SizeRemaining"].(float64); ok {
			mount.Free = uint64(remaining)
			mount.Used = mount.Total - mount.Free
			if mount.Total > 0 {
				mount.UsedPct = float64(mount.Used) / float64(mount.Total) * 100
			}
		}

		mounts = append(mounts, mount)
	}

	return &types.MountChangesResult{
		CurrentMounts: mounts,
		Count:         len(mounts),
		Timestamp:     time.Now(),
	}, nil
}

// getFSEvents returns filesystem event monitoring info on Windows.
func (c *Collector) getFSEvents() (*types.FSEventsResult, error) {
	return &types.FSEventsResult{
		Supported: true,
		Message:   "Filesystem events available via ReadDirectoryChangesW. Use fsnotify library for real-time monitoring.",
		Timestamp: time.Now(),
	}, nil
}
