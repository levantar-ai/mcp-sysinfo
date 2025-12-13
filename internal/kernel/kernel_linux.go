//go:build linux

package kernel

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getKernelModules retrieves loaded kernel modules from /proc/modules.
func (c *Collector) getKernelModules() (*types.KernelModulesResult, error) {
	var modules []types.KernelModule

	// Read /proc/modules
	// #nosec G304 -- reading from procfs
	file, err := os.Open("/proc/modules")
	if err != nil {
		return &types.KernelModulesResult{
			Modules:   modules,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Format: name size usedby state address
	// e.g., "ext4 745472 2 - Live 0xffffffffc0000000"
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		module := types.KernelModule{
			Name: fields[0],
		}

		// Parse size
		if size, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
			module.Size = size
		}

		// Parse used by count
		if usedBy, err := strconv.Atoi(fields[2]); err == nil {
			module.UsedBy = usedBy
		}

		// Parse modules using this one
		if fields[3] != "-" {
			usedByMods := strings.TrimSuffix(fields[3], ",")
			if usedByMods != "" {
				module.UsedByMods = strings.Split(usedByMods, ",")
			}
		}

		// Parse state and address if available
		if len(fields) >= 5 {
			module.State = fields[4]
		}
		if len(fields) >= 6 {
			module.Address = fields[5]
		}

		modules = append(modules, module)
	}

	return &types.KernelModulesResult{
		Modules:   modules,
		Count:     len(modules),
		Timestamp: time.Now(),
	}, nil
}

// getLoadedDrivers retrieves loaded device drivers from /sys/bus/*/drivers.
func (c *Collector) getLoadedDrivers() (*types.LoadedDriversResult, error) {
	var drivers []types.LoadedDriver

	// Scan /sys/bus for device drivers
	busPath := "/sys/bus"
	buses, err := os.ReadDir(busPath)
	if err != nil {
		return &types.LoadedDriversResult{
			Drivers:   drivers,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	for _, bus := range buses {
		if !bus.IsDir() {
			continue
		}

		driversPath := filepath.Join(busPath, bus.Name(), "drivers")
		driverEntries, err := os.ReadDir(driversPath)
		if err != nil {
			continue
		}

		for _, driverEntry := range driverEntries {
			if !driverEntry.IsDir() {
				continue
			}

			driverPath := filepath.Join(driversPath, driverEntry.Name())
			driver := types.LoadedDriver{
				Name:        driverEntry.Name(),
				DeviceClass: bus.Name(),
				Path:        driverPath,
				Status:      "Loaded",
			}

			// Try to get module info
			modulePath := filepath.Join(driverPath, "module")
			if target, err := os.Readlink(modulePath); err == nil {
				driver.Version = filepath.Base(target)
			}

			// Try to get description from module
			modInfoPath := filepath.Join("/sys/module", driverEntry.Name(), "description")
			// #nosec G304 -- reading from sysfs
			if desc, err := os.ReadFile(modInfoPath); err == nil {
				driver.Description = strings.TrimSpace(string(desc))
			}

			// Try to get version from module
			versionPath := filepath.Join("/sys/module", driverEntry.Name(), "version")
			// #nosec G304 -- reading from sysfs
			if ver, err := os.ReadFile(versionPath); err == nil {
				driver.Version = strings.TrimSpace(string(ver))
			}

			drivers = append(drivers, driver)
		}
	}

	return &types.LoadedDriversResult{
		Drivers:   drivers,
		Count:     len(drivers),
		Timestamp: time.Now(),
	}, nil
}
