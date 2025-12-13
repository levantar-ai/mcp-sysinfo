//go:build darwin

package kernel

import (
	"bufio"
	"bytes"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getKernelModules retrieves loaded kernel extensions on macOS.
func (c *Collector) getKernelModules() (*types.KernelModulesResult, error) {
	var modules []types.KernelModule

	// Use kextstat to list loaded kernel extensions
	kextstat, err := exec.LookPath("kextstat")
	if err != nil {
		return &types.KernelModulesResult{
			Modules:   modules,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// #nosec G204 -- kextstat path is from LookPath
	cmd := exec.Command(kextstat, "-l")
	output, err := cmd.Output()
	if err != nil {
		return &types.KernelModulesResult{
			Modules:   modules,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	modules = parseKextstat(output)

	return &types.KernelModulesResult{
		Modules:   modules,
		Count:     len(modules),
		Timestamp: time.Now(),
	}, nil
}

// parseKextstat parses kextstat output.
func parseKextstat(output []byte) []types.KernelModule {
	var modules []types.KernelModule
	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Skip header
	scanner.Scan()

	// Format: Index Refs Address    Size       Wired      Name (Version) UUID <Linked Against>
	// e.g., "  123    0 0xffffff7f8b100000 0x5000     0x5000     com.apple.driver.AppleACPIPlatform (6.1) 12345..."
	pattern := regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+\S+\s+(\S+)`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		module := types.KernelModule{
			Name:    matches[5],
			Address: matches[3],
			State:   "Live",
		}

		// Parse refs
		if refs, err := strconv.Atoi(matches[2]); err == nil {
			module.UsedBy = refs
		}

		// Parse size (hex)
		if sizeStr := matches[4]; strings.HasPrefix(sizeStr, "0x") {
			if size, err := strconv.ParseInt(sizeStr[2:], 16, 64); err == nil {
				module.Size = size
			}
		}

		modules = append(modules, module)
	}

	return modules
}

// getLoadedDrivers retrieves loaded drivers on macOS.
func (c *Collector) getLoadedDrivers() (*types.LoadedDriversResult, error) {
	var drivers []types.LoadedDriver

	// Use system_profiler to get driver info
	cmd := exec.Command("/usr/sbin/system_profiler", "SPExtensionsDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to kextstat
		return c.getDriversFromKextstat()
	}

	drivers = parseSystemProfilerExtensions(output)

	return &types.LoadedDriversResult{
		Drivers:   drivers,
		Count:     len(drivers),
		Timestamp: time.Now(),
	}, nil
}

// parseSystemProfilerExtensions parses system_profiler JSON output.
func parseSystemProfilerExtensions(output []byte) []types.LoadedDriver {
	var drivers []types.LoadedDriver

	// Simple parsing - look for extension names
	content := string(output)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "_name") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				name := strings.Trim(parts[1], `", `)
				if name != "" && !strings.HasPrefix(name, "SPExtensions") {
					drivers = append(drivers, types.LoadedDriver{
						Name:   name,
						Status: "Loaded",
					})
				}
			}
		}
	}

	return drivers
}

// getDriversFromKextstat uses kextstat as fallback.
func (c *Collector) getDriversFromKextstat() (*types.LoadedDriversResult, error) {
	var drivers []types.LoadedDriver

	kextstat, err := exec.LookPath("kextstat")
	if err != nil {
		return &types.LoadedDriversResult{
			Drivers:   drivers,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// #nosec G204 -- kextstat path is from LookPath
	cmd := exec.Command(kextstat, "-l")
	output, err := cmd.Output()
	if err != nil {
		return &types.LoadedDriversResult{
			Drivers:   drivers,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Scan() // skip header

	pattern := regexp.MustCompile(`^\s*\d+\s+\d+\s+\S+\s+\S+\s+\S+\s+(\S+)`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := pattern.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		name := matches[1]
		deviceClass := "kernel"
		if strings.Contains(name, ".driver.") {
			deviceClass = "driver"
		} else if strings.Contains(name, ".iokit.") {
			deviceClass = "iokit"
		} else if strings.Contains(name, ".network.") {
			deviceClass = "network"
		}

		drivers = append(drivers, types.LoadedDriver{
			Name:        name,
			DeviceClass: deviceClass,
			Status:      "Loaded",
		})
	}

	return &types.LoadedDriversResult{
		Drivers:   drivers,
		Count:     len(drivers),
		Timestamp: time.Now(),
	}, nil
}
