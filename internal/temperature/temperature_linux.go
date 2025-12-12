//go:build linux

package temperature

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// collect gathers temperature sensor information on Linux.
func (c *Collector) collect() (*types.TemperatureInfo, error) {
	var sensors []types.SensorInfo

	// Read from /sys/class/hwmon
	hwmonPath := "/sys/class/hwmon"
	entries, err := os.ReadDir(hwmonPath)
	if err != nil {
		// hwmon may not be available on all systems
		return &types.TemperatureInfo{
			Sensors:   sensors,
			Timestamp: time.Now(),
		}, nil
	}

	for _, entry := range entries {
		devicePath := filepath.Join(hwmonPath, entry.Name())

		// Get device name
		// #nosec G304 -- reading from sysfs hwmon, entry from directory listing
		nameBytes, err := os.ReadFile(filepath.Join(devicePath, "name"))
		if err != nil {
			continue
		}
		deviceName := strings.TrimSpace(string(nameBytes))

		// Find temperature inputs
		files, err := filepath.Glob(filepath.Join(devicePath, "temp*_input"))
		if err != nil {
			continue
		}

		for _, tempFile := range files {
			sensor, err := readTempSensor(tempFile, deviceName)
			if err != nil {
				continue
			}
			sensors = append(sensors, *sensor)
		}
	}

	// Also check /sys/class/thermal
	thermalPath := "/sys/class/thermal"
	thermalEntries, err := os.ReadDir(thermalPath)
	if err == nil {
		for _, entry := range thermalEntries {
			if !strings.HasPrefix(entry.Name(), "thermal_zone") {
				continue
			}

			zonePath := filepath.Join(thermalPath, entry.Name())

			// Get zone type
			// #nosec G304 -- reading from sysfs, paths derived from directory listing
			typeBytes, err := os.ReadFile(filepath.Join(zonePath, "type"))
			if err != nil {
				continue
			}
			zoneType := strings.TrimSpace(string(typeBytes))

			// Read temperature
			// #nosec G304 -- reading from sysfs, paths derived from directory listing
			tempBytes, err := os.ReadFile(filepath.Join(zonePath, "temp"))
			if err != nil {
				continue
			}
			tempMilli, err := strconv.ParseFloat(strings.TrimSpace(string(tempBytes)), 64)
			if err != nil {
				continue
			}

			sensors = append(sensors, types.SensorInfo{
				Name:        zoneType,
				Temperature: tempMilli / 1000.0, // Convert from millidegrees
			})
		}
	}

	return &types.TemperatureInfo{
		Sensors:   sensors,
		Timestamp: time.Now(),
	}, nil
}

// readTempSensor reads a temperature sensor from hwmon.
func readTempSensor(tempFile, deviceName string) (*types.SensorInfo, error) {
	// Read temperature
	// #nosec G304 -- reading from sysfs hwmon, tempFile from directory listing
	tempBytes, err := os.ReadFile(tempFile)
	if err != nil {
		return nil, err
	}

	tempMilli, err := strconv.ParseFloat(strings.TrimSpace(string(tempBytes)), 64)
	if err != nil {
		return nil, err
	}

	// Get sensor label
	labelFile := strings.Replace(tempFile, "_input", "_label", 1)
	label := deviceName
	// #nosec G304 -- reading from sysfs hwmon, path derived from tempFile
	if labelBytes, err := os.ReadFile(labelFile); err == nil {
		label = strings.TrimSpace(string(labelBytes))
	}

	sensor := &types.SensorInfo{
		Name:        label,
		Temperature: tempMilli / 1000.0, // Convert from millidegrees
	}

	// Try to read high/critical thresholds
	maxFile := strings.Replace(tempFile, "_input", "_max", 1)
	// #nosec G304 -- reading from sysfs hwmon, path derived from tempFile
	if maxBytes, err := os.ReadFile(maxFile); err == nil {
		if maxMilli, err := strconv.ParseFloat(strings.TrimSpace(string(maxBytes)), 64); err == nil {
			sensor.High = maxMilli / 1000.0
		}
	}

	critFile := strings.Replace(tempFile, "_input", "_crit", 1)
	// #nosec G304 -- reading from sysfs hwmon, path derived from tempFile
	if critBytes, err := os.ReadFile(critFile); err == nil {
		if critMilli, err := strconv.ParseFloat(strings.TrimSpace(string(critBytes)), 64); err == nil {
			sensor.Critical = critMilli / 1000.0
		}
	}

	return sensor, nil
}
