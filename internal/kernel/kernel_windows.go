//go:build windows

package kernel

import (
	"bufio"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// getKernelModules retrieves loaded kernel drivers on Windows.
func (c *Collector) getKernelModules() (*types.KernelModulesResult, error) {
	var modules []types.KernelModule

	// Use driverquery to list drivers
	// #nosec G204 -- driverquery is a system tool
	cmd := cmdexec.Command("driverquery", "/v", "/fo", "csv")
	output, err := cmd.Output()
	if err != nil {
		return &types.KernelModulesResult{
			Modules:   modules,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	modules = parseDriverQuery(output)

	return &types.KernelModulesResult{
		Modules:   modules,
		Count:     len(modules),
		Timestamp: time.Now(),
	}, nil
}

// parseDriverQuery parses driverquery CSV output.
func parseDriverQuery(output []byte) []types.KernelModule {
	var modules []types.KernelModule

	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Skip header
	if !scanner.Scan() {
		return modules
	}

	// Parse CSV header to find column indices
	header := scanner.Text()
	headers := parseCSVLine(header)

	// Find column indices
	nameIdx := findColumnIndex(headers, "Module Name")
	stateIdx := findColumnIndex(headers, "State")

	for scanner.Scan() {
		line := scanner.Text()
		fields := parseCSVLine(line)
		if len(fields) == 0 {
			continue
		}

		module := types.KernelModule{
			State: "Running",
		}

		if nameIdx >= 0 && nameIdx < len(fields) {
			module.Name = fields[nameIdx]
		}
		if stateIdx >= 0 && stateIdx < len(fields) {
			module.State = fields[stateIdx]
		}

		if module.Name != "" {
			modules = append(modules, module)
		}
	}

	return modules
}

// getLoadedDrivers retrieves loaded device drivers on Windows.
func (c *Collector) getLoadedDrivers() (*types.LoadedDriversResult, error) {
	var drivers []types.LoadedDriver

	// Use driverquery with verbose info
	// #nosec G204 -- driverquery is a system tool
	cmd := cmdexec.Command("driverquery", "/v", "/fo", "csv")
	output, err := cmd.Output()
	if err != nil {
		// Try PowerShell as fallback
		return c.getDriversPowerShell()
	}

	drivers = parseDriverQueryForDrivers(output)

	return &types.LoadedDriversResult{
		Drivers:   drivers,
		Count:     len(drivers),
		Timestamp: time.Now(),
	}, nil
}

// parseDriverQueryForDrivers parses driverquery for driver info.
func parseDriverQueryForDrivers(output []byte) []types.LoadedDriver {
	var drivers []types.LoadedDriver

	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Skip header
	if !scanner.Scan() {
		return drivers
	}

	header := scanner.Text()
	headers := parseCSVLine(header)

	nameIdx := findColumnIndex(headers, "Module Name")
	displayNameIdx := findColumnIndex(headers, "Display Name")
	typeIdx := findColumnIndex(headers, "Driver Type")
	stateIdx := findColumnIndex(headers, "State")
	pathIdx := findColumnIndex(headers, "Path")

	for scanner.Scan() {
		line := scanner.Text()
		fields := parseCSVLine(line)
		if len(fields) == 0 {
			continue
		}

		driver := types.LoadedDriver{
			Status: "Running",
		}

		if nameIdx >= 0 && nameIdx < len(fields) {
			driver.Name = fields[nameIdx]
		}
		if displayNameIdx >= 0 && displayNameIdx < len(fields) {
			driver.Description = fields[displayNameIdx]
		}
		if typeIdx >= 0 && typeIdx < len(fields) {
			driver.DeviceClass = fields[typeIdx]
		}
		if stateIdx >= 0 && stateIdx < len(fields) {
			driver.Status = fields[stateIdx]
		}
		if pathIdx >= 0 && pathIdx < len(fields) {
			driver.Path = fields[pathIdx]
		}

		if driver.Name != "" {
			drivers = append(drivers, driver)
		}
	}

	return drivers
}

// getDriversPowerShell uses PowerShell as fallback.
func (c *Collector) getDriversPowerShell() (*types.LoadedDriversResult, error) {
	var drivers []types.LoadedDriver

	psCmd := `Get-WmiObject Win32_SystemDriver | Select-Object Name,DisplayName,State,PathName | ConvertTo-Json`
	// #nosec G204 -- PowerShell is a system tool
	cmd := cmdexec.Command("powershell", "-NoProfile", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return &types.LoadedDriversResult{
			Drivers:   drivers,
			Count:     0,
			Timestamp: time.Now(),
		}, nil
	}

	// Simple JSON parsing
	content := string(output)
	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentDriver types.LoadedDriver
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "\"Name\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentDriver.Name = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "\"DisplayName\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentDriver.Description = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "\"State\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentDriver.Status = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "\"PathName\":") {
			if idx := strings.Index(line, ":"); idx > 0 {
				currentDriver.Path = strings.Trim(line[idx+1:], `", `)
			}
		} else if strings.Contains(line, "}") {
			if currentDriver.Name != "" {
				drivers = append(drivers, currentDriver)
			}
			currentDriver = types.LoadedDriver{}
		}
	}

	return &types.LoadedDriversResult{
		Drivers:   drivers,
		Count:     len(drivers),
		Timestamp: time.Now(),
	}, nil
}

// parseCSVLine parses a CSV line respecting quotes.
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ',' && !inQuotes:
			fields = append(fields, strings.TrimSpace(current.String()))
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	fields = append(fields, strings.TrimSpace(current.String()))

	return fields
}

// findColumnIndex finds the index of a column by name.
func findColumnIndex(headers []string, name string) int {
	for i, h := range headers {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return i
		}
	}
	return -1
}
