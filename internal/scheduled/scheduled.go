// Package scheduled provides scheduled task and startup item collection.
package scheduled

import (
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects scheduled task and startup information.
type Collector struct{}

// NewCollector creates a new scheduled task collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetScheduledTasks retrieves scheduled tasks (Windows Task Scheduler, at jobs, launchd).
func (c *Collector) GetScheduledTasks() (*types.ScheduledTasksResult, error) {
	return c.getScheduledTasks()
}

// GetCronJobs retrieves cron jobs (Linux/macOS).
func (c *Collector) GetCronJobs() (*types.CronJobsResult, error) {
	return c.getCronJobs()
}

// GetStartupItems retrieves startup programs and services.
func (c *Collector) GetStartupItems() (*types.StartupItemsResult, error) {
	return c.getStartupItems()
}

// GetSystemdServices retrieves systemd service status (Linux only).
func (c *Collector) GetSystemdServices() (*types.SystemdServicesResult, error) {
	return c.getSystemdServices()
}
