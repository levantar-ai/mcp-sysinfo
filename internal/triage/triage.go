// Package triage provides triage and summary queries for incident response.
package triage

import "github.com/levantar-ai/mcp-sysinfo/pkg/types"

// Collector gathers triage and summary information.
type Collector struct{}

// NewCollector creates a new triage collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetRecentReboots returns recent system reboots.
func (c *Collector) GetRecentReboots(limit int) (*types.RecentRebootsResult, error) {
	if limit <= 0 {
		limit = 10
	}
	return c.getRecentReboots(limit)
}

// GetRecentServiceFailures returns recent service failures.
func (c *Collector) GetRecentServiceFailures(limit int) (*types.RecentServiceFailuresResult, error) {
	if limit <= 0 {
		limit = 20
	}
	return c.getRecentServiceFailures(limit)
}

// GetRecentKernelEvents returns recent kernel events.
func (c *Collector) GetRecentKernelEvents(limit int) (*types.RecentKernelEventsResult, error) {
	if limit <= 0 {
		limit = 50
	}
	return c.getRecentKernelEvents(limit)
}

// GetRecentResourceIncidents returns recent resource incidents.
func (c *Collector) GetRecentResourceIncidents(limit int) (*types.RecentResourceIncidentsResult, error) {
	if limit <= 0 {
		limit = 20
	}
	return c.getRecentResourceIncidents(limit)
}

// GetRecentConfigChanges returns recent configuration changes.
func (c *Collector) GetRecentConfigChanges(limit int) (*types.RecentConfigChangesResult, error) {
	if limit <= 0 {
		limit = 50
	}
	return c.getRecentConfigChanges(limit)
}

// GetRecentCriticalEvents returns recent critical events.
func (c *Collector) GetRecentCriticalEvents(limit int) (*types.RecentCriticalEventsResult, error) {
	if limit <= 0 {
		limit = 30
	}
	return c.getRecentCriticalEvents(limit)
}

// GetFailedUnits returns currently failed systemd units (Linux) or equivalent.
func (c *Collector) GetFailedUnits() (*types.FailedUnitsResult, error) {
	return c.getFailedUnits()
}

// GetTimerJobs returns scheduled timer jobs and cron entries.
func (c *Collector) GetTimerJobs() (*types.TimerJobsResult, error) {
	return c.getTimerJobs()
}

// GetServiceLogView returns recent logs for a specific service.
func (c *Collector) GetServiceLogView(service string, lines int) (*types.ServiceLogViewResult, error) {
	if lines <= 0 {
		lines = 100
	}
	return c.getServiceLogView(service, lines)
}

// GetDeploymentEvents returns recent deployment or update events.
func (c *Collector) GetDeploymentEvents(limit int) (*types.DeploymentEventsResult, error) {
	if limit <= 0 {
		limit = 20
	}
	return c.getDeploymentEvents(limit)
}

// GetAuthFailureSummary returns authentication failure summary.
func (c *Collector) GetAuthFailureSummary(hours int) (*types.AuthFailureSummaryResult, error) {
	if hours <= 0 {
		hours = 24
	}
	return c.getAuthFailureSummary(hours)
}

// GetSecurityBasics returns basic security status.
func (c *Collector) GetSecurityBasics() (*types.SecurityBasicsResult, error) {
	return c.getSecurityBasics()
}

// GetSSHSecuritySummary returns SSH security configuration summary.
func (c *Collector) GetSSHSecuritySummary() (*types.SSHSecuritySummaryResult, error) {
	return c.getSSHSecuritySummary()
}

// GetAdminAccountSummary returns administrative account summary.
func (c *Collector) GetAdminAccountSummary() (*types.AdminAccountSummaryResult, error) {
	return c.getAdminAccountSummary()
}

// GetExposedServicesSummary returns summary of exposed network services.
func (c *Collector) GetExposedServicesSummary() (*types.ExposedServicesSummaryResult, error) {
	return c.getExposedServicesSummary()
}

// GetResourceLimits returns system resource limits.
func (c *Collector) GetResourceLimits() (*types.ResourceLimitsResult, error) {
	return c.getResourceLimits()
}

// GetRecentlyInstalledSoftware returns recently installed software.
func (c *Collector) GetRecentlyInstalledSoftware(days int) (*types.RecentlyInstalledSoftwareResult, error) {
	if days <= 0 {
		days = 7
	}
	return c.getRecentlyInstalledSoftware(days)
}

// GetFSHealthSummary returns filesystem health summary.
func (c *Collector) GetFSHealthSummary() (*types.FSHealthSummaryResult, error) {
	return c.getFSHealthSummary()
}

// GetIncidentTriageSnapshot returns a comprehensive incident triage snapshot.
func (c *Collector) GetIncidentTriageSnapshot() (*types.IncidentTriageSnapshotResult, error) {
	return c.getIncidentTriageSnapshot()
}

// GetSecurityPostureSnapshot returns security posture overview.
func (c *Collector) GetSecurityPostureSnapshot() (*types.SecurityPostureSnapshotResult, error) {
	return c.getSecurityPostureSnapshot()
}
