// Package compliance provides security scanning and compliance checking.
package compliance

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects security and compliance data.
type Collector struct{}

// NewCollector creates a new compliance collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetSecurityScan performs a security vulnerability scan.
func (c *Collector) GetSecurityScan() (*types.SecurityScanResult, error) {
	return c.getSecurityScan()
}

// GetComplianceCheck performs a compliance check.
func (c *Collector) GetComplianceCheck(framework string) (*types.ComplianceCheckResult, error) {
	return c.getComplianceCheck(framework)
}

// GetForensicSnapshot collects forensic data snapshot.
func (c *Collector) GetForensicSnapshot() (*types.ForensicSnapshotResult, error) {
	return c.getForensicSnapshot()
}

// GetAuditTrail retrieves security audit events.
func (c *Collector) GetAuditTrail(hours int) (*types.AuditTrailResult, error) {
	return c.getAuditTrail(hours)
}

// GetHardeningRecommendations provides security hardening recommendations.
func (c *Collector) GetHardeningRecommendations() (*types.HardeningRecommendationsResult, error) {
	return c.getHardeningRecommendations()
}

// generateSnapshotID creates a unique snapshot ID.
func generateSnapshotID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// calculateSecurityScore calculates overall security score.
func calculateSecurityScore(findings []types.SecurityFinding) (int, string) {
	if len(findings) == 0 {
		return 100, "A"
	}

	// Start with 100 and deduct based on severity
	score := 100
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			score -= 25
		case "high":
			score -= 15
		case "medium":
			score -= 8
		case "low":
			score -= 3
		case "info":
			score -= 1
		}
	}

	if score < 0 {
		score = 0
	}

	// Determine grade
	var grade string
	switch {
	case score >= 90:
		grade = "A"
	case score >= 80:
		grade = "B"
	case score >= 70:
		grade = "C"
	case score >= 60:
		grade = "D"
	default:
		grade = "F"
	}

	return score, grade
}

// calculateComplianceScore calculates compliance percentage.
func calculateComplianceScore(checks []types.ComplianceCheck) float64 {
	if len(checks) == 0 {
		return 100
	}

	var passed int
	var total int

	for _, check := range checks {
		if check.Status == "skip" || check.Status == "manual" {
			continue
		}
		total++
		if check.Status == "pass" {
			passed++
		}
	}

	if total == 0 {
		return 100
	}

	return float64(passed) / float64(total) * 100
}

// createSecuritySummary creates a summary from findings.
func createSecuritySummary(findings []types.SecurityFinding, passedChecks int) types.SecuritySummary {
	summary := types.SecuritySummary{
		TotalFindings: len(findings),
		PassedChecks:  passedChecks,
		FailedChecks:  len(findings),
	}

	for _, f := range findings {
		switch f.Severity {
		case "critical":
			summary.CriticalFindings++
		case "high":
			summary.HighFindings++
		case "medium":
			summary.MediumFindings++
		case "low":
			summary.LowFindings++
		case "info":
			summary.InfoFindings++
		}
	}

	return summary
}

// createComplianceSummary creates a summary from checks.
func createComplianceSummary(checks []types.ComplianceCheck) types.ComplianceSummary {
	summary := types.ComplianceSummary{
		TotalChecks: len(checks),
	}

	for _, check := range checks {
		switch check.Status {
		case "pass":
			summary.Passed++
		case "fail":
			summary.Failed++
		case "skip":
			summary.Skipped++
		case "manual":
			summary.Manual++
		}
	}

	return summary
}

// getTimeRange creates a time range for the specified hours.
func getTimeRange(hours int) types.TimeRange {
	end := time.Now()
	start := end.Add(-time.Duration(hours) * time.Hour)

	duration := ""
	if hours == 1 {
		duration = "1h"
	} else if hours == 24 {
		duration = "24h"
	} else if hours == 168 {
		duration = "7d"
	} else {
		duration = fmt.Sprintf("%dh", hours)
	}

	return types.TimeRange{
		Start:    start,
		End:      end,
		Duration: duration,
	}
}
