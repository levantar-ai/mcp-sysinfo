// Package analytics provides system analytics and trend analysis.
package analytics

import (
	"math"
	"sort"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cpu"
	"github.com/levantar-ai/mcp-sysinfo/internal/disk"
	"github.com/levantar-ai/mcp-sysinfo/internal/memory"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects analytics and trend data.
type Collector struct{}

// NewCollector creates a new analytics collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetHistoricalMetrics retrieves historical system metrics.
// Since we don't have persistent storage, this provides recent snapshots.
func (c *Collector) GetHistoricalMetrics(period string) (*types.HistoricalMetricsResult, error) {
	result := &types.HistoricalMetricsResult{
		DataSource: "current",
		Timestamp:  time.Now(),
	}

	end := time.Now()
	var start time.Time

	switch period {
	case "1h":
		start = end.Add(-1 * time.Hour)
	case "24h":
		start = end.Add(-24 * time.Hour)
	case "7d":
		start = end.Add(-7 * 24 * time.Hour)
	default:
		start = end.Add(-1 * time.Hour)
		period = "1h"
	}

	result.TimeRange = types.TimeRange{
		Start:    start,
		End:      end,
		Duration: period,
	}

	// Get current CPU metrics
	cpuCollector := cpu.NewCollector()
	cpuInfo, err := cpuCollector.Collect(false)
	if err == nil {
		result.CPU = []types.MetricDataPoint{
			{
				Timestamp: time.Now(),
				Value:     cpuInfo.Percent,
				Label:     "cpu_percent",
			},
		}
	}

	// Get current memory metrics
	memCollector := memory.NewCollector()
	memInfo, err := memCollector.Collect()
	if err == nil {
		result.Memory = []types.MetricDataPoint{
			{
				Timestamp: time.Now(),
				Value:     memInfo.UsedPercent,
				Label:     "memory_percent",
			},
		}
	}

	// Get current disk metrics
	diskCollector := disk.NewCollector()
	diskInfo, err := diskCollector.Collect()
	if err == nil && len(diskInfo.Partitions) > 0 {
		for _, part := range diskInfo.Partitions {
			result.Disk = append(result.Disk, types.MetricDataPoint{
				Timestamp: time.Now(),
				Value:     part.UsedPercent,
				Label:     part.Mountpoint,
			})
		}
	}

	return result, nil
}

// GetAnomalyDetection detects anomalies in current system metrics.
func (c *Collector) GetAnomalyDetection() (*types.AnomalyDetectionResult, error) {
	result := &types.AnomalyDetectionResult{
		Thresholds: map[string]float64{
			"cpu_high":     90.0,
			"memory_high":  90.0,
			"disk_high":    90.0,
			"load_high":    4.0,
		},
		TimeRange: types.TimeRange{
			Start:    time.Now().Add(-5 * time.Minute),
			End:      time.Now(),
			Duration: "5m",
		},
		Timestamp: time.Now(),
	}

	// Check CPU
	cpuCollector := cpu.NewCollector()
	cpuInfo, err := cpuCollector.Collect(false)
	if err == nil {
		if cpuInfo.Percent > result.Thresholds["cpu_high"] {
			result.Anomalies = append(result.Anomalies, types.Anomaly{
				Metric:      "cpu_percent",
				Value:       cpuInfo.Percent,
				Expected:    result.Thresholds["cpu_high"],
				Deviation:   ((cpuInfo.Percent - result.Thresholds["cpu_high"]) / result.Thresholds["cpu_high"]) * 100,
				Severity:    getSeverity(cpuInfo.Percent, 90, 95, 99),
				Timestamp:   time.Now(),
				Description: "CPU usage is abnormally high",
			})
		}

		// Check load average
		if cpuInfo.LoadAverage != nil && cpuInfo.LoadAverage.Load1 > result.Thresholds["load_high"]*float64(cpuInfo.Count) {
			expectedLoad := result.Thresholds["load_high"] * float64(cpuInfo.Count)
			result.Anomalies = append(result.Anomalies, types.Anomaly{
				Metric:      "load_average",
				Value:       cpuInfo.LoadAverage.Load1,
				Expected:    expectedLoad,
				Deviation:   ((cpuInfo.LoadAverage.Load1 - expectedLoad) / expectedLoad) * 100,
				Severity:    getSeverity(cpuInfo.LoadAverage.Load1/float64(cpuInfo.Count), 2, 4, 8),
				Timestamp:   time.Now(),
				Description: "System load is abnormally high",
			})
		}
	}

	// Check Memory
	memCollector := memory.NewCollector()
	memInfo, err := memCollector.Collect()
	if err == nil {
		if memInfo.UsedPercent > result.Thresholds["memory_high"] {
			result.Anomalies = append(result.Anomalies, types.Anomaly{
				Metric:      "memory_percent",
				Value:       memInfo.UsedPercent,
				Expected:    result.Thresholds["memory_high"],
				Deviation:   ((memInfo.UsedPercent - result.Thresholds["memory_high"]) / result.Thresholds["memory_high"]) * 100,
				Severity:    getSeverity(memInfo.UsedPercent, 90, 95, 99),
				Timestamp:   time.Now(),
				Description: "Memory usage is abnormally high",
			})
		}

		// Check swap usage
		if memInfo.Swap != nil && memInfo.Swap.UsedPercent > 50 {
			result.Anomalies = append(result.Anomalies, types.Anomaly{
				Metric:      "swap_percent",
				Value:       memInfo.Swap.UsedPercent,
				Expected:    20.0,
				Deviation:   ((memInfo.Swap.UsedPercent - 20) / 20) * 100,
				Severity:    getSeverity(memInfo.Swap.UsedPercent, 50, 75, 90),
				Timestamp:   time.Now(),
				Description: "Swap usage is elevated, indicating memory pressure",
			})
		}
	}

	// Check Disk
	diskCollector := disk.NewCollector()
	diskInfo, err := diskCollector.Collect()
	if err == nil {
		for _, part := range diskInfo.Partitions {
			if part.UsedPercent > result.Thresholds["disk_high"] {
				result.Anomalies = append(result.Anomalies, types.Anomaly{
					Metric:      "disk_percent:" + part.Mountpoint,
					Value:       part.UsedPercent,
					Expected:    result.Thresholds["disk_high"],
					Deviation:   ((part.UsedPercent - result.Thresholds["disk_high"]) / result.Thresholds["disk_high"]) * 100,
					Severity:    getSeverity(part.UsedPercent, 90, 95, 99),
					Timestamp:   time.Now(),
					Description: "Disk " + part.Mountpoint + " usage is critically high",
				})
			}
		}
	}

	result.Count = len(result.Anomalies)
	return result, nil
}

// getSeverity determines severity based on thresholds.
func getSeverity(value, medium, high, critical float64) string {
	if value >= critical {
		return "critical"
	}
	if value >= high {
		return "high"
	}
	if value >= medium {
		return "medium"
	}
	return "low"
}

// GetCapacityForecast provides capacity forecasts for resources.
func (c *Collector) GetCapacityForecast() (*types.CapacityForecastResult, error) {
	result := &types.CapacityForecastResult{
		Timestamp: time.Now(),
	}

	// Disk capacity forecasts
	diskCollector := disk.NewCollector()
	diskInfo, err := diskCollector.Collect()
	if err == nil {
		for _, part := range diskInfo.Partitions {
			forecast := types.CapacityForecast{
				Resource:     "disk:" + part.Mountpoint,
				CurrentUsage: part.UsedPercent,
				Confidence:   70.0, // Lower confidence without historical data
			}

			// Estimate growth rate (assumes 1% per day as default without history)
			forecast.GrowthRate = 1.0

			if part.UsedPercent < 100 {
				remainingPercent := 100 - part.UsedPercent
				forecast.DaysToFull = int(remainingPercent / forecast.GrowthRate)
				if forecast.DaysToFull > 0 {
					forecast.EstimatedFull = time.Now().AddDate(0, 0, forecast.DaysToFull)
				}
			}

			// Generate recommendation
			if part.UsedPercent >= 95 {
				forecast.Recommendation = "CRITICAL: Immediate action required. Free up space or expand storage."
			} else if part.UsedPercent >= 90 {
				forecast.Recommendation = "WARNING: Plan storage expansion within 1-2 weeks."
			} else if part.UsedPercent >= 80 {
				forecast.Recommendation = "NOTICE: Monitor growth and plan for expansion."
			} else {
				forecast.Recommendation = "OK: Adequate capacity available."
			}

			result.Forecasts = append(result.Forecasts, forecast)
		}
	}

	// Memory capacity (for swap detection)
	memCollector := memory.NewCollector()
	memInfo, err := memCollector.Collect()
	if err == nil {
		memForecast := types.CapacityForecast{
			Resource:     "memory",
			CurrentUsage: memInfo.UsedPercent,
			GrowthRate:   0.0, // Memory doesn't "grow" the same way
			Confidence:   50.0,
		}

		if memInfo.UsedPercent >= 90 {
			memForecast.Recommendation = "WARNING: High memory usage. Consider adding RAM or optimizing applications."
		} else if memInfo.UsedPercent >= 75 {
			memForecast.Recommendation = "NOTICE: Elevated memory usage. Monitor for growth."
		} else {
			memForecast.Recommendation = "OK: Adequate memory available."
		}

		result.Forecasts = append(result.Forecasts, memForecast)
	}

	return result, nil
}

// GetTrendAnalysis provides performance trend analysis.
func (c *Collector) GetTrendAnalysis(period string) (*types.TrendAnalysisResult, error) {
	result := &types.TrendAnalysisResult{
		Period:    period,
		Timestamp: time.Now(),
	}

	if period == "" {
		period = "1h"
		result.Period = period
	}

	// Since we don't have historical data, analyze current state
	// and provide stability assessment

	// CPU trend
	cpuCollector := cpu.NewCollector()
	cpuInfo, err := cpuCollector.Collect(false)
	if err == nil {
		cpuTrend := types.Trend{
			Metric:     "cpu_percent",
			StartValue: cpuInfo.Percent,
			EndValue:   cpuInfo.Percent,
			Direction:  "stable",
			ChangeRate: 0,
			Slope:      0,
		}

		if cpuInfo.Percent > 80 {
			cpuTrend.Analysis = "CPU usage is high. Monitor for sustained load."
		} else if cpuInfo.Percent > 50 {
			cpuTrend.Analysis = "CPU usage is moderate."
		} else {
			cpuTrend.Analysis = "CPU usage is low. System is idle or lightly loaded."
		}

		result.Trends = append(result.Trends, cpuTrend)
	}

	// Memory trend
	memCollector := memory.NewCollector()
	memInfo, err := memCollector.Collect()
	if err == nil {
		memTrend := types.Trend{
			Metric:     "memory_percent",
			StartValue: memInfo.UsedPercent,
			EndValue:   memInfo.UsedPercent,
			Direction:  "stable",
			ChangeRate: 0,
			Slope:      0,
		}

		if memInfo.UsedPercent > 80 {
			memTrend.Analysis = "Memory usage is high. Watch for memory pressure."
		} else if memInfo.UsedPercent > 50 {
			memTrend.Analysis = "Memory usage is moderate."
		} else {
			memTrend.Analysis = "Memory usage is low. Adequate headroom available."
		}

		result.Trends = append(result.Trends, memTrend)
	}

	// Disk I/O trend (current activity)
	diskCollector := disk.NewCollector()
	ioCounters, err := diskCollector.GetIOCounters()
	if err == nil {
		var totalReads, totalWrites uint64
		for _, counter := range ioCounters {
			totalReads += counter.ReadBytes
			totalWrites += counter.WriteBytes
		}

		ioTrend := types.Trend{
			Metric:     "disk_io",
			StartValue: float64(totalReads + totalWrites),
			EndValue:   float64(totalReads + totalWrites),
			Direction:  "stable",
		}

		if totalWrites > totalReads*2 {
			ioTrend.Analysis = "Write-heavy I/O pattern detected."
		} else if totalReads > totalWrites*2 {
			ioTrend.Analysis = "Read-heavy I/O pattern detected."
		} else {
			ioTrend.Analysis = "Balanced read/write I/O pattern."
		}

		result.Trends = append(result.Trends, ioTrend)
	}

	return result, nil
}

// calculateMean computes the mean of a slice.
func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

// calculateStdDev computes the standard deviation.
func calculateStdDev(values []float64, mean float64) float64 {
	if len(values) < 2 {
		return 0
	}
	var sumSq float64
	for _, v := range values {
		diff := v - mean
		sumSq += diff * diff
	}
	return math.Sqrt(sumSq / float64(len(values)-1))
}

// calculatePercentile computes the p-th percentile.
func calculatePercentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sorted := make([]float64, len(values))
	copy(sorted, values)
	sort.Float64s(sorted)

	idx := (p / 100) * float64(len(sorted)-1)
	lower := int(idx)
	upper := lower + 1

	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}

	weight := idx - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}
