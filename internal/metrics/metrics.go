// Package metrics provides Prometheus metrics for MCP System Info.
package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	once     sync.Once
	registry *prometheus.Registry

	// Request metrics
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec

	// Tool metrics
	toolCallsTotal   *prometheus.CounterVec
	toolCallDuration *prometheus.HistogramVec
	toolCallErrors   *prometheus.CounterVec

	// Server info
	serverInfo *prometheus.GaugeVec

	// Authentication metrics
	authRequestsTotal *prometheus.CounterVec
)

// Init initializes the metrics registry and collectors.
func Init() {
	once.Do(func() {
		registry = prometheus.NewRegistry()

		// Add Go runtime metrics
		registry.MustRegister(collectors.NewGoCollector())
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

		// Request metrics
		requestsTotal = promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "mcp_sysinfo",
				Name:      "http_requests_total",
				Help:      "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		)

		requestDuration = promauto.With(registry).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "mcp_sysinfo",
				Name:      "http_request_duration_seconds",
				Help:      "HTTP request duration in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		)

		// Tool call metrics
		toolCallsTotal = promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "mcp_sysinfo",
				Name:      "tool_calls_total",
				Help:      "Total number of tool calls",
			},
			[]string{"tool", "scope"},
		)

		toolCallDuration = promauto.With(registry).NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "mcp_sysinfo",
				Name:      "tool_call_duration_seconds",
				Help:      "Tool call duration in seconds",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"tool"},
		)

		toolCallErrors = promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "mcp_sysinfo",
				Name:      "tool_call_errors_total",
				Help:      "Total number of tool call errors",
			},
			[]string{"tool", "error_type"},
		)

		// Server info
		serverInfo = promauto.With(registry).NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "mcp_sysinfo",
				Name:      "server_info",
				Help:      "Server information",
			},
			[]string{"version", "transport", "auth_method"},
		)

		// Authentication metrics
		authRequestsTotal = promauto.With(registry).NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "mcp_sysinfo",
				Name:      "auth_requests_total",
				Help:      "Total number of authentication requests",
			},
			[]string{"result"},
		)
	})
}

// Handler returns an HTTP handler for the /metrics endpoint.
func Handler() http.Handler {
	Init()
	return promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// RecordRequest records an HTTP request metric.
func RecordRequest(method, path, status string, duration time.Duration) {
	Init()
	requestsTotal.WithLabelValues(method, path, status).Inc()
	requestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
}

// RecordToolCall records a tool call metric.
func RecordToolCall(tool, scope string, duration time.Duration) {
	Init()
	toolCallsTotal.WithLabelValues(tool, scope).Inc()
	toolCallDuration.WithLabelValues(tool).Observe(duration.Seconds())
}

// RecordToolError records a tool call error.
func RecordToolError(tool, errorType string) {
	Init()
	toolCallErrors.WithLabelValues(tool, errorType).Inc()
}

// RecordAuth records an authentication attempt.
func RecordAuth(result string) {
	Init()
	authRequestsTotal.WithLabelValues(result).Inc()
}

// SetServerInfo sets the server info gauge.
func SetServerInfo(version, transport, authMethod string) {
	Init()
	serverInfo.WithLabelValues(version, transport, authMethod).Set(1)
}
