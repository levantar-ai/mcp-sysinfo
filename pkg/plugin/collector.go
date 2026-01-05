package plugin

import "context"

// Collector defines the interface for data collection from external systems.
// Plugins implement this interface for each query type they support.
type Collector interface {
	// Collect gathers data and returns a JSON-serializable result.
	// The params map contains query-specific parameters.
	Collect(ctx context.Context, params map[string]interface{}) (interface{}, error)
}

// CollectorFunc is a function adapter for Collector.
// It allows using a simple function as a Collector.
type CollectorFunc func(ctx context.Context, params map[string]interface{}) (interface{}, error)

// Collect implements the Collector interface.
func (f CollectorFunc) Collect(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	return f(ctx, params)
}

// BaseCollector provides common functionality for collectors.
type BaseCollector struct {
	name string
}

// NewBaseCollector creates a new base collector with the given name.
func NewBaseCollector(name string) *BaseCollector {
	return &BaseCollector{name: name}
}

// Name returns the collector name.
func (c *BaseCollector) Name() string {
	return c.name
}

// GetStringParam extracts a string parameter with a default value.
func GetStringParam(params map[string]interface{}, key, defaultVal string) string {
	if v, ok := params[key].(string); ok && v != "" {
		return v
	}
	return defaultVal
}

// GetIntParam extracts an integer parameter with a default value.
func GetIntParam(params map[string]interface{}, key string, defaultVal int) int {
	if v, ok := params[key].(float64); ok {
		return int(v)
	}
	if v, ok := params[key].(int); ok {
		return v
	}
	return defaultVal
}

// GetBoolParam extracts a boolean parameter with a default value.
func GetBoolParam(params map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := params[key].(bool); ok {
		return v
	}
	return defaultVal
}
