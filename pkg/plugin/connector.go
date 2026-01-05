package plugin

import (
	"context"
	"fmt"
	"time"
)

// ConnectionConfig holds connection parameters for external systems.
// Sensitive fields (Password, etc.) are never logged or returned in results.
type ConnectionConfig struct {
	// Host is the server hostname or IP address
	Host string `json:"host"`

	// Port is the server port number
	Port int `json:"port"`

	// Username for authentication (may be empty for some systems)
	Username string `json:"username,omitempty"`

	// Password for authentication - NEVER logged or returned
	Password string `json:"-"`

	// Database name (for database systems)
	Database string `json:"database,omitempty"`

	// Timeout for connection and operations
	Timeout time.Duration `json:"timeout,omitempty"`

	// TLS enables TLS/SSL connection
	TLS bool `json:"tls,omitempty"`

	// TLSSkipVerify disables certificate verification (not recommended)
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`

	// Options contains system-specific connection options
	Options map[string]string `json:"options,omitempty"`
}

// Connector defines the interface for plugins that connect to external systems.
type Connector interface {
	// Connect establishes a connection using the provided config.
	Connect(ctx context.Context, config ConnectionConfig) error

	// Close closes the connection.
	Close() error

	// IsConnected returns true if the connection is active.
	IsConnected() bool

	// Ping tests the connection health.
	Ping(ctx context.Context) error
}

// BaseConnector provides common functionality for connectors.
type BaseConnector struct {
	config    ConnectionConfig
	connected bool
}

// IsConnected returns the connection status.
func (c *BaseConnector) IsConnected() bool {
	return c.connected
}

// SetConnected updates the connection status.
func (c *BaseConnector) SetConnected(connected bool) {
	c.connected = connected
}

// GetConfig returns the connection config (for subclasses).
func (c *BaseConnector) GetConfig() ConnectionConfig {
	return c.config
}

// SetConfig sets the connection config.
func (c *BaseConnector) SetConfig(config ConnectionConfig) {
	c.config = config
}

// ConnectionError represents a connection failure.
type ConnectionError struct {
	System  string
	Host    string
	Port    int
	Message string
	Cause   error
}

func (e *ConnectionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s connection to %s:%d failed: %s (%v)", e.System, e.Host, e.Port, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s connection to %s:%d failed: %s", e.System, e.Host, e.Port, e.Message)
}

func (e *ConnectionError) Unwrap() error {
	return e.Cause
}

// NewConnectionError creates a new connection error.
func NewConnectionError(system, host string, port int, message string, cause error) *ConnectionError {
	return &ConnectionError{
		System:  system,
		Host:    host,
		Port:    port,
		Message: message,
		Cause:   cause,
	}
}

// ParseConnectionParams extracts connection config from tool parameters.
func ParseConnectionParams(params map[string]interface{}, defaults ConnectionConfig) ConnectionConfig {
	config := defaults

	if host := GetStringParam(params, "host", ""); host != "" {
		config.Host = host
	}
	if port := GetIntParam(params, "port", 0); port > 0 {
		config.Port = port
	}
	if user := GetStringParam(params, "username", ""); user != "" {
		config.Username = user
	}
	if pass := GetStringParam(params, "password", ""); pass != "" {
		config.Password = pass
	}
	if db := GetStringParam(params, "database", ""); db != "" {
		config.Database = db
	}
	if timeout := GetIntParam(params, "timeout", 0); timeout > 0 {
		config.Timeout = time.Duration(timeout) * time.Second
	}
	config.TLS = GetBoolParam(params, "tls", config.TLS)
	config.TLSSkipVerify = GetBoolParam(params, "tls_skip_verify", config.TLSSkipVerify)

	return config
}
