// Package audit provides structured audit logging for security and compliance.
//
// This package implements an industry-standard audit logging system with:
//   - JSON Lines format (each line is a self-contained JSON object)
//   - Tamper-evident logging with checksums and sequence numbers
//   - Immutable append-only writes
//   - Async buffered writing for performance
//   - File rotation support
//   - Provider-based architecture for extensibility
//
// # Quick Start
//
// Audit logging is opt-in. To enable:
//
//	audit.Enable(audit.Config{
//	    Output: "/var/log/mcp-sysinfo/audit.jsonl",
//	})
//
//	// Log an event
//	audit.Log(audit.Event{
//	    Action:   "tools/call",
//	    Resource: "get_cpu_info",
//	    Identity: "user@example.com",
//	})
//
// # Providers
//
// The default provider writes to local files. Custom providers can be
// implemented for remote logging, SIEM integration, etc.
package audit

import (
	"context"
	"sync"
	"time"
)

// Event represents a single audit log entry.
type Event struct {
	// Timestamp is when the event occurred (UTC).
	Timestamp time.Time `json:"timestamp"`

	// Sequence is a monotonically increasing sequence number for ordering
	// and detecting gaps (tamper evidence).
	Sequence uint64 `json:"seq"`

	// EventID is a unique identifier for this event (UUID).
	EventID string `json:"event_id"`

	// CorrelationID links related events (e.g., request/response pairs).
	CorrelationID string `json:"correlation_id,omitempty"`

	// Action is what operation was performed (e.g., "tools/call", "auth/login").
	Action string `json:"action"`

	// Resource is what was accessed (e.g., "get_cpu_info", "get_processes").
	Resource string `json:"resource,omitempty"`

	// Identity is who performed the action (from JWT sub claim, etc.).
	Identity string `json:"identity,omitempty"`

	// ClientIP is the client's IP address (for HTTP transport).
	ClientIP string `json:"client_ip,omitempty"`

	// Parameters are the input parameters for the action.
	Parameters map[string]interface{} `json:"params,omitempty"`

	// Result indicates success/failure.
	Result EventResult `json:"result"`

	// Error contains error details if Result is "error".
	Error string `json:"error,omitempty"`

	// Duration is how long the action took.
	Duration time.Duration `json:"duration_ns,omitempty"`

	// Metadata contains additional context.
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// PreviousHash is the hash of the previous event (chain integrity).
	PreviousHash string `json:"prev_hash,omitempty"`

	// Hash is the SHA-256 hash of this event (excluding this field).
	Hash string `json:"hash,omitempty"`
}

// EventResult represents the outcome of an audited action.
type EventResult string

const (
	ResultSuccess EventResult = "success"
	ResultError   EventResult = "error"
	ResultDenied  EventResult = "denied"
)

// Provider defines the interface for audit log backends.
type Provider interface {
	// Name returns the provider's identifier.
	Name() string

	// Write writes an event to the audit log.
	// Implementations must ensure durability before returning.
	Write(ctx context.Context, event *Event) error

	// Flush ensures all buffered events are written.
	Flush(ctx context.Context) error

	// Close closes the provider and releases resources.
	Close() error

	// Verify checks the integrity of the audit log.
	// Returns the number of events verified and any integrity errors.
	Verify(ctx context.Context) (int, error)
}

// Config holds audit logging configuration.
type Config struct {
	// Enabled controls whether audit logging is active.
	Enabled bool

	// ProviderName specifies which provider to use.
	ProviderName string

	// Provider is the active audit provider instance.
	Provider Provider

	// Output is the output destination (file path, URL, etc.).
	// Interpretation depends on the provider.
	Output string

	// BufferSize is the number of events to buffer before flushing.
	// 0 means synchronous writes (no buffering).
	BufferSize int

	// FlushInterval is how often to flush buffered events.
	FlushInterval time.Duration

	// MaxFileSize is the maximum size of a single log file before rotation.
	// 0 means no rotation.
	MaxFileSize int64

	// MaxFiles is the maximum number of rotated files to keep.
	MaxFiles int

	// IncludeHash enables hash chain for tamper evidence.
	IncludeHash bool

	// SyncWrite forces synchronous writes (fsync after each write).
	SyncWrite bool
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:       false,
		ProviderName:  "default",
		BufferSize:    100,
		FlushInterval: 5 * time.Second,
		MaxFileSize:   100 * 1024 * 1024, // 100MB
		MaxFiles:      10,
		IncludeHash:   true,
		SyncWrite:     false,
	}
}

// Global state
var (
	globalConfig   = DefaultConfig()
	globalProvider Provider
	configMu       sync.RWMutex

	// Provider registry
	providers   = make(map[string]func(Config) (Provider, error))
	providersMu sync.RWMutex

	// Sequence counter for tamper evidence
	sequence   uint64
	sequenceMu sync.Mutex
)

// RegisterProvider registers a provider factory function.
func RegisterProvider(name string, factory func(Config) (Provider, error)) {
	providersMu.Lock()
	defer providersMu.Unlock()
	providers[name] = factory
}

// GetProviderFactory returns a provider factory by name.
func GetProviderFactory(name string) func(Config) (Provider, error) {
	providersMu.RLock()
	defer providersMu.RUnlock()
	return providers[name]
}

// ListProviders returns the names of all registered providers.
func ListProviders() []string {
	providersMu.RLock()
	defer providersMu.RUnlock()
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	return names
}

// Configure sets up audit logging with the given configuration.
func Configure(cfg Config) error {
	configMu.Lock()
	defer configMu.Unlock()

	// Close existing provider if any
	if globalProvider != nil {
		if err := globalProvider.Close(); err != nil {
			// Log but don't fail
			_ = err
		}
	}

	if !cfg.Enabled {
		globalConfig = cfg
		globalProvider = nil
		return nil
	}

	// Get provider factory
	factory := GetProviderFactory(cfg.ProviderName)
	if factory == nil {
		factory = GetProviderFactory("default")
	}
	if factory == nil {
		return ErrNoProvider
	}

	// Create provider
	provider, err := factory(cfg)
	if err != nil {
		return err
	}

	globalConfig = cfg
	globalProvider = provider
	cfg.Provider = provider

	return nil
}

// Enable enables audit logging with the given output path.
func Enable(output string) error {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Output = output
	return Configure(cfg)
}

// Disable disables audit logging.
func Disable() error {
	return Configure(Config{Enabled: false})
}

// IsEnabled returns whether audit logging is enabled.
func IsEnabled() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig.Enabled && globalProvider != nil
}

// GetConfig returns the current configuration.
func GetConfig() Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig
}

// nextSequence returns the next sequence number.
func nextSequence() uint64 {
	sequenceMu.Lock()
	defer sequenceMu.Unlock()
	sequence++
	return sequence
}

// Errors
var (
	ErrNoProvider  = &AuditError{Message: "no audit provider configured"}
	ErrNotEnabled  = &AuditError{Message: "audit logging not enabled"}
	ErrWriteFailed = &AuditError{Message: "failed to write audit event"}
)

// AuditError represents an audit-specific error.
type AuditError struct {
	Message string
	Cause   error
}

func (e *AuditError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *AuditError) Unwrap() error {
	return e.Cause
}
