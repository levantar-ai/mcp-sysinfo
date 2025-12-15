package audit

import (
	"context"
	"time"
)

// Log writes an event to the audit log.
// Returns nil if audit logging is disabled.
func Log(event Event) error {
	return LogContext(context.Background(), event)
}

// LogContext writes an event to the audit log with context.
func LogContext(ctx context.Context, event Event) error {
	configMu.RLock()
	provider := globalProvider
	enabled := globalConfig.Enabled
	configMu.RUnlock()

	if !enabled || provider == nil {
		return nil
	}

	return provider.Write(ctx, &event)
}

// LogAction is a convenience function for logging a simple action.
func LogAction(action, resource, identity string, result EventResult) error {
	return Log(Event{
		Action:   action,
		Resource: resource,
		Identity: identity,
		Result:   result,
	})
}

// LogSuccess logs a successful action.
func LogSuccess(action, resource, identity string) error {
	return LogAction(action, resource, identity, ResultSuccess)
}

// LogError logs a failed action with error details.
func LogError(action, resource, identity string, err error) error {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	return Log(Event{
		Action:   action,
		Resource: resource,
		Identity: identity,
		Result:   ResultError,
		Error:    errMsg,
	})
}

// LogDenied logs an access denial.
func LogDenied(action, resource, identity, reason string) error {
	return Log(Event{
		Action:   action,
		Resource: resource,
		Identity: identity,
		Result:   ResultDenied,
		Error:    reason,
	})
}

// LogToolCall logs an MCP tool invocation.
func LogToolCall(toolName string, params map[string]interface{}, identity, clientIP string, duration time.Duration, result EventResult, errMsg string) error {
	return Log(Event{
		Action:     "tools/call",
		Resource:   toolName,
		Identity:   identity,
		ClientIP:   clientIP,
		Parameters: params,
		Duration:   duration,
		Result:     result,
		Error:      errMsg,
	})
}

// LogAuth logs an authentication event.
func LogAuth(action string, identity, clientIP string, result EventResult, metadata map[string]interface{}) error {
	return Log(Event{
		Action:   "auth/" + action,
		Identity: identity,
		ClientIP: clientIP,
		Result:   result,
		Metadata: metadata,
	})
}

// Flush ensures all buffered audit events are written.
func Flush() error {
	return FlushContext(context.Background())
}

// FlushContext ensures all buffered audit events are written.
func FlushContext(ctx context.Context) error {
	configMu.RLock()
	provider := globalProvider
	enabled := globalConfig.Enabled
	configMu.RUnlock()

	if !enabled || provider == nil {
		return nil
	}

	return provider.Flush(ctx)
}

// Verify checks the integrity of the audit log.
func Verify() (int, error) {
	return VerifyContext(context.Background())
}

// VerifyContext checks the integrity of the audit log.
func VerifyContext(ctx context.Context) (int, error) {
	configMu.RLock()
	provider := globalProvider
	enabled := globalConfig.Enabled
	configMu.RUnlock()

	if !enabled || provider == nil {
		return 0, ErrNotEnabled
	}

	return provider.Verify(ctx)
}

// Close gracefully shuts down audit logging.
func Close() error {
	configMu.Lock()
	defer configMu.Unlock()

	if globalProvider == nil {
		return nil
	}

	err := globalProvider.Close()
	globalProvider = nil
	globalConfig.Enabled = false
	return err
}

// WithCorrelationID returns an event builder with a correlation ID set.
type EventBuilder struct {
	event Event
}

// NewEvent creates a new event builder.
func NewEvent(action string) *EventBuilder {
	return &EventBuilder{
		event: Event{
			Action: action,
		},
	}
}

// WithCorrelationID sets the correlation ID.
func (b *EventBuilder) WithCorrelationID(id string) *EventBuilder {
	b.event.CorrelationID = id
	return b
}

// WithResource sets the resource.
func (b *EventBuilder) WithResource(resource string) *EventBuilder {
	b.event.Resource = resource
	return b
}

// WithIdentity sets the identity.
func (b *EventBuilder) WithIdentity(identity string) *EventBuilder {
	b.event.Identity = identity
	return b
}

// WithClientIP sets the client IP.
func (b *EventBuilder) WithClientIP(ip string) *EventBuilder {
	b.event.ClientIP = ip
	return b
}

// WithParams sets the parameters.
func (b *EventBuilder) WithParams(params map[string]interface{}) *EventBuilder {
	b.event.Parameters = params
	return b
}

// WithDuration sets the duration.
func (b *EventBuilder) WithDuration(d time.Duration) *EventBuilder {
	b.event.Duration = d
	return b
}

// WithMetadata sets the metadata.
func (b *EventBuilder) WithMetadata(metadata map[string]interface{}) *EventBuilder {
	b.event.Metadata = metadata
	return b
}

// Success logs the event as successful.
func (b *EventBuilder) Success() error {
	b.event.Result = ResultSuccess
	return Log(b.event)
}

// Error logs the event as an error.
func (b *EventBuilder) Error(err error) error {
	b.event.Result = ResultError
	if err != nil {
		b.event.Error = err.Error()
	}
	return Log(b.event)
}

// Denied logs the event as access denied.
func (b *EventBuilder) Denied(reason string) error {
	b.event.Result = ResultDenied
	b.event.Error = reason
	return Log(b.event)
}

// Log logs the event with the specified result.
func (b *EventBuilder) Log(result EventResult) error {
	b.event.Result = result
	return Log(b.event)
}
