// Package redact provides field-level and pattern-based redaction of sensitive data.
//
// This package implements a provider-based redaction system that is opt-in by default.
// Multiple providers are supported, including:
//   - DefaultProvider: Built-in pattern matching for common secrets
//   - GitGuardianProvider: Integration with GitGuardian's secret detection
//
// # Quick Start
//
// Redaction is disabled by default. To enable it:
//
//	// Enable with the default provider
//	redact.Enable("")
//
//	// Or enable with a specific provider
//	redact.Enable("gitguardian")
//
//	// Or configure with full options
//	redact.Configure(redact.Config{
//	    Enabled:      true,
//	    ProviderName: "default",
//	})
//
// # Using Redaction
//
// Once enabled, use the package-level functions:
//
//	value := redact.RedactValue("PASSWORD", "secret123")  // Returns "[REDACTED]"
//	value := redact.RedactValue("hostname", "server1")    // Returns "server1"
//
// # Custom Providers
//
// Implement the Provider interface and register it:
//
//	type MyProvider struct{}
//	func (p *MyProvider) Name() string { return "myprovider" }
//	// ... implement other methods
//
//	redact.RegisterProvider(&MyProvider{})
//	redact.Enable("myprovider")
package redact

// RedactedPlaceholder is the string used to replace sensitive values.
const RedactedPlaceholder = "[REDACTED]"

// Redactor is an alias for DefaultProvider for backward compatibility.
// Deprecated: Use DefaultProvider directly or the Provider interface.
type Redactor = DefaultProvider

// NewRedactor creates a new Redactor (DefaultProvider) with default settings.
// Deprecated: Use NewDefaultProvider instead.
func NewRedactor() *Redactor {
	return NewDefaultProvider()
}

// Package-level convenience functions
// These check if redaction is enabled before performing redaction.

// IsSensitiveField checks if a field name indicates sensitive content.
// Returns false if redaction is disabled.
func IsSensitiveField(fieldName string) bool {
	if !IsEnabled() {
		return false
	}
	return getActiveProvider().IsSensitiveField(fieldName)
}

// IsSensitiveValue checks if a value matches sensitive patterns.
// Returns false if redaction is disabled.
func IsSensitiveValue(value string) bool {
	if !IsEnabled() {
		return false
	}
	return getActiveProvider().IsSensitiveValue(value)
}

// RedactValue redacts a value if sensitive.
// Returns the original value unchanged if redaction is disabled.
func RedactValue(fieldName, value string) string {
	if !IsEnabled() {
		return value
	}
	return getActiveProvider().RedactValue(fieldName, value)
}

// RedactMap redacts sensitive values in a map.
// Returns the original map unchanged if redaction is disabled.
func RedactMap(m map[string]string) map[string]string {
	if !IsEnabled() {
		return m
	}
	return getActiveProvider().RedactMap(m)
}

// RedactConnectionString redacts credentials in connection strings.
// Returns the original string unchanged if redaction is disabled.
func RedactConnectionString(connStr string) string {
	if !IsEnabled() {
		return connStr
	}
	provider := getActiveProvider()
	if dp, ok := provider.(*DefaultProvider); ok {
		return dp.RedactConnectionString(connStr)
	}
	// For other providers, use the generic RedactValue
	return provider.RedactValue("connection_string", connStr)
}
