package redact

import (
	"sync"
)

// Provider defines the interface for redaction providers.
// Implementations can use different detection mechanisms (pattern matching,
// external services like GitGuardian, etc.) to identify sensitive data.
type Provider interface {
	// Name returns the provider's identifier (e.g., "default", "gitguardian").
	Name() string

	// IsSensitiveField checks if a field name indicates sensitive content.
	IsSensitiveField(fieldName string) bool

	// IsSensitiveValue checks if a value matches sensitive patterns.
	IsSensitiveValue(value string) bool

	// RedactValue redacts a value if the field name or value is sensitive.
	// Returns the original value if not sensitive, or a redacted placeholder.
	RedactValue(fieldName, value string) string

	// RedactMap redacts sensitive values in a map.
	RedactMap(m map[string]string) map[string]string
}

// Config holds the redaction configuration.
type Config struct {
	// Enabled controls whether redaction is active. Default is false (opt-in).
	Enabled bool

	// ProviderName specifies which provider to use. Default is "default".
	ProviderName string

	// Provider is the active redaction provider instance.
	// If nil and Enabled is true, the default provider will be used.
	Provider Provider
}

// Global configuration with mutex for thread safety
var (
	globalConfig = &Config{
		Enabled:      false,
		ProviderName: "default",
	}
	configMu sync.RWMutex

	// Registry of available providers
	providers   = make(map[string]Provider)
	providersMu sync.RWMutex
)

func init() {
	// Register the default provider
	RegisterProvider(NewDefaultProvider())
}

// RegisterProvider adds a provider to the registry.
func RegisterProvider(p Provider) {
	providersMu.Lock()
	defer providersMu.Unlock()
	providers[p.Name()] = p
}

// GetProvider returns a provider by name, or nil if not found.
func GetProvider(name string) Provider {
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

// Configure sets the global redaction configuration.
func Configure(cfg Config) error {
	configMu.Lock()
	defer configMu.Unlock()

	// If provider is specified by name, look it up
	if cfg.Provider == nil && cfg.ProviderName != "" {
		cfg.Provider = GetProvider(cfg.ProviderName)
	}

	// Default to the default provider if none specified
	if cfg.Provider == nil {
		cfg.Provider = GetProvider("default")
	}

	globalConfig = &cfg
	return nil
}

// Enable enables redaction with the specified provider.
// If providerName is empty, uses the default provider.
func Enable(providerName string) {
	if providerName == "" {
		providerName = "default"
	}
	_ = Configure(Config{
		Enabled:      true,
		ProviderName: providerName,
		Provider:     GetProvider(providerName),
	})
}

// Disable disables redaction globally.
func Disable() {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig.Enabled = false
}

// IsEnabled returns whether redaction is currently enabled.
func IsEnabled() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig.Enabled
}

// GetConfig returns a copy of the current configuration.
func GetConfig() Config {
	configMu.RLock()
	defer configMu.RUnlock()
	return *globalConfig
}

// getActiveProvider returns the currently configured provider.
func getActiveProvider() Provider {
	configMu.RLock()
	defer configMu.RUnlock()

	if globalConfig.Provider != nil {
		return globalConfig.Provider
	}
	return GetProvider("default")
}

// NoOpProvider is a provider that performs no redaction.
// Used when redaction is disabled.
type NoOpProvider struct{}

func (NoOpProvider) Name() string                                    { return "noop" }
func (NoOpProvider) IsSensitiveField(string) bool                    { return false }
func (NoOpProvider) IsSensitiveValue(string) bool                    { return false }
func (NoOpProvider) RedactValue(_, value string) string              { return value }
func (NoOpProvider) RedactMap(m map[string]string) map[string]string { return m }

var noopProvider = &NoOpProvider{}

func init() {
	RegisterProvider(noopProvider)
}
