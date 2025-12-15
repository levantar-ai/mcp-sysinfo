package redact

import (
	"regexp"
	"strings"
)

// DefaultProvider implements the Provider interface using built-in
// pattern matching for sensitive field names and value patterns.
type DefaultProvider struct {
	// AdditionalKeywords allows adding custom sensitive field keywords.
	AdditionalKeywords []string
	// AdditionalPatterns allows adding custom value patterns (as regex strings).
	AdditionalPatterns []string
	// compiledAdditionalPatterns caches compiled additional patterns.
	compiledAdditionalPatterns []*regexp.Regexp
}

// sensitiveFieldKeywords are keywords that indicate a field contains sensitive data.
// These are matched case-insensitively against field/variable names.
var sensitiveFieldKeywords = []string{
	// Password-related
	"password",
	"passwd",
	"pwd",
	"pass",
	"passphrase",
	// Secret keys
	"secret",
	// API keys and tokens
	"api_key",
	"apikey",
	"token",
	"access_token",
	"refresh_token",
	"id_token",
	"auth_token",
	// Private keys and certificates
	"private_key",
	"privatekey",
	"ssl_key",
	"sslkey",
	"keystore",
	"truststore",
	// Credentials/Authorization
	"auth",
	"authorization",
	"credential",
	"credentials",
}

// sensitiveValuePatterns are compiled regex patterns that match sensitive values.
var sensitiveValuePatterns []*regexp.Regexp

func init() {
	patterns := []string{
		// Connection strings with embedded credentials: protocol://user:pass@host
		// Matches: postgres://user:pass@host, mysql://user:secret@host, amqp://user:pwd@host
		`(?i)^[a-z][a-z0-9+.-]*://[^:]+:[^@]+@`,

		// AWS Access Key ID (starts with AKIA, AIDA, AROA, AIPA, ANPA, ANVA, ASIA)
		// Format is 20 characters total: 4-char prefix + 16 alphanumeric
		`^(AKIA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,17}$`,

		// AWS Secret Access Key (40 character base64-like string)
		`^[A-Za-z0-9/+=]{40}$`,

		// JWT tokens (three base64 segments separated by dots)
		`^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$`,

		// Private key content (PEM format markers)
		`(?i)-----BEGIN\s+(RSA|DSA|EC|OPENSSH|ENCRYPTED|PRIVATE)\s+.*KEY-----`,

		// GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
		`^gh[pousr]_[A-Za-z0-9_]{36,}$`,

		// Generic API key patterns (32+ hex characters)
		`^[a-fA-F0-9]{32,}$`,

		// Slack tokens
		`^xox[baprs]-[0-9A-Za-z-]+$`,

		// Stripe keys
		`^sk_live_[0-9a-zA-Z]{24,}$`,
		`^rk_live_[0-9a-zA-Z]{24,}$`,

		// Basic auth in URLs: user:pass (when value contains @ and :// pattern)
		`(?i)://[^/@:]+:[^/@]+@`,

		// Bearer token pattern
		`(?i)^bearer\s+[a-zA-Z0-9._-]+$`,

		// Generic long hex string that could be a key (64 chars - SHA256, etc.)
		`^[a-fA-F0-9]{64}$`,
	}

	for _, p := range patterns {
		sensitiveValuePatterns = append(sensitiveValuePatterns, regexp.MustCompile(p))
	}
}

// NewDefaultProvider creates a new DefaultProvider.
func NewDefaultProvider() *DefaultProvider {
	return &DefaultProvider{}
}

// NewDefaultProviderWithOptions creates a DefaultProvider with custom keywords and patterns.
func NewDefaultProviderWithOptions(keywords []string, patterns []string) *DefaultProvider {
	p := &DefaultProvider{
		AdditionalKeywords: keywords,
	}
	for _, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			p.compiledAdditionalPatterns = append(p.compiledAdditionalPatterns, compiled)
			p.AdditionalPatterns = append(p.AdditionalPatterns, pattern)
		}
	}
	return p
}

// Name returns the provider identifier.
func (p *DefaultProvider) Name() string {
	return "default"
}

// WithKeywords returns a DefaultProvider with additional sensitive keywords.
func (p *DefaultProvider) WithKeywords(keywords ...string) *DefaultProvider {
	p.AdditionalKeywords = append(p.AdditionalKeywords, keywords...)
	return p
}

// WithPatterns returns a DefaultProvider with additional value patterns.
func (p *DefaultProvider) WithPatterns(patterns ...string) *DefaultProvider {
	for _, pattern := range patterns {
		if compiled, err := regexp.Compile(pattern); err == nil {
			p.compiledAdditionalPatterns = append(p.compiledAdditionalPatterns, compiled)
			p.AdditionalPatterns = append(p.AdditionalPatterns, pattern)
		}
	}
	return p
}

// IsSensitiveField checks if a field name indicates sensitive content.
// The check is case-insensitive and looks for keywords anywhere in the field name.
func (p *DefaultProvider) IsSensitiveField(fieldName string) bool {
	upper := strings.ToUpper(fieldName)

	// Check built-in keywords
	for _, keyword := range sensitiveFieldKeywords {
		if strings.Contains(upper, strings.ToUpper(keyword)) {
			return true
		}
	}

	// Check additional keywords
	for _, keyword := range p.AdditionalKeywords {
		if strings.Contains(upper, strings.ToUpper(keyword)) {
			return true
		}
	}

	return false
}

// IsSensitiveValue checks if a value matches sensitive patterns.
// This catches secrets that might not be in obviously-named fields.
func (p *DefaultProvider) IsSensitiveValue(value string) bool {
	// Skip empty or very short values
	if len(value) < 8 {
		return false
	}

	// Check built-in patterns
	for _, pattern := range sensitiveValuePatterns {
		if pattern.MatchString(value) {
			return true
		}
	}

	// Check additional patterns
	for _, pattern := range p.compiledAdditionalPatterns {
		if pattern.MatchString(value) {
			return true
		}
	}

	return false
}

// RedactValue redacts a value if the field name indicates sensitivity
// or if the value itself matches sensitive patterns.
// Returns the original value if not sensitive, or RedactedPlaceholder if sensitive.
func (p *DefaultProvider) RedactValue(fieldName, value string) string {
	if p.IsSensitiveField(fieldName) || p.IsSensitiveValue(value) {
		return RedactedPlaceholder
	}
	return value
}

// RedactMap redacts sensitive values in a map based on key names and value patterns.
// Returns a new map with sensitive values replaced by RedactedPlaceholder.
func (p *DefaultProvider) RedactMap(m map[string]string) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = p.RedactValue(k, v)
	}
	return result
}

// RedactConnectionString redacts credentials embedded in connection strings.
// Supports formats like: protocol://user:password@host:port/database
func (p *DefaultProvider) RedactConnectionString(connStr string) string {
	// Pattern to match connection strings with embedded credentials
	pattern := regexp.MustCompile(`(?i)^([a-z][a-z0-9+.-]*://)([^:]+):([^@]+)@(.+)$`)

	if matches := pattern.FindStringSubmatch(connStr); len(matches) == 5 {
		// Return: protocol://user:[REDACTED]@host
		return matches[1] + matches[2] + ":" + RedactedPlaceholder + "@" + matches[4]
	}

	return connStr
}
