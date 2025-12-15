package redact

import (
	"testing"
)

// setupTest enables redaction for tests and returns a cleanup function.
func setupTest(t *testing.T) func() {
	t.Helper()
	Enable("default")
	return func() {
		Disable()
	}
}

func TestIsSensitiveField(t *testing.T) {
	cleanup := setupTest(t)
	defer cleanup()

	tests := []struct {
		name      string
		fieldName string
		want      bool
	}{
		// Password-related
		{"lowercase password", "password", true},
		{"uppercase PASSWORD", "PASSWORD", true},
		{"mixed case Password", "Password", true},
		{"password in name", "db_password", true},
		{"password in name 2", "USER_PASSWORD", true},
		{"passwd", "passwd", true},
		{"pwd", "pwd", true},
		{"passphrase", "ssh_passphrase", true},
		{"RABBITMQ_DEFAULT_PASS", "RABBITMQ_DEFAULT_PASS", true},

		// Secret keys
		{"secret", "secret", true},
		{"SECRET_KEY", "SECRET_KEY", true},
		{"API_SECRET", "API_SECRET", true},
		{"client_secret", "client_secret", true},
		{"AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", true},

		// API keys and tokens
		{"api_key", "api_key", true},
		{"API_KEY", "API_KEY", true},
		{"apikey", "apikey", true},
		{"MYAPP_API_KEY", "MYAPP_API_KEY", true},
		{"token", "token", true},
		{"access_token", "access_token", true},
		{"refresh_token", "refresh_token", true},
		{"id_token", "id_token", true},
		{"auth_token", "auth_token", true},
		{"GITHUB_TOKEN", "GITHUB_TOKEN", true},

		// Private keys and certificates
		{"private_key", "private_key", true},
		{"PRIVATE_KEY", "PRIVATE_KEY", true},
		{"ssl_key", "ssl_key", true},
		{"SSL_PRIVATE_KEY_PATH", "SSL_PRIVATE_KEY_PATH", true},
		{"keystore_password", "KAFKA_SSL_KEYSTORE_PASSWORD", true},
		{"truststore", "KAFKA_SSL_TRUSTSTORE_PASSWORD", true},

		// Credentials/Authorization
		{"auth", "auth", true},
		{"authorization", "authorization", true},
		{"credential", "credential", true},
		{"credentials", "credentials", true},
		{"AdminCredentials", "AdminCredentials", true},
		{"PasswordCredential", "PasswordCredential", true},
		{"AuthKey", "AuthKey", true},

		// Non-sensitive fields
		{"PATH", "PATH", false},
		{"HOME", "HOME", false},
		{"USER", "USER", false},
		{"hostname", "hostname", false},
		{"port", "port", false},
		{"database_name", "database_name", false},
		{"log_level", "log_level", false},
		{"timeout", "timeout", false},
		{"max_connections", "max_connections", false},
		{"ELASTIC_HOST", "ELASTIC_HOST", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSensitiveField(tt.fieldName); got != tt.want {
				t.Errorf("IsSensitiveField(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

func TestIsSensitiveValue(t *testing.T) {
	cleanup := setupTest(t)
	defer cleanup()

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		// Connection strings with embedded credentials
		{"postgres connection string", "postgres://user:secretpass@localhost:5432/db", true},
		{"mysql connection string", "mysql://admin:password123@db.example.com:3306/mydb", true},
		{"amqp connection string", "amqp://rabbit:pass123@host/vhost", true},
		{"mongodb connection string", "mongodb://user:pass@cluster.mongodb.net/test", true},
		{"redis connection string", "redis://default:mypassword@redis.example.com:6379", true},

		// AWS credentials
		{"AWS Access Key ID AKIA", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS Access Key ID ASIA", "ASIAQNZGFP3KQK7EXAM", true},
		{"AWS Secret Access Key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", true},

		// JWT tokens
		{"JWT token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", true},

		// Private keys
		{"RSA private key header", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"EC private key header", "-----BEGIN EC PRIVATE KEY-----", true},
		{"OPENSSH private key", "-----BEGIN OPENSSH PRIVATE KEY-----", true},
		{"Encrypted private key", "-----BEGIN ENCRYPTED PRIVATE KEY-----", true},

		// GitHub tokens
		{"GitHub personal access token", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", true},
		{"GitHub OAuth token", "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", true},

		// Slack tokens
		{"Slack bot token", "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", true},
		{"Slack user token", "xoxp-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", true},

		// Stripe keys
		{"Stripe secret key", "sk_live_1234567890abcdefghijklmnop", true},
		{"Stripe restricted key", "rk_live_1234567890abcdefghijklmnop", true},

		// Bearer tokens
		{"Bearer token", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", true},

		// Long hex strings (potential API keys)
		{"32 char hex string", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", true},
		{"64 char hex string (SHA256)", "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", true},

		// Non-sensitive values
		{"short value", "hello", false},
		{"normal hostname", "localhost", false},
		{"IP address", "192.168.1.1", false},
		{"email address", "user@example.com", false},
		{"URL without credentials", "https://example.com/api/endpoint", false},
		{"path", "/home/user/documents", false},
		{"numeric value", "12345678", false},
		{"boolean string", "true", false},
		{"date string", "2024-01-15", false},
		{"normal text", "This is a normal log message", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSensitiveValue(tt.value); got != tt.want {
				t.Errorf("IsSensitiveValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestRedactValue(t *testing.T) {
	cleanup := setupTest(t)
	defer cleanup()

	tests := []struct {
		name      string
		fieldName string
		value     string
		want      string
	}{
		// Sensitive by field name
		{"password field", "password", "mysecretpassword", RedactedPlaceholder},
		{"token field", "API_TOKEN", "abc123", RedactedPlaceholder},
		{"secret field", "client_secret", "xyz789", RedactedPlaceholder},

		// Sensitive by value pattern
		{"connection string", "DATABASE_URL", "postgres://user:pass@localhost/db", RedactedPlaceholder},
		{"JWT in non-obvious field", "data", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IjqByrSRyF8fCcOuWNsPcKIYYGJPljWsVfRxZ7OA", RedactedPlaceholder},

		// Non-sensitive
		{"normal field value", "hostname", "server1.example.com", "server1.example.com"},
		{"path value", "log_path", "/var/log/app.log", "/var/log/app.log"},
		{"numeric value", "port", "8080", "8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactValue(tt.fieldName, tt.value); got != tt.want {
				t.Errorf("RedactValue(%q, %q) = %q, want %q", tt.fieldName, tt.value, got, tt.want)
			}
		})
	}
}

func TestRedactMap(t *testing.T) {
	cleanup := setupTest(t)
	defer cleanup()

	input := map[string]string{
		"PATH":                  "/usr/bin:/bin",
		"HOME":                  "/home/user",
		"PASSWORD":              "secretpass",
		"API_KEY":               "key123",
		"DATABASE_URL":          "postgres://user:pass@localhost/db",
		"LOG_LEVEL":             "debug",
		"GITHUB_TOKEN":          "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
		"NORMAL_SETTING":        "value123",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}

	result := RedactMap(input)

	// Check sensitive values are redacted
	sensitiveKeys := []string{"PASSWORD", "API_KEY", "DATABASE_URL", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"}
	for _, key := range sensitiveKeys {
		if result[key] != RedactedPlaceholder {
			t.Errorf("RedactMap: %s should be redacted, got %q", key, result[key])
		}
	}

	// Check non-sensitive values are preserved
	nonSensitiveKeys := []string{"PATH", "HOME", "LOG_LEVEL", "NORMAL_SETTING"}
	for _, key := range nonSensitiveKeys {
		if result[key] != input[key] {
			t.Errorf("RedactMap: %s should be preserved, got %q, want %q", key, result[key], input[key])
		}
	}
}

func TestRedactConnectionString(t *testing.T) {
	cleanup := setupTest(t)
	defer cleanup()

	tests := []struct {
		name    string
		connStr string
		want    string
	}{
		{
			"postgres",
			"postgres://admin:secretpass@localhost:5432/mydb",
			"postgres://admin:" + RedactedPlaceholder + "@localhost:5432/mydb",
		},
		{
			"mysql",
			"mysql://root:rootpass@db.example.com:3306/app",
			"mysql://root:" + RedactedPlaceholder + "@db.example.com:3306/app",
		},
		{
			"amqp",
			"amqp://rabbit:bunny123@mq.local/vhost",
			"amqp://rabbit:" + RedactedPlaceholder + "@mq.local/vhost",
		},
		{
			"mongodb",
			"mongodb://dbuser:dbpass@cluster.mongodb.net/test?retryWrites=true",
			"mongodb://dbuser:" + RedactedPlaceholder + "@cluster.mongodb.net/test?retryWrites=true",
		},
		{
			"redis",
			"redis://default:myredispass@redis.example.com:6379/0",
			"redis://default:" + RedactedPlaceholder + "@redis.example.com:6379/0",
		},
		{
			"no credentials",
			"https://api.example.com/v1/endpoint",
			"https://api.example.com/v1/endpoint",
		},
		{
			"not a connection string",
			"just some text",
			"just some text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactConnectionString(tt.connStr); got != tt.want {
				t.Errorf("RedactConnectionString(%q) = %q, want %q", tt.connStr, got, tt.want)
			}
		})
	}
}

func TestRedactorWithCustomKeywords(t *testing.T) {
	r := NewDefaultProvider().WithKeywords("mycompany_secret", "internal_key")

	tests := []struct {
		fieldName string
		want      bool
	}{
		{"MYCOMPANY_SECRET_VALUE", true},
		{"internal_key_123", true},
		{"normal_field", false},
	}

	for _, tt := range tests {
		if got := r.IsSensitiveField(tt.fieldName); got != tt.want {
			t.Errorf("IsSensitiveField(%q) with custom keywords = %v, want %v", tt.fieldName, got, tt.want)
		}
	}
}

func TestRedactorWithCustomPatterns(t *testing.T) {
	r := NewDefaultProvider().WithPatterns(`^custom-[a-z]+-[0-9]+$`)

	tests := []struct {
		value string
		want  bool
	}{
		{"custom-abc-123", true},
		{"custom-xyz-999", true},
		{"not-custom", false},
	}

	for _, tt := range tests {
		if got := r.IsSensitiveValue(tt.value); got != tt.want {
			t.Errorf("IsSensitiveValue(%q) with custom pattern = %v, want %v", tt.value, got, tt.want)
		}
	}
}

func TestRedactedPlaceholder(t *testing.T) {
	if RedactedPlaceholder != "[REDACTED]" {
		t.Errorf("RedactedPlaceholder = %q, want %q", RedactedPlaceholder, "[REDACTED]")
	}
}

func TestRedactionDisabledByDefault(t *testing.T) {
	// Ensure redaction is disabled
	Disable()

	// When disabled, nothing should be redacted
	if IsSensitiveField("PASSWORD") {
		t.Error("IsSensitiveField should return false when redaction is disabled")
	}

	if IsSensitiveValue("AKIAIOSFODNN7EXAMPLE") {
		t.Error("IsSensitiveValue should return false when redaction is disabled")
	}

	value := RedactValue("PASSWORD", "secret123")
	if value != "secret123" {
		t.Errorf("RedactValue should return original value when disabled, got %q", value)
	}
}

func TestEnableDisable(t *testing.T) {
	// Start disabled
	Disable()
	if IsEnabled() {
		t.Error("Should be disabled after Disable()")
	}

	// Enable
	Enable("")
	if !IsEnabled() {
		t.Error("Should be enabled after Enable()")
	}

	// Verify redaction works when enabled
	if !IsSensitiveField("PASSWORD") {
		t.Error("Should detect sensitive field when enabled")
	}

	// Disable again
	Disable()
	if IsEnabled() {
		t.Error("Should be disabled after second Disable()")
	}
}

func TestProviderRegistry(t *testing.T) {
	providers := ListProviders()
	if len(providers) < 2 {
		t.Errorf("Expected at least 2 providers (default, noop), got %d", len(providers))
	}

	// Check default provider exists
	defaultProvider := GetProvider("default")
	if defaultProvider == nil {
		t.Error("Default provider should be registered")
	}

	// Check noop provider exists
	noopProvider := GetProvider("noop")
	if noopProvider == nil {
		t.Error("NoOp provider should be registered")
	}
}

func TestGitGuardianProvider(t *testing.T) {
	p := NewGitGuardianProvider()
	// Disable API and CLI for deterministic pattern-only testing
	// (API/CLI may not detect known example keys like AKIAIOSFODNN7EXAMPLE)
	p.UseAPI = false
	p.UseCLI = false

	// Test field-level detection (same as default)
	if !p.IsSensitiveField("PASSWORD") {
		t.Error("GitGuardianProvider should detect PASSWORD as sensitive")
	}

	// Test pattern-based detection (uses GitGuardian patterns)
	if !p.IsSensitiveValue("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890") {
		t.Error("GitGuardianProvider should detect GitHub token")
	}

	if !p.IsSensitiveValue("AKIAIOSFODNN7EXAMPLE") {
		t.Error("GitGuardianProvider should detect AWS key")
	}

	// Test detection mode (should be patterns when API/CLI disabled)
	mode := p.GetDetectionMode()
	if mode != "patterns" {
		t.Errorf("Expected detection mode 'patterns', got '%s'", mode)
	}
}

// Benchmark tests
func BenchmarkIsSensitiveField(b *testing.B) {
	Enable("")
	defer Disable()

	fields := []string{"PASSWORD", "API_KEY", "hostname", "DATABASE_URL", "port"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, f := range fields {
			IsSensitiveField(f)
		}
	}
}

func BenchmarkIsSensitiveValue(b *testing.B) {
	Enable("")
	defer Disable()

	values := []string{
		"postgres://user:pass@localhost/db",
		"normal value",
		"AKIAIOSFODNN7EXAMPLE",
		"localhost",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, v := range values {
			IsSensitiveValue(v)
		}
	}
}

func BenchmarkRedactMap(b *testing.B) {
	Enable("")
	defer Disable()

	m := map[string]string{
		"PATH":         "/usr/bin",
		"PASSWORD":     "secret",
		"API_KEY":      "key123",
		"DATABASE_URL": "postgres://user:pass@host/db",
		"LOG_LEVEL":    "debug",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RedactMap(m)
	}
}
