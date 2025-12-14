package tokenserver

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds the token server configuration.
type Config struct {
	// Server settings
	ListenAddr string `json:"listen_addr"`
	TLSCert    string `json:"tls_cert,omitempty"`
	TLSKey     string `json:"tls_key,omitempty"`

	// Token settings
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	DefaultTTL int    `json:"default_ttl"` // seconds
	MaxTTL     int    `json:"max_ttl"`     // seconds

	// Storage paths
	KeyDir      string `json:"key_dir"`
	ClientsFile string `json:"clients_file"`

	// Key rotation
	KeyRotationHours int `json:"key_rotation_hours"`
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:       "127.0.0.1:8444",
		Issuer:           "http://localhost:8444",
		Audience:         "mcp-sysinfo",
		DefaultTTL:       300,  // 5 minutes
		MaxTTL:           300,  // 5 minutes max (per security docs)
		KeyDir:           "",   // In-memory keys by default
		ClientsFile:      "",   // No persistence by default
		KeyRotationHours: 24,
	}
}

// LoadConfig reads configuration from a JSON file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}
	if c.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if c.Audience == "" {
		return fmt.Errorf("audience is required")
	}
	if c.DefaultTTL <= 0 {
		return fmt.Errorf("default_ttl must be positive")
	}
	if c.MaxTTL <= 0 {
		return fmt.Errorf("max_ttl must be positive")
	}
	if c.MaxTTL > 300 {
		return fmt.Errorf("max_ttl cannot exceed 300 seconds (5 minutes) per security policy")
	}

	// If TLS is partially configured, that's an error
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("both tls_cert and tls_key must be provided, or neither")
	}

	return nil
}

// GetDefaultTTL returns the default TTL as a duration.
func (c *Config) GetDefaultTTL() time.Duration {
	return time.Duration(c.DefaultTTL) * time.Second
}

// GetMaxTTL returns the max TTL as a duration.
func (c *Config) GetMaxTTL() time.Duration {
	return time.Duration(c.MaxTTL) * time.Second
}

// IsTLSEnabled returns true if TLS is configured.
func (c *Config) IsTLSEnabled() bool {
	return c.TLSCert != "" && c.TLSKey != ""
}
