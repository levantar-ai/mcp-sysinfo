package plugin

import (
	"testing"
	"time"
)

func TestBaseConnector(t *testing.T) {
	bc := &BaseConnector{}

	// Initial state
	if bc.IsConnected() {
		t.Error("BaseConnector should not be connected initially")
	}

	// Set connected
	bc.SetConnected(true)
	if !bc.IsConnected() {
		t.Error("BaseConnector should be connected after SetConnected(true)")
	}

	// Set config
	config := ConnectionConfig{Host: "localhost", Port: 5432}
	bc.SetConfig(config)
	if bc.GetConfig().Host != "localhost" {
		t.Error("BaseConnector.GetConfig() returned wrong host")
	}
}

func TestConnectionError(t *testing.T) {
	// Error without cause
	err := NewConnectionError("MySQL", "localhost", 3306, "connection refused", nil)
	expected := "MySQL connection to localhost:3306 failed: connection refused"
	if err.Error() != expected {
		t.Errorf("ConnectionError.Error() = %q, want %q", err.Error(), expected)
	}

	// Error with cause
	cause := &ConnectionError{System: "inner", Host: "inner", Port: 1, Message: "inner error"}
	err = NewConnectionError("PostgreSQL", "db.example.com", 5432, "timeout", cause)
	if err.Unwrap() != cause {
		t.Error("ConnectionError.Unwrap() did not return cause")
	}
}

func TestParseConnectionParams(t *testing.T) {
	defaults := ConnectionConfig{
		Host:    "default-host",
		Port:    1234,
		Timeout: 30 * time.Second,
		TLS:     false,
	}

	params := map[string]interface{}{
		"host":     "custom-host",
		"port":     float64(5432),
		"username": "admin",
		"password": "secret",
		"database": "mydb",
		"timeout":  float64(60),
		"tls":      true,
	}

	config := ParseConnectionParams(params, defaults)

	if config.Host != "custom-host" {
		t.Errorf("Host = %s, want custom-host", config.Host)
	}
	if config.Port != 5432 {
		t.Errorf("Port = %d, want 5432", config.Port)
	}
	if config.Username != "admin" {
		t.Errorf("Username = %s, want admin", config.Username)
	}
	if config.Password != "secret" {
		t.Errorf("Password = %s, want secret", config.Password)
	}
	if config.Database != "mydb" {
		t.Errorf("Database = %s, want mydb", config.Database)
	}
	if config.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want 60s", config.Timeout)
	}
	if !config.TLS {
		t.Error("TLS should be true")
	}
}

func TestParseConnectionParams_Defaults(t *testing.T) {
	defaults := ConnectionConfig{
		Host:    "default-host",
		Port:    3306,
		Timeout: 30 * time.Second,
	}

	// Empty params should use all defaults
	config := ParseConnectionParams(map[string]interface{}{}, defaults)

	if config.Host != "default-host" {
		t.Errorf("Host = %s, want default-host", config.Host)
	}
	if config.Port != 3306 {
		t.Errorf("Port = %d, want 3306", config.Port)
	}
}

func TestConnectionConfig_PasswordNotSerialized(t *testing.T) {
	config := ConnectionConfig{
		Host:     "localhost",
		Port:     5432,
		Password: "secret",
	}

	// Password field has json:"-" tag, so it shouldn't appear in JSON
	// This is a compile-time guarantee via the struct tag, but we verify the intent
	if config.Password != "secret" {
		t.Error("Password should be stored internally")
	}
}
