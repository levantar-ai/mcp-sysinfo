package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("default config should have Enabled=false")
	}
	if cfg.ProviderName != "default" {
		t.Errorf("expected provider name 'default', got %q", cfg.ProviderName)
	}
	if cfg.BufferSize != 100 {
		t.Errorf("expected buffer size 100, got %d", cfg.BufferSize)
	}
	if cfg.FlushInterval != 5*time.Second {
		t.Errorf("expected flush interval 5s, got %v", cfg.FlushInterval)
	}
	if cfg.MaxFileSize != 100*1024*1024 {
		t.Errorf("expected max file size 100MB, got %d", cfg.MaxFileSize)
	}
	if cfg.MaxFiles != 10 {
		t.Errorf("expected max files 10, got %d", cfg.MaxFiles)
	}
	if !cfg.IncludeHash {
		t.Error("expected IncludeHash=true by default")
	}
}

func TestEnableDisable(t *testing.T) {
	// Clean up
	defer func() {
		_ = Close()
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	// Create temp file
	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	// Initially disabled
	if IsEnabled() {
		t.Error("audit should be disabled initially")
	}

	// Enable
	if err := Enable(auditFile); err != nil {
		t.Fatalf("failed to enable audit: %v", err)
	}

	if !IsEnabled() {
		t.Error("audit should be enabled after Enable()")
	}

	// Disable
	if err := Disable(); err != nil {
		t.Fatalf("failed to disable audit: %v", err)
	}

	if IsEnabled() {
		t.Error("audit should be disabled after Disable()")
	}
}

func TestLogWhenDisabled(t *testing.T) {
	// Ensure disabled
	configMu.Lock()
	globalConfig.Enabled = false
	globalProvider = nil
	configMu.Unlock()

	// Log should return nil when disabled
	err := Log(Event{Action: "test"})
	if err != nil {
		t.Errorf("Log() should return nil when disabled, got %v", err)
	}
}

func TestLogEvent(t *testing.T) {
	// Clean up
	defer func() {
		_ = Close()
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	// Configure with sync writes for predictable testing
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Output = auditFile
	cfg.BufferSize = 0 // Synchronous writes
	cfg.SyncWrite = true
	cfg.IncludeHash = true

	if err := Configure(cfg); err != nil {
		t.Fatalf("failed to configure audit: %v", err)
	}

	// Log an event
	err := Log(Event{
		Action:   "tools/call",
		Resource: "get_cpu_info",
		Identity: "test@example.com",
		Result:   ResultSuccess,
	})
	if err != nil {
		t.Fatalf("Log() failed: %v", err)
	}

	// Flush to ensure written
	if err := Flush(); err != nil {
		t.Fatalf("Flush() failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("failed to read audit file: %v", err)
	}

	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatalf("failed to parse event: %v", err)
	}

	if event.Action != "tools/call" {
		t.Errorf("expected action 'tools/call', got %q", event.Action)
	}
	if event.Resource != "get_cpu_info" {
		t.Errorf("expected resource 'get_cpu_info', got %q", event.Resource)
	}
	if event.Identity != "test@example.com" {
		t.Errorf("expected identity 'test@example.com', got %q", event.Identity)
	}
	if event.Result != ResultSuccess {
		t.Errorf("expected result 'success', got %q", event.Result)
	}
	if event.EventID == "" {
		t.Error("expected EventID to be populated")
	}
	if event.Timestamp.IsZero() {
		t.Error("expected Timestamp to be populated")
	}
	if event.Sequence == 0 {
		t.Error("expected Sequence to be > 0")
	}
	if event.Hash == "" {
		t.Error("expected Hash to be populated")
	}
}

func TestLogConvenienceFunctions(t *testing.T) {
	// Clean up
	defer func() {
		_ = Close()
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Output = auditFile
	cfg.BufferSize = 0
	cfg.SyncWrite = true

	if err := Configure(cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Test LogSuccess
	if err := LogSuccess("test", "resource", "user"); err != nil {
		t.Errorf("LogSuccess failed: %v", err)
	}

	// Test LogError
	if err := LogError("test", "resource", "user", &AuditError{Message: "test error"}); err != nil {
		t.Errorf("LogError failed: %v", err)
	}

	// Test LogDenied
	if err := LogDenied("test", "resource", "user", "access denied"); err != nil {
		t.Errorf("LogDenied failed: %v", err)
	}

	// Test LogToolCall
	if err := LogToolCall("get_cpu_info", map[string]interface{}{"foo": "bar"}, "user", "127.0.0.1", time.Second, ResultSuccess, ""); err != nil {
		t.Errorf("LogToolCall failed: %v", err)
	}

	// Test LogAuth
	if err := LogAuth("login", "user", "127.0.0.1", ResultSuccess, nil); err != nil {
		t.Errorf("LogAuth failed: %v", err)
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Verify 5 events written
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Errorf("expected 5 events, got %d", len(lines))
	}
}

func TestEventBuilder(t *testing.T) {
	// Clean up
	defer func() {
		_ = Close()
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Output = auditFile
	cfg.BufferSize = 0
	cfg.SyncWrite = true

	if err := Configure(cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Test builder pattern
	err := NewEvent("tools/call").
		WithResource("get_memory_info").
		WithIdentity("builder@test.com").
		WithClientIP("192.168.1.1").
		WithCorrelationID("corr-123").
		WithParams(map[string]interface{}{"unit": "bytes"}).
		WithDuration(500 * time.Millisecond).
		WithMetadata(map[string]interface{}{"version": "1.0"}).
		Success()

	if err != nil {
		t.Fatalf("builder.Success() failed: %v", err)
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Read and verify
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		t.Fatalf("failed to parse event: %v", err)
	}

	if event.Action != "tools/call" {
		t.Errorf("expected action 'tools/call', got %q", event.Action)
	}
	if event.Resource != "get_memory_info" {
		t.Errorf("expected resource 'get_memory_info', got %q", event.Resource)
	}
	if event.Identity != "builder@test.com" {
		t.Errorf("expected identity 'builder@test.com', got %q", event.Identity)
	}
	if event.ClientIP != "192.168.1.1" {
		t.Errorf("expected client IP '192.168.1.1', got %q", event.ClientIP)
	}
	if event.CorrelationID != "corr-123" {
		t.Errorf("expected correlation ID 'corr-123', got %q", event.CorrelationID)
	}
	if event.Duration != 500*time.Millisecond {
		t.Errorf("expected duration 500ms, got %v", event.Duration)
	}
}

func TestHashChainIntegrity(t *testing.T) {
	// Clean up
	defer func() {
		_ = Close()
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Output = auditFile
	cfg.BufferSize = 0
	cfg.SyncWrite = true
	cfg.IncludeHash = true

	if err := Configure(cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Write multiple events
	for i := 0; i < 5; i++ {
		if err := LogSuccess("test", "resource", "user"); err != nil {
			t.Fatalf("LogSuccess failed: %v", err)
		}
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Verify hash chain
	count, err := Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 verified events, got %d", count)
	}
}

func TestSequenceNumbers(t *testing.T) {
	// Clean up
	defer func() {
		_ = Close()
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Output = auditFile
	cfg.BufferSize = 0
	cfg.SyncWrite = true

	if err := Configure(cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Write events
	for i := 0; i < 3; i++ {
		if err := LogSuccess("test", "resource", "user"); err != nil {
			t.Fatalf("LogSuccess failed: %v", err)
		}
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	// Read and check sequences
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var prevSeq uint64
	for i, line := range lines {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("failed to parse line %d: %v", i, err)
		}

		if event.Sequence <= prevSeq {
			t.Errorf("sequence not monotonically increasing: %d <= %d at line %d", event.Sequence, prevSeq, i)
		}
		prevSeq = event.Sequence
	}
}

func TestConcurrentWrites(t *testing.T) {
	// Clean up
	defer func() {
		_ = Close()
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Output = auditFile
	cfg.BufferSize = 100
	cfg.FlushInterval = 100 * time.Millisecond
	cfg.IncludeHash = true

	if err := Configure(cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Concurrent writes
	var wg sync.WaitGroup
	numGoroutines := 10
	eventsPerGoroutine := 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				_ = LogSuccess("concurrent", "resource", "user")
			}
		}(i)
	}

	wg.Wait()

	// Close triggers final flush
	if err := Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Verify all events written
	data, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	expectedEvents := numGoroutines * eventsPerGoroutine
	if len(lines) != expectedEvents {
		t.Errorf("expected %d events, got %d", expectedEvents, len(lines))
	}
}

func TestProviderRegistry(t *testing.T) {
	// Check default provider is registered
	providers := ListProviders()
	found := false
	for _, name := range providers {
		if name == "default" {
			found = true
			break
		}
	}
	if !found {
		t.Error("default provider should be registered")
	}

	// Test GetProviderFactory
	factory := GetProviderFactory("default")
	if factory == nil {
		t.Error("GetProviderFactory should return default factory")
	}

	factory = GetProviderFactory("nonexistent")
	if factory != nil {
		t.Error("GetProviderFactory should return nil for nonexistent provider")
	}
}

func TestAuditError(t *testing.T) {
	// Error without cause
	err := &AuditError{Message: "test error"}
	if err.Error() != "test error" {
		t.Errorf("expected 'test error', got %q", err.Error())
	}
	if err.Unwrap() != nil {
		t.Error("Unwrap should return nil when no cause")
	}

	// Error with cause
	cause := &AuditError{Message: "cause"}
	err = &AuditError{Message: "wrapper", Cause: cause}
	if err.Error() != "wrapper: cause" {
		t.Errorf("expected 'wrapper: cause', got %q", err.Error())
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap should return the cause")
	}
}

func TestVerifyNotEnabled(t *testing.T) {
	// Ensure disabled
	configMu.Lock()
	globalConfig.Enabled = false
	globalProvider = nil
	configMu.Unlock()

	_, err := Verify()
	if err != ErrNotEnabled {
		t.Errorf("expected ErrNotEnabled, got %v", err)
	}
}

func TestFlushWhenDisabled(t *testing.T) {
	// Ensure disabled
	configMu.Lock()
	globalConfig.Enabled = false
	globalProvider = nil
	configMu.Unlock()

	err := Flush()
	if err != nil {
		t.Errorf("Flush should return nil when disabled, got %v", err)
	}
}

func TestCloseIdempotent(t *testing.T) {
	// Clean up
	defer func() {
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	if err := Enable(auditFile); err != nil {
		t.Fatalf("failed to enable: %v", err)
	}

	// Close multiple times should not error
	if err := Close(); err != nil {
		t.Errorf("first Close failed: %v", err)
	}
	if err := Close(); err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

func TestLogContext(t *testing.T) {
	// Clean up
	defer func() {
		_ = Close()
		configMu.Lock()
		globalConfig = DefaultConfig()
		globalProvider = nil
		configMu.Unlock()
	}()

	tmpDir := t.TempDir()
	auditFile := filepath.Join(tmpDir, "audit.jsonl")

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Output = auditFile
	cfg.BufferSize = 0
	cfg.SyncWrite = true

	if err := Configure(cfg); err != nil {
		t.Fatalf("failed to configure: %v", err)
	}

	// Test with context
	ctx := context.Background()
	err := LogContext(ctx, Event{
		Action: "context/test",
		Result: ResultSuccess,
	})
	if err != nil {
		t.Fatalf("LogContext failed: %v", err)
	}

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Cancelled context should still work for synchronous writes
	err = LogContext(ctx, Event{
		Action: "context/cancelled",
		Result: ResultSuccess,
	})
	if err != nil {
		t.Logf("LogContext with cancelled context: %v (may be expected)", err)
	}

	if err := Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
}
