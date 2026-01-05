package plugin

import (
	"context"
	"errors"
	"testing"
)

func TestCollectorFunc(t *testing.T) {
	called := false
	expectedResult := map[string]string{"status": "ok"}

	cf := CollectorFunc(func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		called = true
		return expectedResult, nil
	})

	result, err := cf.Collect(context.Background(), nil)
	if err != nil {
		t.Errorf("CollectorFunc.Collect() error = %v", err)
	}
	if !called {
		t.Error("CollectorFunc.Collect() did not call function")
	}
	if result.(map[string]string)["status"] != "ok" {
		t.Error("CollectorFunc.Collect() returned wrong result")
	}
}

func TestCollectorFunc_Error(t *testing.T) {
	expectedErr := errors.New("collection failed")

	cf := CollectorFunc(func(ctx context.Context, params map[string]interface{}) (interface{}, error) {
		return nil, expectedErr
	})

	_, err := cf.Collect(context.Background(), nil)
	if err != expectedErr {
		t.Errorf("CollectorFunc.Collect() error = %v, want %v", err, expectedErr)
	}
}

func TestBaseCollector(t *testing.T) {
	bc := NewBaseCollector("test_collector")

	if got := bc.Name(); got != "test_collector" {
		t.Errorf("BaseCollector.Name() = %s, want test_collector", got)
	}
}

func TestGetStringParam(t *testing.T) {
	params := map[string]interface{}{
		"host":  "localhost",
		"empty": "",
	}

	tests := []struct {
		key      string
		defVal   string
		expected string
	}{
		{"host", "default", "localhost"},
		{"empty", "default", "default"}, // Empty string should use default
		{"missing", "default", "default"},
	}

	for _, tt := range tests {
		got := GetStringParam(params, tt.key, tt.defVal)
		if got != tt.expected {
			t.Errorf("GetStringParam(%q) = %s, want %s", tt.key, got, tt.expected)
		}
	}
}

func TestGetIntParam(t *testing.T) {
	params := map[string]interface{}{
		"port_float": float64(5432),
		"port_int":   3306,
		"zero":       float64(0),
	}

	tests := []struct {
		key      string
		defVal   int
		expected int
	}{
		{"port_float", 0, 5432},
		{"port_int", 0, 3306},
		{"zero", 100, 0},
		{"missing", 8080, 8080},
	}

	for _, tt := range tests {
		got := GetIntParam(params, tt.key, tt.defVal)
		if got != tt.expected {
			t.Errorf("GetIntParam(%q) = %d, want %d", tt.key, got, tt.expected)
		}
	}
}

func TestGetBoolParam(t *testing.T) {
	params := map[string]interface{}{
		"enabled":  true,
		"disabled": false,
	}

	tests := []struct {
		key      string
		defVal   bool
		expected bool
	}{
		{"enabled", false, true},
		{"disabled", true, false},
		{"missing", true, true},
		{"missing", false, false},
	}

	for _, tt := range tests {
		got := GetBoolParam(params, tt.key, tt.defVal)
		if got != tt.expected {
			t.Errorf("GetBoolParam(%q, %v) = %v, want %v", tt.key, tt.defVal, got, tt.expected)
		}
	}
}
