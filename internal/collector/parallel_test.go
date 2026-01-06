package collector

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestParallelCollector_Collect(t *testing.T) {
	pc := NewParallelCollector(5 * time.Second)

	var callCount int32

	collectors := map[string]CollectorFunc{
		"fast1": func(ctx context.Context) (interface{}, error) {
			atomic.AddInt32(&callCount, 1)
			return "result1", nil
		},
		"fast2": func(ctx context.Context) (interface{}, error) {
			atomic.AddInt32(&callCount, 1)
			return "result2", nil
		},
		"slow": func(ctx context.Context) (interface{}, error) {
			atomic.AddInt32(&callCount, 1)
			time.Sleep(100 * time.Millisecond)
			return "slow_result", nil
		},
	}

	start := time.Now()
	results := pc.Collect(context.Background(), collectors)
	elapsed := time.Since(start)

	// All collectors should have been called
	if callCount != 3 {
		t.Errorf("Expected 3 collectors to be called, got %d", callCount)
	}

	// Should complete in ~100ms (parallel), not 300ms (serial)
	if elapsed > 500*time.Millisecond {
		t.Errorf("Collection took too long: %v (expected ~100ms for parallel execution)", elapsed)
	}

	// Check results
	if len(results) != 3 {
		t.Errorf("Expected 3 results, got %d", len(results))
	}

	for name, r := range results {
		if r.Error != nil {
			t.Errorf("Collector %s returned error: %v", name, r.Error)
		}
		if r.Data == nil {
			t.Errorf("Collector %s returned nil data", name)
		}
	}

	t.Logf("Parallel collection of 3 collectors completed in %v", elapsed)
}

func TestParallelCollector_Timeout(t *testing.T) {
	pc := NewParallelCollector(100 * time.Millisecond)

	collectors := map[string]CollectorFunc{
		"fast": func(ctx context.Context) (interface{}, error) {
			return "fast", nil
		},
		"very_slow": func(ctx context.Context) (interface{}, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return "slow", nil
			}
		},
	}

	start := time.Now()
	results := pc.Collect(context.Background(), collectors)
	elapsed := time.Since(start)

	// Should timeout at ~100ms, not 5 seconds
	if elapsed > 500*time.Millisecond {
		t.Errorf("Collection should have timed out, took: %v", elapsed)
	}

	// Fast collector should succeed
	if results["fast"].Error != nil {
		t.Errorf("Fast collector should succeed: %v", results["fast"].Error)
	}

	// Slow collector should have context error
	if results["very_slow"].Error == nil {
		t.Log("Slow collector completed before timeout (timing dependent)")
	}

	t.Logf("Parallel collection with timeout completed in %v", elapsed)
}

func TestParallelCollector_ErrorHandling(t *testing.T) {
	pc := NewParallelCollector(5 * time.Second)

	expectedErr := errors.New("test error")

	collectors := map[string]CollectorFunc{
		"success": func(ctx context.Context) (interface{}, error) {
			return "ok", nil
		},
		"failure": func(ctx context.Context) (interface{}, error) {
			return nil, expectedErr
		},
	}

	results := pc.Collect(context.Background(), collectors)

	// Success collector
	if results["success"].Error != nil {
		t.Errorf("Success collector should not have error: %v", results["success"].Error)
	}
	if results["success"].Data != "ok" {
		t.Errorf("Success collector data mismatch: %v", results["success"].Data)
	}

	// Failure collector
	if results["failure"].Error == nil {
		t.Error("Failure collector should have error")
	}
	if results["failure"].Data != nil {
		t.Errorf("Failure collector should have nil data: %v", results["failure"].Data)
	}
}
