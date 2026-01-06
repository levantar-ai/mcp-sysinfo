// Package collector provides utilities for parallel data collection.
package collector

import (
	"context"
	"sync"
	"time"
)

// Result holds the result of a collection operation.
type Result struct {
	Name  string
	Data  interface{}
	Error error
}

// CollectorFunc is a function that collects data and returns a result.
type CollectorFunc func(ctx context.Context) (interface{}, error)

// ParallelCollector runs multiple collectors in parallel and aggregates results.
type ParallelCollector struct {
	timeout time.Duration
}

// NewParallelCollector creates a new parallel collector with the specified timeout.
func NewParallelCollector(timeout time.Duration) *ParallelCollector {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &ParallelCollector{timeout: timeout}
}

// Collect runs all collectors in parallel and returns results.
// Each collector is identified by name for easy result lookup.
func (pc *ParallelCollector) Collect(ctx context.Context, collectors map[string]CollectorFunc) map[string]Result {
	ctx, cancel := context.WithTimeout(ctx, pc.timeout)
	defer cancel()

	results := make(map[string]Result)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for name, fn := range collectors {
		wg.Add(1)
		go func(name string, fn CollectorFunc) {
			defer wg.Done()

			data, err := fn(ctx)

			mu.Lock()
			results[name] = Result{
				Name:  name,
				Data:  data,
				Error: err,
			}
			mu.Unlock()
		}(name, fn)
	}

	wg.Wait()
	return results
}

// CollectOrdered runs collectors in parallel but returns results in a slice
// preserving the order of the input names.
func (pc *ParallelCollector) CollectOrdered(ctx context.Context, names []string, collectors map[string]CollectorFunc) []Result {
	resultMap := pc.Collect(ctx, collectors)

	results := make([]Result, len(names))
	for i, name := range names {
		if r, ok := resultMap[name]; ok {
			results[i] = r
		} else {
			results[i] = Result{Name: name, Error: nil}
		}
	}
	return results
}
