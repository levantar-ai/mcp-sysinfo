package plugin

import (
	"sort"
	"sync"

	"github.com/levantar-ai/mcp-sysinfo/internal/mcp"
)

// Registry holds all registered plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// DefaultRegistry is the global registry instance.
// Plugins register themselves via init() functions.
var DefaultRegistry = &Registry{
	plugins: make(map[string]Plugin),
}

// Register adds a plugin to the registry.
// This is typically called from a plugin's init() function.
func (r *Registry) Register(p Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[p.Name()] = p
}

// Get returns a plugin by name, or nil if not found.
func (r *Registry) Get(name string) Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.plugins[name]
}

// GetAll returns all registered plugins sorted by name.
func (r *Registry) GetAll() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Plugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		result = append(result, p)
	}

	// Sort by name for consistent ordering
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name() < result[j].Name()
	})

	return result
}

// Count returns the number of registered plugins.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.plugins)
}

// RegisterAllPlugins registers all plugins in the registry with the MCP server.
// Returns the number of successfully registered plugins and any errors.
func (r *Registry) RegisterAllPlugins(server *mcp.Server) (int, []error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var errors []error
	registered := 0

	for _, p := range r.plugins {
		if err := p.Register(server); err != nil {
			errors = append(errors, err)
		} else {
			registered++
		}
	}

	return registered, errors
}

// Register is a convenience function that registers with the default registry.
func Register(p Plugin) {
	DefaultRegistry.Register(p)
}
