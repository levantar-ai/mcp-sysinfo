package plugin

import (
	"context"
	"errors"
	"testing"

	"github.com/levantar-ai/mcp-sysinfo/internal/mcp"
)

// mockPlugin implements Plugin for testing
type mockPlugin struct {
	name        string
	version     string
	scope       string
	description string
	registerErr error
	toolCount   int
}

func (m *mockPlugin) Name() string        { return m.name }
func (m *mockPlugin) Version() string     { return m.version }
func (m *mockPlugin) Scope() string       { return m.scope }
func (m *mockPlugin) Description() string { return m.description }

func (m *mockPlugin) Register(server *mcp.Server) error {
	if m.registerErr != nil {
		return m.registerErr
	}
	// Register a dummy tool to simulate plugin registration
	for i := 0; i < m.toolCount; i++ {
		server.RegisterTool(mcp.Tool{
			Name:        m.name + "_tool",
			Description: "Test tool",
			InputSchema: mcp.InputSchema{Type: "object"},
		}, m.scope, func(ctx context.Context, args map[string]interface{}) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{}, nil
		})
	}
	return nil
}

func TestRegistry_Register(t *testing.T) {
	r := &Registry{plugins: make(map[string]Plugin)}

	p := &mockPlugin{name: "test", version: "1.0.0", scope: "test"}
	r.Register(p)

	if got := r.Get("test"); got != p {
		t.Errorf("Get() = %v, want %v", got, p)
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	r := &Registry{plugins: make(map[string]Plugin)}

	if got := r.Get("nonexistent"); got != nil {
		t.Errorf("Get() = %v, want nil", got)
	}
}

func TestRegistry_GetAll(t *testing.T) {
	r := &Registry{plugins: make(map[string]Plugin)}

	r.Register(&mockPlugin{name: "charlie"})
	r.Register(&mockPlugin{name: "alpha"})
	r.Register(&mockPlugin{name: "bravo"})

	all := r.GetAll()
	if len(all) != 3 {
		t.Errorf("GetAll() returned %d plugins, want 3", len(all))
	}

	// Should be sorted by name
	names := []string{all[0].Name(), all[1].Name(), all[2].Name()}
	expected := []string{"alpha", "bravo", "charlie"}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("GetAll()[%d].Name() = %s, want %s", i, name, expected[i])
		}
	}
}

func TestRegistry_Count(t *testing.T) {
	r := &Registry{plugins: make(map[string]Plugin)}

	if got := r.Count(); got != 0 {
		t.Errorf("Count() = %d, want 0", got)
	}

	r.Register(&mockPlugin{name: "test1"})
	r.Register(&mockPlugin{name: "test2"})

	if got := r.Count(); got != 2 {
		t.Errorf("Count() = %d, want 2", got)
	}
}

func TestRegistry_RegisterAllPlugins(t *testing.T) {
	r := &Registry{plugins: make(map[string]Plugin)}

	r.Register(&mockPlugin{name: "success1", scope: "test", toolCount: 1})
	r.Register(&mockPlugin{name: "success2", scope: "test", toolCount: 2})
	r.Register(&mockPlugin{name: "failure", registerErr: errors.New("registration failed")})

	server := mcp.NewServer("test", "1.0.0")
	count, errs := r.RegisterAllPlugins(server)

	if count != 2 {
		t.Errorf("RegisterAllPlugins() registered %d, want 2", count)
	}
	if len(errs) != 1 {
		t.Errorf("RegisterAllPlugins() returned %d errors, want 1", len(errs))
	}
}

func TestGlobalRegister(t *testing.T) {
	// Save original registry
	original := DefaultRegistry
	defer func() { DefaultRegistry = original }()

	// Create fresh registry for test
	DefaultRegistry = &Registry{plugins: make(map[string]Plugin)}

	p := &mockPlugin{name: "global_test"}
	Register(p)

	if got := DefaultRegistry.Get("global_test"); got != p {
		t.Error("Global Register() did not add plugin to DefaultRegistry")
	}
}

func TestPluginInfo(t *testing.T) {
	info := PluginInfo{
		Name:        "test",
		Version:     "1.0.0",
		Scope:       "test",
		Description: "Test plugin",
		ToolCount:   5,
	}

	if info.Name != "test" {
		t.Errorf("PluginInfo.Name = %s, want test", info.Name)
	}
}
