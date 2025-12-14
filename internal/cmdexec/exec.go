// Package cmdexec provides a mockable command execution interface.
// Usage in collectors:
//
//	import "github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
//	cmd := cmdexec.Command("ls", "-la")
//
// Usage in tests:
//
//	cmdexec.SetMockOutput("system_profiler", `{"SPHardwareDataType": [...]}`)
//	defer cmdexec.Reset()
package cmdexec

import (
	"os"
	"os/exec"
	"sync"
)

// CommandFunc is the function signature for creating commands.
type CommandFunc func(name string, arg ...string) *exec.Cmd

var (
	mu          sync.RWMutex
	commandFunc CommandFunc = exec.Command
	mockOutputs             = make(map[string]mockResult)
)

type mockResult struct {
	output   string
	exitCode int
}

// Command creates a new exec.Cmd. Override with SetCommandFunc for testing.
func Command(name string, arg ...string) *exec.Cmd {
	mu.RLock()
	fn := commandFunc
	mu.RUnlock()
	return fn(name, arg...)
}

// LookPath wraps exec.LookPath for consistency.
func LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// SetCommandFunc replaces the command function (for testing).
func SetCommandFunc(fn CommandFunc) {
	mu.Lock()
	commandFunc = fn
	mu.Unlock()
}

// SetMockOutput sets mock output for a specific command.
// The mock will be used when Command is called with matching name.
func SetMockOutput(cmdName, output string) {
	mu.Lock()
	mockOutputs[cmdName] = mockResult{output: output, exitCode: 0}
	mu.Unlock()
}

// SetMockError sets mock output and exit code for a command.
func SetMockError(cmdName, output string, exitCode int) {
	mu.Lock()
	mockOutputs[cmdName] = mockResult{output: output, exitCode: exitCode}
	mu.Unlock()
}

// UseMocks enables the mock command function.
// Call defer Reset() to restore normal behavior.
func UseMocks() {
	mu.Lock()
	commandFunc = mockCommandFunc
	mu.Unlock()
}

// Reset restores the default exec.Command and clears mocks.
func Reset() {
	mu.Lock()
	commandFunc = exec.Command
	mockOutputs = make(map[string]mockResult)
	mu.Unlock()
}

// mockCommandFunc creates a command that will output mock data.
func mockCommandFunc(name string, arg ...string) *exec.Cmd {
	mu.RLock()
	mock, hasMock := mockOutputs[name]
	mu.RUnlock()

	if !hasMock {
		// No mock registered - return empty output
		mock = mockResult{output: "", exitCode: 0}
	}

	// Create a command that runs the test helper process
	cs := []string{"-test.run=TestHelperProcess", "--", name}
	cs = append(cs, arg...)
	// #nosec G204 -- intentional for test mocking, args come from test setup
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"MOCK_OUTPUT="+mock.output,
		"MOCK_EXIT_CODE="+string(rune('0'+mock.exitCode)),
	)
	return cmd
}

// HelperProcess should be called from TestHelperProcess in test files.
// Add this to any test file that needs mocking:
//
//	func TestHelperProcess(t *testing.T) {
//	    cmdexec.HelperProcess()
//	}
func HelperProcess() {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	output := os.Getenv("MOCK_OUTPUT")
	_, _ = os.Stdout.WriteString(output)
	os.Exit(0)
}
