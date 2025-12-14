// Package cmdexec provides a mockable command execution interface.
package cmdexec

import (
	"os/exec"
)

// CommandFunc is the function signature for creating commands.
type CommandFunc func(name string, arg ...string) *exec.Cmd

// Command is the package-level command function. Override in tests.
var Command CommandFunc = exec.Command

// Reset restores the default exec.Command.
func Reset() {
	Command = exec.Command
}
