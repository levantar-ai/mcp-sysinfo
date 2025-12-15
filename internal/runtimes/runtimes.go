// Package runtimes provides language runtime version detection.
package runtimes

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/cmdexec"
	"github.com/levantar-ai/mcp-sysinfo/pkg/types"
)

// Collector collects language runtime information.
type Collector struct{}

// NewCollector creates a new runtimes collector.
func NewCollector() *Collector {
	return &Collector{}
}

// GetLanguageRuntimes detects installed language runtimes and their versions.
func (c *Collector) GetLanguageRuntimes() (*types.LanguageRuntimesResult, error) {
	result := &types.LanguageRuntimesResult{
		Timestamp: time.Now(),
	}

	// Detect Python
	if runtime := c.detectPython(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	// Detect Node.js
	if runtime := c.detectNode(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	// Detect Go
	if runtime := c.detectGo(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	// Detect Ruby
	if runtime := c.detectRuby(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	// Detect Java
	if runtime := c.detectJava(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	// Detect PHP
	if runtime := c.detectPHP(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	// Detect Rust
	if runtime := c.detectRust(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	// Detect .NET
	if runtime := c.detectDotNet(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	// Detect Perl
	if runtime := c.detectPerl(); runtime != nil {
		result.Runtimes = append(result.Runtimes, *runtime)
	}

	result.Count = len(result.Runtimes)
	return result, nil
}

// detectPython detects Python runtime.
func (c *Collector) detectPython() *types.LanguageRuntime {
	// Try python3 first, then python
	for _, cmd := range []string{"python3", "python"} {
		path, err := cmdexec.LookPath(cmd)
		if err != nil {
			continue
		}

		runtime := &types.LanguageRuntime{
			Name: "python",
			Path: path,
		}

		// Get version
		// #nosec G204 -- no user input
		if output, err := cmdexec.Command(cmd, "--version").Output(); err == nil {
			// Output: "Python 3.11.4" or "Python 2.7.18"
			re := regexp.MustCompile(`Python\s+([\d.]+)`)
			if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
				runtime.Version = matches[1]
			}
		}

		// Detect package manager (pip)
		pipCmd := "pip"
		if cmd == "python3" {
			pipCmd = "pip3"
		}
		if pipPath, err := cmdexec.LookPath(pipCmd); err == nil {
			runtime.Manager = pipCmd
			// Get pip version
			// #nosec G204 -- no user input
			if output, err := cmdexec.Command(pipPath, "--version").Output(); err == nil {
				// Output: "pip 23.0.1 from /usr/lib/python3/dist-packages/pip (python 3.11)"
				re := regexp.MustCompile(`pip\s+([\d.]+)`)
				if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
					runtime.ManagerVer = matches[1]
				}
			}
		}

		// Check for virtualenv
		if os.Getenv("VIRTUAL_ENV") != "" {
			runtime.Environment = "virtualenv"
			runtime.DefaultPkg = filepath.Join(os.Getenv("VIRTUAL_ENV"), "lib", "python"+runtime.Version[:3], "site-packages")
		} else if os.Getenv("CONDA_DEFAULT_ENV") != "" {
			runtime.Environment = "conda"
		}

		return runtime
	}

	return nil
}

// detectNode detects Node.js runtime.
func (c *Collector) detectNode() *types.LanguageRuntime {
	path, err := cmdexec.LookPath("node")
	if err != nil {
		return nil
	}

	runtime := &types.LanguageRuntime{
		Name: "node",
		Path: path,
	}

	// Get version
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command(path, "--version").Output(); err == nil {
		// Output: "v20.10.0"
		version := strings.TrimSpace(string(output))
		runtime.Version = strings.TrimPrefix(version, "v")
	}

	// Check for npm
	if npmPath, err := cmdexec.LookPath("npm"); err == nil {
		runtime.Manager = "npm"
		// #nosec G204 -- no user input
		if output, err := cmdexec.Command(npmPath, "--version").Output(); err == nil {
			runtime.ManagerVer = strings.TrimSpace(string(output))
		}
	}

	// Check for nvm
	if os.Getenv("NVM_DIR") != "" {
		runtime.Environment = "nvm"
	} else if os.Getenv("NVM_BIN") != "" {
		runtime.Environment = "nvm"
	}

	return runtime
}

// detectGo detects Go runtime.
func (c *Collector) detectGo() *types.LanguageRuntime {
	path, err := cmdexec.LookPath("go")
	if err != nil {
		return nil
	}

	runtime := &types.LanguageRuntime{
		Name:    "go",
		Path:    path,
		Manager: "go mod",
	}

	// Get version
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command(path, "version").Output(); err == nil {
		// Output: "go version go1.21.5 linux/amd64"
		re := regexp.MustCompile(`go([\d.]+)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
			runtime.Version = matches[1]
		}
	}

	// Check for GOPATH/GOROOT
	if gopath := os.Getenv("GOPATH"); gopath != "" {
		runtime.DefaultPkg = filepath.Join(gopath, "pkg", "mod")
	} else {
		home, _ := os.UserHomeDir()
		runtime.DefaultPkg = filepath.Join(home, "go", "pkg", "mod")
	}

	return runtime
}

// detectRuby detects Ruby runtime.
func (c *Collector) detectRuby() *types.LanguageRuntime {
	path, err := cmdexec.LookPath("ruby")
	if err != nil {
		return nil
	}

	runtime := &types.LanguageRuntime{
		Name: "ruby",
		Path: path,
	}

	// Get version
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command(path, "--version").Output(); err == nil {
		// Output: "ruby 3.2.2 (2023-03-30 revision e51014f9c0) [x86_64-linux]"
		re := regexp.MustCompile(`ruby\s+([\d.]+)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
			runtime.Version = matches[1]
		}
	}

	// Check for gem
	if gemPath, err := cmdexec.LookPath("gem"); err == nil {
		runtime.Manager = "gem"
		// #nosec G204 -- no user input
		if output, err := cmdexec.Command(gemPath, "--version").Output(); err == nil {
			runtime.ManagerVer = strings.TrimSpace(string(output))
		}
	}

	// Check for rbenv/rvm
	if os.Getenv("RBENV_VERSION") != "" || os.Getenv("RBENV_ROOT") != "" {
		runtime.Environment = "rbenv"
	} else if os.Getenv("rvm_path") != "" {
		runtime.Environment = "rvm"
	}

	return runtime
}

// detectJava detects Java runtime.
func (c *Collector) detectJava() *types.LanguageRuntime {
	path, err := cmdexec.LookPath("java")
	if err != nil {
		return nil
	}

	runtime := &types.LanguageRuntime{
		Name: "java",
		Path: path,
	}

	// Get version
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command(path, "-version").CombinedOutput(); err == nil {
		// Output (stderr): 'openjdk version "17.0.8" 2023-07-18' or 'java version "1.8.0_381"'
		re := regexp.MustCompile(`(?:openjdk|java) version "([^"]+)"`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
			runtime.Version = matches[1]
		}
	}

	// Check for maven
	if mvnPath, err := cmdexec.LookPath("mvn"); err == nil {
		runtime.Manager = "maven"
		// #nosec G204 -- no user input
		if output, err := cmdexec.Command(mvnPath, "--version").Output(); err == nil {
			re := regexp.MustCompile(`Apache Maven ([\d.]+)`)
			if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
				runtime.ManagerVer = matches[1]
			}
		}
	} else if gradlePath, err := cmdexec.LookPath("gradle"); err == nil {
		runtime.Manager = "gradle"
		// #nosec G204 -- no user input
		if output, err := cmdexec.Command(gradlePath, "--version").Output(); err == nil {
			re := regexp.MustCompile(`Gradle ([\d.]+)`)
			if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
				runtime.ManagerVer = matches[1]
			}
		}
	}

	// Check JAVA_HOME
	if javaHome := os.Getenv("JAVA_HOME"); javaHome != "" {
		runtime.DefaultPkg = javaHome
	}

	// Check for SDKMAN
	if os.Getenv("SDKMAN_DIR") != "" {
		runtime.Environment = "sdkman"
	}

	return runtime
}

// detectPHP detects PHP runtime.
func (c *Collector) detectPHP() *types.LanguageRuntime {
	path, err := cmdexec.LookPath("php")
	if err != nil {
		return nil
	}

	runtime := &types.LanguageRuntime{
		Name: "php",
		Path: path,
	}

	// Get version
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command(path, "--version").Output(); err == nil {
		// Output: "PHP 8.2.7 (cli) (built: Jun  6 2023 21:28:56) (NTS)"
		re := regexp.MustCompile(`PHP\s+([\d.]+)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
			runtime.Version = matches[1]
		}
	}

	// Check for composer
	if composerPath, err := cmdexec.LookPath("composer"); err == nil {
		runtime.Manager = "composer"
		// #nosec G204 -- no user input
		if output, err := cmdexec.Command(composerPath, "--version").Output(); err == nil {
			re := regexp.MustCompile(`Composer version ([\d.]+)`)
			if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
				runtime.ManagerVer = matches[1]
			}
		}
	}

	return runtime
}

// detectRust detects Rust runtime.
func (c *Collector) detectRust() *types.LanguageRuntime {
	path, err := cmdexec.LookPath("rustc")
	if err != nil {
		return nil
	}

	runtime := &types.LanguageRuntime{
		Name: "rust",
		Path: path,
	}

	// Get version
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command(path, "--version").Output(); err == nil {
		// Output: "rustc 1.75.0 (82e1608df 2023-12-21)"
		re := regexp.MustCompile(`rustc\s+([\d.]+)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
			runtime.Version = matches[1]
		}
	}

	// Check for cargo
	if cargoPath, err := cmdexec.LookPath("cargo"); err == nil {
		runtime.Manager = "cargo"
		// #nosec G204 -- no user input
		if output, err := cmdexec.Command(cargoPath, "--version").Output(); err == nil {
			re := regexp.MustCompile(`cargo\s+([\d.]+)`)
			if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
				runtime.ManagerVer = matches[1]
			}
		}
	}

	// rustup environment
	if os.Getenv("RUSTUP_HOME") != "" {
		runtime.Environment = "rustup"
	}

	home, _ := os.UserHomeDir()
	runtime.DefaultPkg = filepath.Join(home, ".cargo", "registry")

	return runtime
}

// detectDotNet detects .NET runtime.
func (c *Collector) detectDotNet() *types.LanguageRuntime {
	path, err := cmdexec.LookPath("dotnet")
	if err != nil {
		return nil
	}

	runtime := &types.LanguageRuntime{
		Name:    "dotnet",
		Path:    path,
		Manager: "nuget",
	}

	// Get version
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command(path, "--version").Output(); err == nil {
		runtime.Version = strings.TrimSpace(string(output))
	}

	return runtime
}

// detectPerl detects Perl runtime.
func (c *Collector) detectPerl() *types.LanguageRuntime {
	path, err := cmdexec.LookPath("perl")
	if err != nil {
		return nil
	}

	runtime := &types.LanguageRuntime{
		Name: "perl",
		Path: path,
	}

	// Get version
	// #nosec G204 -- no user input
	if output, err := cmdexec.Command(path, "-v").Output(); err == nil {
		// Output contains: "This is perl 5, version 36, subversion 0 (v5.36.0)"
		re := regexp.MustCompile(`\(v([\d.]+)\)`)
		if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
			runtime.Version = matches[1]
		}
	}

	// Check for cpanm
	if cpanmPath, err := cmdexec.LookPath("cpanm"); err == nil {
		runtime.Manager = "cpanm"
		// #nosec G204 -- no user input
		if output, err := cmdexec.Command(cpanmPath, "--version").Output(); err == nil {
			re := regexp.MustCompile(`cpanm[^\d]+([\d.]+)`)
			if matches := re.FindStringSubmatch(string(output)); len(matches) >= 2 {
				runtime.ManagerVer = matches[1]
			}
		}
	}

	// Check for perlbrew
	if os.Getenv("PERLBREW_ROOT") != "" {
		runtime.Environment = "perlbrew"
	}

	return runtime
}
