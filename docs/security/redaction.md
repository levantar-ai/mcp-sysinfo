# Output Redaction

MCP System Info supports automatic redaction of sensitive data in query output. Redaction is **opt-in** and disabled by default.

## Quick Start

Enable redaction when starting the server:

```bash
# Enable with default provider
mcp-sysinfo --redact

# Enable with GitGuardian provider
mcp-sysinfo --redact --redact-provider gitguardian

# Enable with GitGuardian API (requires API key)
GITGUARDIAN_API_KEY=your-key mcp-sysinfo --redact --redact-provider gitguardian
```

## How It Works

Redaction uses two complementary detection methods:

### 1. Field-Level Detection

Values are redacted when the field/variable name contains sensitive keywords:

| Category | Keywords |
|----------|----------|
| Passwords | `password`, `passwd`, `pwd`, `pass`, `passphrase` |
| Secrets | `secret`, `SECRET_KEY`, `API_SECRET`, `client_secret` |
| Tokens | `token`, `api_key`, `apikey`, `access_token`, `refresh_token`, `auth_token` |
| Keys | `private_key`, `ssl_key`, `keystore`, `truststore` |
| Auth | `auth`, `authorization`, `credential`, `credentials` |

### 2. Pattern-Based Detection

Values are redacted regardless of field name when they match sensitive patterns:

- Connection strings with embedded credentials (`postgres://user:pass@host`)
- AWS Access Key IDs (`AKIA*`, `ASIA*`, etc.)
- AWS Secret Access Keys
- JWT tokens
- Private key content (PEM format)
- GitHub tokens (`ghp_*`, `gho_*`, etc.)
- Slack tokens (`xoxb-*`, `xoxp-*`, etc.)
- Stripe keys (`sk_live_*`, `rk_live_*`)
- And many more...

## Providers

### Default Provider

The built-in provider uses local pattern matching. It's fast, requires no external dependencies, and works offline.

```bash
mcp-sysinfo --redact --redact-provider default
```

**Pros:**
- No external dependencies
- Fast (local regex matching)
- Works offline
- No API keys required

**Cons:**
- Pattern-based detection only
- May miss novel secret formats

### GitGuardian Provider

Integrates with [GitGuardian](https://www.gitguardian.com/) for enterprise-grade secret detection.

```bash
# Using ggshield CLI (if installed)
mcp-sysinfo --redact --redact-provider gitguardian

# Using GitGuardian API
GITGUARDIAN_API_KEY=your-api-key mcp-sysinfo --redact --redact-provider gitguardian
```

The GitGuardian provider tries detection methods in order:

1. **API Mode** - Uses GitGuardian's API for detection (requires `GITGUARDIAN_API_KEY`)
2. **CLI Mode** - Uses `ggshield` CLI if installed
3. **Pattern Mode** - Falls back to built-in GitGuardian-style patterns

**Pros:**
- 350+ secret detector types
- Continuously updated detection rules
- Validated against real-world leaks
- API provides additional context

**Cons:**
- Requires API key or ggshield CLI for full functionality
- API calls add latency
- May require internet access

#### Installing ggshield

```bash
# Using pip
pip install ggshield

# Using Homebrew (macOS)
brew install gitguardian/tap/ggshield

# Authenticate (optional, for full API access)
ggshield auth login
```

## Custom Providers

You can implement custom redaction providers by implementing the `Provider` interface:

```go
package myprovider

import "github.com/levantar-ai/mcp-sysinfo/internal/redact"

type MyProvider struct{}

func (p *MyProvider) Name() string {
    return "myprovider"
}

func (p *MyProvider) IsSensitiveField(fieldName string) bool {
    // Your logic here
    return false
}

func (p *MyProvider) IsSensitiveValue(value string) bool {
    // Your logic here
    return false
}

func (p *MyProvider) RedactValue(fieldName, value string) string {
    if p.IsSensitiveField(fieldName) || p.IsSensitiveValue(value) {
        return redact.RedactedPlaceholder
    }
    return value
}

func (p *MyProvider) RedactMap(m map[string]string) map[string]string {
    result := make(map[string]string, len(m))
    for k, v := range m {
        result[k] = p.RedactValue(k, v)
    }
    return result
}

func init() {
    redact.RegisterProvider(&MyProvider{})
}
```

Then import your provider package and use it:

```bash
mcp-sysinfo --redact --redact-provider myprovider
```

## Programmatic Usage

```go
package main

import "github.com/levantar-ai/mcp-sysinfo/internal/redact"

func main() {
    // Enable redaction with default provider
    redact.Enable("")

    // Or enable with specific provider
    redact.Enable("gitguardian")

    // Or configure with full options
    redact.Configure(redact.Config{
        Enabled:      true,
        ProviderName: "default",
    })

    // Use redaction functions
    value := redact.RedactValue("PASSWORD", "secret123")  // Returns "[REDACTED]"
    value = redact.RedactValue("hostname", "server1")     // Returns "server1"

    // Redact a map
    env := map[string]string{
        "PATH":     "/usr/bin",
        "PASSWORD": "secret",
    }
    redactedEnv := redact.RedactMap(env)

    // Check if enabled
    if redact.IsEnabled() {
        // ...
    }

    // Disable
    redact.Disable()
}
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GITGUARDIAN_API_KEY` | API key for GitGuardian provider API mode |

## CLI Flags

| Flag | Description |
|------|-------------|
| `--redact` | Enable output redaction |
| `--redact-provider` | Provider to use: `default`, `gitguardian` |

## Security Considerations

1. **Redaction is not encryption** - Redacted values are replaced with `[REDACTED]`. The original data is not recoverable.

2. **Pattern-based detection has limits** - Novel or custom secret formats may not be detected. Consider using GitGuardian for comprehensive detection.

3. **Performance impact** - Pattern matching adds some overhead. GitGuardian API calls add network latency. For high-volume scenarios, consider caching strategies.

4. **False positives** - Some non-sensitive values may be redacted if they match patterns (e.g., long hex strings). This is intentional for security.

5. **Defense in depth** - Redaction is one layer of protection. Also use:
   - Network segmentation
   - Authentication and authorization
   - Audit logging
   - Principle of least privilege

## Comparison with Other Tools

| Feature | MCP Redaction | GitGuardian ggshield | AWS Secrets Manager |
|---------|--------------|---------------------|---------------------|
| Local pattern matching | ✅ | ✅ | ❌ |
| API-based detection | ✅ (with GG) | ✅ | N/A |
| Pre-commit hooks | ❌ | ✅ | ❌ |
| CI/CD integration | ❌ | ✅ | ❌ |
| Real-time output filtering | ✅ | ❌ | ❌ |
| Custom patterns | ✅ | ✅ | N/A |
| No external dependencies | ✅ (default) | ❌ | ❌ |
