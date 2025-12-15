package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// GitGuardianProvider implements the Provider interface using GitGuardian's
// secret detection capabilities. It supports two modes:
//
//  1. API Mode: Uses GitGuardian's API for detection (requires API key)
//  2. CLI Mode: Uses ggshield CLI tool if installed
//  3. Fallback Mode: Uses built-in patterns based on GitGuardian's public detector list
//
// The provider automatically selects the best available mode.
type GitGuardianProvider struct {
	// APIKey is the GitGuardian API key for API mode.
	// Can also be set via GITGUARDIAN_API_KEY environment variable.
	APIKey string

	// APIEndpoint is the GitGuardian API endpoint.
	// Defaults to https://api.gitguardian.com
	APIEndpoint string

	// UseAPI enables API mode when an API key is available.
	UseAPI bool

	// UseCLI enables CLI mode using ggshield.
	UseCLI bool

	// Timeout for API/CLI calls.
	Timeout time.Duration

	// cache stores recent scan results to avoid repeated API calls
	cache     map[string]bool
	cacheMu   sync.RWMutex
	cacheSize int

	// ggshieldPath caches the path to ggshield binary
	ggshieldPath string
	ggshieldOnce sync.Once

	// compiledPatterns caches GitGuardian-style patterns
	compiledPatterns []*regexp.Regexp
	patternsOnce     sync.Once
}

// GitGuardian detector patterns based on their public documentation.
// These are used in fallback mode when API/CLI are unavailable.
var gitguardianPatterns = []string{
	// AWS
	`(?i)aws[_\-\.]?access[_\-\.]?key[_\-\.]?id\s*[:=]\s*["']?([A-Z0-9]{20})["']?`,
	`(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`,
	`AKIA[0-9A-Z]{16}`,
	`ASIA[0-9A-Z]{16}`,

	// GitHub
	`ghp_[a-zA-Z0-9]{36,}`,
	`gho_[a-zA-Z0-9]{36,}`,
	`ghu_[a-zA-Z0-9]{36,}`,
	`ghs_[a-zA-Z0-9]{36,}`,
	`ghr_[a-zA-Z0-9]{36,}`,
	`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`,

	// GitLab
	`glpat-[a-zA-Z0-9\-_]{20,}`,
	`glptt-[a-zA-Z0-9]{40}`,

	// Slack
	`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
	`xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}`,

	// Stripe
	`sk_live_[0-9a-zA-Z]{24,}`,
	`rk_live_[0-9a-zA-Z]{24,}`,
	`pk_live_[0-9a-zA-Z]{24,}`,

	// Google
	`AIza[0-9A-Za-z\-_]{35}`,
	`ya29\.[0-9A-Za-z\-_]+`,

	// Twilio
	`SK[a-f0-9]{32}`,
	`AC[a-f0-9]{32}`,

	// SendGrid
	`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`,

	// Mailchimp
	`[a-f0-9]{32}-us[0-9]{1,2}`,

	// NPM
	`npm_[a-zA-Z0-9]{36}`,

	// PyPI
	`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`,

	// Shopify
	`shpat_[a-fA-F0-9]{32}`,
	`shpca_[a-fA-F0-9]{32}`,
	`shppa_[a-fA-F0-9]{32}`,

	// Heroku
	`[hH]eroku.*[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`,

	// DigitalOcean
	`dop_v1_[a-f0-9]{64}`,
	`doo_v1_[a-f0-9]{64}`,

	// Discord
	`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`,

	// Private keys
	`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----`,
	`-----BEGIN CERTIFICATE-----`,

	// JWT tokens
	`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`,

	// Generic high entropy (potential secrets)
	`(?i)(api[_-]?key|apikey|secret|password|passwd|token|auth)[_\-\.]?\s*[:=]\s*["']?[A-Za-z0-9/+=_\-]{16,}["']?`,

	// Database connection strings
	`(?i)(mysql|postgres|postgresql|mongodb|redis|amqp|rabbitmq)://[^:]+:[^@]+@`,

	// Azure
	`(?i)azure[_\-\.]?storage[_\-\.]?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{86,}["']?`,

	// HashiCorp Vault
	`hvs\.[a-zA-Z0-9_-]{24,}`,
	`hvb\.[a-zA-Z0-9_-]{24,}`,
}

// NewGitGuardianProvider creates a new GitGuardianProvider with default settings.
func NewGitGuardianProvider() *GitGuardianProvider {
	return &GitGuardianProvider{
		APIEndpoint: "https://api.gitguardian.com",
		UseAPI:      true,
		UseCLI:      true,
		Timeout:     5 * time.Second,
		cache:       make(map[string]bool),
		cacheSize:   1000,
	}
}

// NewGitGuardianProviderWithAPIKey creates a provider configured with an API key.
func NewGitGuardianProviderWithAPIKey(apiKey string) *GitGuardianProvider {
	p := NewGitGuardianProvider()
	p.APIKey = apiKey
	return p
}

// Name returns the provider identifier.
func (p *GitGuardianProvider) Name() string {
	return "gitguardian"
}

// IsSensitiveField checks if a field name indicates sensitive content.
// GitGuardian focuses on value patterns, so this delegates to DefaultProvider's logic.
func (p *GitGuardianProvider) IsSensitiveField(fieldName string) bool {
	// Use the same field-level detection as DefaultProvider
	upper := strings.ToUpper(fieldName)
	for _, keyword := range sensitiveFieldKeywords {
		if strings.Contains(upper, strings.ToUpper(keyword)) {
			return true
		}
	}
	return false
}

// IsSensitiveValue checks if a value matches GitGuardian's secret patterns.
func (p *GitGuardianProvider) IsSensitiveValue(value string) bool {
	// Skip empty or very short values
	if len(value) < 8 {
		return false
	}

	// Check cache first
	p.cacheMu.RLock()
	if cached, ok := p.cache[value]; ok {
		p.cacheMu.RUnlock()
		return cached
	}
	p.cacheMu.RUnlock()

	// Try detection methods in order of preference
	var isSensitive bool

	// 1. Try API if configured
	if p.UseAPI && p.getAPIKey() != "" {
		if result, err := p.scanWithAPI(value); err == nil {
			isSensitive = result
			p.cacheResult(value, isSensitive)
			return isSensitive
		}
	}

	// 2. Try CLI if available
	if p.UseCLI && p.hasGGShield() {
		if result, err := p.scanWithCLI(value); err == nil {
			isSensitive = result
			p.cacheResult(value, isSensitive)
			return isSensitive
		}
	}

	// 3. Fall back to pattern matching
	isSensitive = p.scanWithPatterns(value)
	p.cacheResult(value, isSensitive)
	return isSensitive
}

// RedactValue redacts a value if it's detected as sensitive.
func (p *GitGuardianProvider) RedactValue(fieldName, value string) string {
	if p.IsSensitiveField(fieldName) || p.IsSensitiveValue(value) {
		return RedactedPlaceholder
	}
	return value
}

// RedactMap redacts sensitive values in a map.
func (p *GitGuardianProvider) RedactMap(m map[string]string) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = p.RedactValue(k, v)
	}
	return result
}

// getAPIKey returns the API key from config or environment.
func (p *GitGuardianProvider) getAPIKey() string {
	if p.APIKey != "" {
		return p.APIKey
	}
	return os.Getenv("GITGUARDIAN_API_KEY")
}

// hasGGShield checks if ggshield CLI is available.
func (p *GitGuardianProvider) hasGGShield() bool {
	p.ggshieldOnce.Do(func() {
		path, err := exec.LookPath("ggshield")
		if err == nil {
			p.ggshieldPath = path
		}
	})
	return p.ggshieldPath != ""
}

// scanWithAPI uses GitGuardian's API to scan for secrets.
func (p *GitGuardianProvider) scanWithAPI(value string) (bool, error) {
	apiKey := p.getAPIKey()
	if apiKey == "" {
		return false, fmt.Errorf("no API key configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	// GitGuardian scan endpoint
	url := p.APIEndpoint + "/v1/scan"

	payload := map[string]interface{}{
		"document": value,
		"filename": "scan.txt",
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonPayload))
	if err != nil {
		return false, err
	}

	req.Header.Set("Authorization", "Token "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: p.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("API error: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		PolicyBreakCount int `json:"policy_break_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return result.PolicyBreakCount > 0, nil
}

// scanWithCLI uses ggshield CLI to scan for secrets.
func (p *GitGuardianProvider) scanWithCLI(value string) (bool, error) {
	if p.ggshieldPath == "" {
		return false, fmt.Errorf("ggshield not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()

	// Create a temporary file for scanning
	tmpfile, err := os.CreateTemp("", "ggshield-scan-*.txt")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.WriteString(value); err != nil {
		_ = tmpfile.Close()
		return false, err
	}
	_ = tmpfile.Close()

	// Run ggshield scan
	// #nosec G204 -- ggshieldPath is validated via exec.LookPath, not user input
	cmd := exec.CommandContext(ctx, p.ggshieldPath, "secret", "scan", "path", tmpfile.Name(), "--json")
	output, err := cmd.Output()

	// ggshield returns non-zero exit code when secrets are found
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 1 means secrets were found
			if exitErr.ExitCode() == 1 {
				return true, nil
			}
		}
		// Other errors - fall back to pattern matching
		return false, err
	}

	// Parse JSON output
	var result struct {
		TotalIncidents int `json:"total_incidents"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		// If we can't parse, assume no secrets found
		return false, nil
	}

	return result.TotalIncidents > 0, nil
}

// scanWithPatterns uses built-in GitGuardian-style patterns.
func (p *GitGuardianProvider) scanWithPatterns(value string) bool {
	p.patternsOnce.Do(func() {
		for _, pattern := range gitguardianPatterns {
			if re, err := regexp.Compile(pattern); err == nil {
				p.compiledPatterns = append(p.compiledPatterns, re)
			}
		}
	})

	for _, re := range p.compiledPatterns {
		if re.MatchString(value) {
			return true
		}
	}

	return false
}

// cacheResult stores a scan result in the cache.
func (p *GitGuardianProvider) cacheResult(value string, isSensitive bool) {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()

	// Simple cache eviction when full
	if len(p.cache) >= p.cacheSize {
		// Clear half the cache
		count := 0
		for k := range p.cache {
			delete(p.cache, k)
			count++
			if count >= p.cacheSize/2 {
				break
			}
		}
	}

	p.cache[value] = isSensitive
}

// ClearCache clears the detection cache.
func (p *GitGuardianProvider) ClearCache() {
	p.cacheMu.Lock()
	defer p.cacheMu.Unlock()
	p.cache = make(map[string]bool)
}

// GetDetectionMode returns the current detection mode being used.
func (p *GitGuardianProvider) GetDetectionMode() string {
	if p.UseAPI && p.getAPIKey() != "" {
		return "api"
	}
	if p.UseCLI && p.hasGGShield() {
		return "cli"
	}
	return "patterns"
}

func init() {
	// Register GitGuardian provider
	RegisterProvider(NewGitGuardianProvider())
}
