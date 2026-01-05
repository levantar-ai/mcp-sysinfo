package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// RegistrationConfig contains configuration for SaaS registration.
type RegistrationConfig struct {
	SaaSURL     string // Base URL of the SaaS (e.g., https://api.example.com)
	APIKey      string // API key for authentication
	CallbackURL string // URL where SaaS can reach this agent
	PublicCert  string // PEM-encoded public certificate
}

// RegistrationResult contains the result of a successful registration.
type RegistrationResult struct {
	AgentID     string `json:"agent_id"`
	JWKSURL     string `json:"jwks_url"`
	RefreshSecs int    `json:"refresh_seconds,omitempty"` // How often to re-register (0 = never)
}

// RegistrationState persists registration state to disk.
type RegistrationState struct {
	AgentID      string    `json:"agent_id"`
	JWKSURL      string    `json:"jwks_url"`
	RegisteredAt time.Time `json:"registered_at"`
	CertHash     string    `json:"cert_hash"` // To detect cert changes
}

// Registrar handles agent registration with a SaaS backend.
type Registrar struct {
	config    *RegistrationConfig
	configDir string
	client    *http.Client
}

// NewRegistrar creates a new SaaS registrar.
func NewRegistrar(config *RegistrationConfig, configDir string) *Registrar {
	if configDir == "" {
		home, _ := os.UserHomeDir()
		configDir = filepath.Join(home, ".mcp-sysinfo")
	}

	return &Registrar{
		config:    config,
		configDir: configDir,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Register registers the agent with the SaaS backend.
// If already registered with the same cert, returns cached state.
func (r *Registrar) Register(ctx context.Context) (*RegistrationResult, error) {
	// Check for existing registration
	state, err := r.loadState()
	if err == nil && state.AgentID != "" {
		// Already registered - check if cert changed
		certHash := hashCert(r.config.PublicCert)
		if state.CertHash == certHash {
			return &RegistrationResult{
				AgentID: state.AgentID,
				JWKSURL: state.JWKSURL,
			}, nil
		}
		// Cert changed, need to re-register
	}

	// Build registration request
	reqBody := map[string]string{
		"callback_url": r.config.CallbackURL,
		"public_cert":  r.config.PublicCert,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create request
	url := r.config.SaaSURL + "/v1/agents/register"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.config.APIKey)
	req.Header.Set("User-Agent", "mcp-sysinfo-agent/1.0")

	// Send request
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check status
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed: %s - %s", resp.Status, string(respBody))
	}

	// Parse response
	var result RegistrationResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Save state
	state = &RegistrationState{
		AgentID:      result.AgentID,
		JWKSURL:      result.JWKSURL,
		RegisteredAt: time.Now(),
		CertHash:     hashCert(r.config.PublicCert),
	}
	if err := r.saveState(state); err != nil {
		// Log but don't fail - registration succeeded
		fmt.Fprintf(os.Stderr, "Warning: failed to save registration state: %v\n", err)
	}

	return &result, nil
}

// loadState loads the registration state from disk.
func (r *Registrar) loadState() (*RegistrationState, error) {
	path := filepath.Join(r.configDir, "registration.json")
	// #nosec G304 -- path is constructed from configDir which is trusted
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var state RegistrationState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}

	return &state, nil
}

// saveState saves the registration state to disk.
func (r *Registrar) saveState(state *RegistrationState) error {
	path := filepath.Join(r.configDir, "registration.json")
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// hashCert creates a simple hash of the certificate for change detection.
func hashCert(cert string) string {
	// Simple hash - just use first 32 chars of cert content (after header)
	// This is just for change detection, not security
	if len(cert) > 100 {
		return cert[28:60] // Skip "-----BEGIN CERTIFICATE-----\n"
	}
	return cert
}

// Deregister removes the agent registration from the SaaS.
func (r *Registrar) Deregister(ctx context.Context) error {
	state, err := r.loadState()
	if err != nil {
		return nil // Not registered, nothing to do
	}

	// Build deregistration request
	url := r.config.SaaSURL + "/v1/agents/" + state.AgentID
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+r.config.APIKey)
	req.Header.Set("User-Agent", "mcp-sysinfo-agent/1.0")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("deregistration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deregistration failed: %s - %s", resp.Status, string(body))
	}

	// Remove local state
	statePath := filepath.Join(r.configDir, "registration.json")
	_ = os.Remove(statePath)

	return nil
}
