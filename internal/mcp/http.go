package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/levantar-ai/mcp-sysinfo/internal/audit"
	"github.com/levantar-ai/mcp-sysinfo/internal/metrics"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const identityKey contextKey = "identity"

// HTTPConfig configures the HTTP transport.
type HTTPConfig struct {
	// ListenAddr is the address to listen on
	ListenAddr string

	// ServerURL is the public URL of this server (for metadata)
	ServerURL string

	// TLSCert and TLSKey for HTTPS
	TLSCert string
	TLSKey  string

	// Auth configuration (nil = no auth) - uses token introspection
	Auth *OAuthConfig

	// OIDC configuration (nil = no OIDC) - uses local JWT validation
	// If both Auth and OIDC are set, OIDC takes precedence
	OIDC *OIDCConfig
}

// OIDCConfig configures OIDC authentication with local JWT validation.
type OIDCConfig struct {
	// Issuer is the OIDC issuer URL (e.g., https://enterprise.okta.com)
	Issuer string

	// Audience is the expected audience claim
	Audience string

	// RequiredScopes that must be present in tokens
	RequiredScopes []string
}

// OAuthConfig configures OAuth 2.1 authentication.
type OAuthConfig struct {
	// AuthServerURL is the OAuth authorization server URL
	AuthServerURL string

	// ClientID and ClientSecret for token introspection
	ClientID     string
	ClientSecret string

	// IntrospectionEndpoint (if different from discovery)
	IntrospectionEndpoint string

	// RequiredScopes that must be present in tokens
	RequiredScopes []string

	// ResourceServerURL is this server's URL (for audience validation)
	ResourceServerURL string
}

// HTTPServer wraps an MCP server with HTTP transport.
type HTTPServer struct {
	mcpServer     *Server
	config        *HTTPConfig
	httpServer    *http.Server
	oidcValidator *OIDCValidator
}

// NewHTTPServer creates an HTTP transport for the MCP server.
func NewHTTPServer(mcpServer *Server, config *HTTPConfig) *HTTPServer {
	h := &HTTPServer{
		mcpServer: mcpServer,
		config:    config,
	}

	// Initialize OIDC validator if configured
	if config.OIDC != nil {
		h.oidcValidator = NewOIDCValidator(&OIDCValidatorConfig{
			Issuer:   config.OIDC.Issuer,
			Audience: config.OIDC.Audience,
		})
	}

	return h
}

// Start begins serving HTTP requests.
func (h *HTTPServer) Start() error {
	mux := http.NewServeMux()

	// MCP endpoint (JSON-RPC over HTTP POST)
	mux.HandleFunc("/", h.handleMCP)

	// OAuth Protected Resource Metadata (RFC 9728)
	mux.HandleFunc("/.well-known/oauth-protected-resource", h.handleProtectedResourceMetadata)

	// Health check
	mux.HandleFunc("/health", h.handleHealth)

	// Prometheus metrics endpoint
	mux.Handle("/metrics", metrics.Handler())

	// Set server info metric
	authMethod := "none"
	if h.config.OIDC != nil {
		authMethod = "oidc"
	} else if h.config.Auth != nil {
		authMethod = "oauth-introspection"
	}
	metrics.SetServerInfo("1.0.0", "http", authMethod)

	handler := h.withMetrics(h.withLogging(h.withCORS(mux)))

	h.httpServer = &http.Server{
		Addr:         h.config.ListenAddr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("MCP HTTP Server starting on %s", h.config.ListenAddr)
	log.Printf("  Server URL: %s", h.config.ServerURL)
	if h.config.OIDC != nil {
		log.Printf("  Auth:       OIDC (local JWT validation)")
		log.Printf("  Issuer:     %s", h.config.OIDC.Issuer)
		log.Printf("  Audience:   %s", h.config.OIDC.Audience)
	} else if h.config.Auth != nil {
		log.Printf("  Auth:       OAuth 2.1 (introspection)")
		log.Printf("  Auth Server: %s", h.config.Auth.AuthServerURL)
	} else {
		log.Printf("  Auth:       none (development only)")
	}

	if h.config.TLSCert != "" && h.config.TLSKey != "" {
		return h.httpServer.ListenAndServeTLS(h.config.TLSCert, h.config.TLSKey)
	}

	return h.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (h *HTTPServer) Shutdown(ctx context.Context) error {
	return h.httpServer.Shutdown(ctx)
}

// handleMCP processes MCP JSON-RPC requests.
func (h *HTTPServer) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get client IP for audit logging
	clientIP := h.getClientIP(r)
	ctx := context.WithValue(r.Context(), ContextKeyClientIP, clientIP)

	// Authenticate if auth is configured (OIDC or OAuth introspection)
	if h.config.OIDC != nil || h.config.Auth != nil {
		identity, err := h.authenticate(r)
		if err != nil {
			// Audit authentication failure
			h.auditAuth("token_validation", "", clientIP, audit.ResultDenied, map[string]interface{}{
				"error": err.Error(),
			})
			metrics.RecordAuth("failure")
			h.sendAuthChallenge(w, err)
			return
		}
		// Store identity in context for scope checking and audit
		ctx = context.WithValue(ctx, identityKey, identity)
		ctx = context.WithValue(ctx, ContextKeyIdentity, identity.Subject)

		// Audit successful authentication
		h.auditAuth("token_validation", identity.Subject, clientIP, audit.ResultSuccess, map[string]interface{}{
			"client_id": identity.ClientID,
			"scopes":    identity.Scopes,
		})
		metrics.RecordAuth("success")
	}

	r = r.WithContext(ctx)

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "Failed to read request body")
		return
	}

	// Process the MCP message
	response := h.mcpServer.handleMessage(r.Context(), body)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if response != nil {
		_ = json.NewEncoder(w).Encode(response)
	}
}

// getClientIP extracts the client IP address from the request.
func (h *HTTPServer) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (common for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// auditAuth logs an authentication event.
func (h *HTTPServer) auditAuth(action, identity, clientIP string, result audit.EventResult, metadata map[string]interface{}) {
	_ = audit.LogAuth(action, identity, clientIP, result, metadata)
}

// Identity represents an authenticated user/client.
type Identity struct {
	Subject  string
	ClientID string
	Scopes   []string
}

// authenticate validates the token using OIDC or OAuth introspection.
func (h *HTTPServer) authenticate(r *http.Request) (*Identity, error) {
	// Extract Bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, fmt.Errorf("invalid Authorization header format")
	}

	token := parts[1]

	// Use OIDC if configured, otherwise fall back to introspection
	if h.oidcValidator != nil {
		identity, err := h.oidcValidator.ValidateToken(r.Context(), token)
		if err != nil {
			return nil, err
		}

		// Check required scopes
		for _, required := range h.config.OIDC.RequiredScopes {
			found := false
			for _, s := range identity.Scopes {
				if s == required {
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("missing required scope: %s", required)
			}
		}

		return identity, nil
	}

	// Fall back to token introspection
	return h.introspectToken(token)
}

// introspectToken calls the authorization server's introspection endpoint.
func (h *HTTPServer) introspectToken(token string) (*Identity, error) {
	endpoint := h.config.Auth.IntrospectionEndpoint
	if endpoint == "" {
		// Try to discover from auth server
		endpoint = strings.TrimSuffix(h.config.Auth.AuthServerURL, "/") + "/introspect"
	}

	// Build introspection request
	data := url.Values{}
	data.Set("token", token)

	req, err := http.NewRequest("POST", endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(h.config.Auth.ClientID, h.config.Auth.ClientSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("introspection returned status %d", resp.StatusCode)
	}

	var result struct {
		Active    bool        `json:"active"`
		Sub       string      `json:"sub"`
		ClientID  string      `json:"client_id"`
		Scope     string      `json:"scope"`
		MCPScopes []string    `json:"mcp_scopes"`
		Aud       interface{} `json:"aud"` // Can be string or []string
		Exp       int64       `json:"exp"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode introspection response: %w", err)
	}

	if !result.Active {
		return nil, fmt.Errorf("token is not active")
	}

	// Validate audience
	if h.config.Auth.ResourceServerURL != "" {
		if !h.validateAudience(result.Aud, h.config.Auth.ResourceServerURL) {
			return nil, fmt.Errorf("invalid token audience")
		}
	}

	// Parse scopes
	scopes := result.MCPScopes
	if len(scopes) == 0 && result.Scope != "" {
		scopes = strings.Fields(result.Scope)
	}

	// Check required scopes
	for _, required := range h.config.Auth.RequiredScopes {
		found := false
		for _, s := range scopes {
			if s == required {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("missing required scope: %s", required)
		}
	}

	return &Identity{
		Subject:  result.Sub,
		ClientID: result.ClientID,
		Scopes:   scopes,
	}, nil
}

// validateAudience checks if the token audience matches our server.
func (h *HTTPServer) validateAudience(aud interface{}, expected string) bool {
	expected = strings.TrimSuffix(expected, "/")

	switch v := aud.(type) {
	case string:
		return strings.TrimSuffix(v, "/") == expected
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok {
				if strings.TrimSuffix(s, "/") == expected {
					return true
				}
			}
		}
	}
	return false
}

// sendAuthChallenge sends a 401 with WWW-Authenticate header.
func (h *HTTPServer) sendAuthChallenge(w http.ResponseWriter, err error) {
	metadataURL := h.config.ServerURL + "/.well-known/oauth-protected-resource"

	w.Header().Set("WWW-Authenticate", fmt.Sprintf(
		`Bearer realm="mcp-sysinfo", resource_metadata="%s"`,
		metadataURL,
	))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "unauthorized",
		"error_description": err.Error(),
	})
}

// handleProtectedResourceMetadata serves RFC 9728 metadata.
func (h *HTTPServer) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := map[string]interface{}{
		"resource": h.config.ServerURL,
		"scopes_supported": []string{
			"mcp:tools",
			"core",
			"logs",
			"hooks",
			"sbom",
			"sensitive",
		},
		"resource_name":        "MCP System Info Server",
		"resource_description": "Read-only AI diagnostics plane for secure incident triage",
	}

	// Include authorization server info based on auth method
	if h.config.OIDC != nil {
		metadata["authorization_servers"] = []string{h.config.OIDC.Issuer}
	} else if h.config.Auth != nil {
		metadata["authorization_servers"] = []string{h.config.Auth.AuthServerURL}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(metadata)
}

// handleHealth returns server health.
func (h *HTTPServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	authMethod := "none"
	if h.config.OIDC != nil {
		authMethod = "oidc"
	} else if h.config.Auth != nil {
		authMethod = "oauth-introspection"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "healthy",
		"transport":   "http",
		"auth_method": authMethod,
	})
}

// sendError sends a JSON error response.
func (h *HTTPServer) sendError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message,
	})
}

// withMetrics wraps a handler with Prometheus metrics recording.
func (h *HTTPServer) withMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip metrics for the metrics endpoint itself
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start)

		metrics.RecordRequest(r.Method, r.URL.Path, strconv.Itoa(wrapped.status), duration)
	})
}

// withLogging wraps a handler with request logging.
func (h *HTTPServer) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(wrapped, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, wrapped.status, time.Since(start))
	})
}

// withCORS adds CORS headers.
func (h *HTTPServer) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}
