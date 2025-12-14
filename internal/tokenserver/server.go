package tokenserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Server is the OAuth 2.1 Authorization Server for MCP.
type Server struct {
	config       *Config
	keyManager   *KeyManager
	tokenIssuer  *TokenIssuer
	clientStore  *ClientStore
	httpServer   *http.Server
	rotationDone chan struct{}
}

// NewServer creates a new authorization server.
func NewServer(cfg *Config) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// Initialize key manager
	km, err := NewKeyManager(cfg.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	// Initialize client store
	cs, err := NewClientStore(cfg.ClientsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client store: %w", err)
	}

	// Initialize token issuer
	ti := NewTokenIssuer(km, cfg.Issuer, cfg.Audience, cfg.GetDefaultTTL(), cfg.GetMaxTTL())

	s := &Server{
		config:       cfg,
		keyManager:   km,
		tokenIssuer:  ti,
		clientStore:  cs,
		rotationDone: make(chan struct{}),
	}

	// Set up HTTP routes
	mux := http.NewServeMux()

	// OAuth 2.1 / OIDC Discovery endpoints
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.handleAuthServerMetadata)
	mux.HandleFunc("/.well-known/openid-configuration", s.handleAuthServerMetadata)
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)

	// OAuth 2.1 endpoints
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/introspect", s.handleIntrospect)

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.withLogging(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s, nil
}

// Start begins serving requests.
func (s *Server) Start() error {
	// Start key rotation goroutine
	if s.config.KeyRotationHours > 0 {
		go s.rotateKeys()
	}

	log.Printf("OAuth Authorization Server starting on %s", s.config.ListenAddr)
	log.Printf("  Issuer:       %s", s.config.Issuer)
	log.Printf("  Audience:     %s", s.config.Audience)
	log.Printf("  Metadata:     %s/.well-known/oauth-authorization-server", s.config.Issuer)
	log.Printf("  JWKS:         %s/.well-known/jwks.json", s.config.Issuer)
	log.Printf("  Token:        %s/token", s.config.Issuer)
	log.Printf("  Introspect:   %s/introspect", s.config.Issuer)

	if s.config.IsTLSEnabled() {
		log.Printf("  TLS:          enabled")
		return s.httpServer.ListenAndServeTLS(s.config.TLSCert, s.config.TLSKey)
	}

	log.Printf("  TLS:          disabled (use only for development)")
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	close(s.rotationDone)
	return s.httpServer.Shutdown(ctx)
}

// rotateKeys periodically rotates signing keys.
func (s *Server) rotateKeys() {
	ticker := time.NewTicker(time.Duration(s.config.KeyRotationHours) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.keyManager.RotateKey(); err != nil {
				log.Printf("ERROR: key rotation failed: %v", err)
			} else {
				log.Printf("Key rotated successfully")
			}
		case <-s.rotationDone:
			return
		}
	}
}

// withLogging wraps a handler with request logging.
func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(wrapped, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, wrapped.status, time.Since(start))
	})
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleAuthServerMetadata serves OAuth 2.1 Authorization Server Metadata (RFC 8414).
func (s *Server) handleAuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := map[string]interface{}{
		"issuer":                 s.config.Issuer,
		"token_endpoint":         s.config.Issuer + "/token",
		"introspection_endpoint": s.config.Issuer + "/introspect",
		"jwks_uri":               s.config.Issuer + "/.well-known/jwks.json",

		// Supported features
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
		"grant_types_supported": []string{
			"client_credentials",
		},
		"response_types_supported": []string{
			"token",
		},
		"scopes_supported": []string{
			"mcp:tools",
			"mcp:resources",
			"mcp:prompts",
			"core",
			"logs",
			"hooks",
			"sbom",
			"sensitive",
		},
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},

		// Algorithm support
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(metadata)
}

// handleJWKS serves the JSON Web Key Set.
func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jwks := s.keyManager.GetJWKS()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(jwks)
}

// handleToken processes OAuth 2.1 token requests (client credentials flow).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse client credentials from Basic auth or body
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		// Try form data
		if err := r.ParseForm(); err == nil {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}
	}

	if clientID == "" || clientSecret == "" {
		s.oauthError(w, "invalid_client", "Missing client credentials", http.StatusUnauthorized)
		return
	}

	// Verify grant type
	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		s.oauthError(w, "unsupported_grant_type", "Only client_credentials grant is supported", http.StatusBadRequest)
		return
	}

	// Authenticate client
	client, err := s.clientStore.Authenticate(clientID, clientSecret)
	if err != nil {
		log.Printf("Authentication failed for client %s: %v", clientID, err)
		s.oauthError(w, "invalid_client", "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Parse requested scopes
	var requestedScopes []string
	if scopeParam := r.FormValue("scope"); scopeParam != "" {
		requestedScopes = strings.Fields(scopeParam)
	}

	// Filter to allowed scopes
	scopes := s.clientStore.FilterScopes(client, requestedScopes)
	if len(scopes) == 0 {
		s.oauthError(w, "invalid_scope", "No valid scopes requested", http.StatusBadRequest)
		return
	}

	// Get resource/audience from request (RFC 8707)
	audience := r.FormValue("resource")
	if audience == "" {
		audience = s.config.Audience // Default audience
	}

	// Issue token
	resp, err := s.tokenIssuer.IssueTokenWithAudience(clientID, scopes, audience, 0)
	if err != nil {
		log.Printf("Token issuance failed: %v", err)
		s.oauthError(w, "server_error", "Token issuance failed", http.StatusInternalServerError)
		return
	}

	log.Printf("Token issued for client %s with scopes: %v, audience: %s", clientID, scopes, audience)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleIntrospect handles OAuth 2.1 token introspection (RFC 7662).
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate the client making the introspection request
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		if err := r.ParseForm(); err == nil {
			clientID = r.FormValue("client_id")
			clientSecret = r.FormValue("client_secret")
		}
	}

	if clientID == "" || clientSecret == "" {
		s.oauthError(w, "invalid_client", "Client authentication required", http.StatusUnauthorized)
		return
	}

	_, err := s.clientStore.Authenticate(clientID, clientSecret)
	if err != nil {
		s.oauthError(w, "invalid_client", "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Get the token to introspect
	token := r.FormValue("token")
	if token == "" {
		// Return inactive for missing token (per RFC 7662)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
		return
	}

	// Validate the token
	claims, err := s.tokenIssuer.ValidateToken(token)
	if err != nil {
		// Token is invalid/expired - return inactive
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
		return
	}

	// Build introspection response
	response := map[string]interface{}{
		"active":     true,
		"scope":      strings.Join(claims.MCPScopes, " "),
		"client_id":  claims.Sub,
		"sub":        claims.Sub,
		"aud":        claims.Aud,
		"iss":        claims.Iss,
		"exp":        claims.Exp,
		"iat":        claims.Iat,
		"token_type": "Bearer",
	}

	// Include MCP scopes as array too for convenience
	response["mcp_scopes"] = claims.MCPScopes

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// handleHealth returns server health status.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	_, kid := s.keyManager.GetCurrentKey()
	resp := map[string]interface{}{
		"status":      "healthy",
		"current_kid": kid,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// oauthError sends an OAuth 2.1 error response.
func (s *Server) oauthError(w http.ResponseWriter, errCode, errDesc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	})
}

// GetClientStore returns the client store for CLI management.
func (s *Server) GetClientStore() *ClientStore {
	return s.clientStore
}

// GetKeyManager returns the key manager for CLI operations.
func (s *Server) GetKeyManager() *KeyManager {
	return s.keyManager
}
