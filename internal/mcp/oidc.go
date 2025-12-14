package mcp

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCValidator validates tokens against an OIDC provider.
type OIDCValidator struct {
	issuer   string
	audience string

	// JWKS cache
	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	keysExp  time.Time
	cacheTTL time.Duration

	// Discovery cache
	discoveryOnce sync.Once
	jwksURI       string
	discoveryErr  error

	client *http.Client
}

// OIDCConfig configures OIDC validation.
type OIDCValidatorConfig struct {
	// Issuer is the OIDC issuer URL (e.g., https://enterprise.okta.com)
	Issuer string

	// Audience is the expected audience claim (typically this server's client ID)
	Audience string

	// CacheTTL for JWKS (default: 1 hour)
	CacheTTL time.Duration
}

// NewOIDCValidator creates a new OIDC token validator.
func NewOIDCValidator(config *OIDCValidatorConfig) *OIDCValidator {
	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = time.Hour
	}

	return &OIDCValidator{
		issuer:   strings.TrimSuffix(config.Issuer, "/"),
		audience: config.Audience,
		keys:     make(map[string]*rsa.PublicKey),
		cacheTTL: cacheTTL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ValidateToken validates a JWT and returns the identity.
func (v *OIDCValidator) ValidateToken(ctx context.Context, tokenString string) (*Identity, error) {
	// Parse and validate the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure it's RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get the key ID
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("token missing kid header")
		}

		// Get the public key
		return v.getKey(ctx, kid)
	}, jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	// Validate audience
	if v.audience != "" {
		if !v.validateAudience(claims) {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	// Extract identity
	identity := &Identity{}

	if sub, ok := claims["sub"].(string); ok {
		identity.Subject = sub
	}

	if clientID, ok := claims["client_id"].(string); ok {
		identity.ClientID = clientID
	} else if azp, ok := claims["azp"].(string); ok {
		// Some providers use azp (authorized party) instead
		identity.ClientID = azp
	}

	// Extract scopes from various claim formats
	identity.Scopes = v.extractScopes(claims)

	return identity, nil
}

// validateAudience checks the audience claim.
func (v *OIDCValidator) validateAudience(claims jwt.MapClaims) bool {
	aud, ok := claims["aud"]
	if !ok {
		return false
	}

	switch a := aud.(type) {
	case string:
		return a == v.audience
	case []interface{}:
		for _, item := range a {
			if s, ok := item.(string); ok && s == v.audience {
				return true
			}
		}
	}

	return false
}

// extractScopes extracts scopes from various claim formats.
func (v *OIDCValidator) extractScopes(claims jwt.MapClaims) []string {
	// Try "scope" claim (space-separated string, OAuth 2.0 standard)
	if scope, ok := claims["scope"].(string); ok {
		return strings.Fields(scope)
	}

	// Try "scp" claim (array, used by Azure AD)
	if scp, ok := claims["scp"].([]interface{}); ok {
		scopes := make([]string, 0, len(scp))
		for _, s := range scp {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
		return scopes
	}

	// Try "scopes" claim (array, used by some providers)
	if scopes, ok := claims["scopes"].([]interface{}); ok {
		result := make([]string, 0, len(scopes))
		for _, s := range scopes {
			if str, ok := s.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}

	return nil
}

// getKey retrieves a public key by key ID, fetching JWKS if needed.
func (v *OIDCValidator) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	// Check cache first
	v.mu.RLock()
	key, ok := v.keys[kid]
	expired := time.Now().After(v.keysExp)
	v.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	// Fetch JWKS
	if err := v.fetchJWKS(ctx); err != nil {
		return nil, err
	}

	// Try again
	v.mu.RLock()
	key, ok = v.keys[kid]
	v.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("key %s not found in JWKS", kid)
	}

	return key, nil
}

// fetchJWKS fetches the JSON Web Key Set from the OIDC provider.
func (v *OIDCValidator) fetchJWKS(ctx context.Context) error {
	// Discover JWKS URI first
	if err := v.discover(ctx); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Parse keys
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}

		key, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue // Skip invalid keys
		}
		keys[k.Kid] = key
	}

	// Update cache
	v.mu.Lock()
	v.keys = keys
	v.keysExp = time.Now().Add(v.cacheTTL)
	v.mu.Unlock()

	return nil
}

// discover fetches the OIDC discovery document.
func (v *OIDCValidator) discover(ctx context.Context) error {
	v.discoveryOnce.Do(func() {
		discoveryURL := v.issuer + "/.well-known/openid-configuration"

		req, err := http.NewRequestWithContext(ctx, "GET", discoveryURL, nil)
		if err != nil {
			v.discoveryErr = fmt.Errorf("failed to create discovery request: %w", err)
			return
		}

		resp, err := v.client.Do(req)
		if err != nil {
			v.discoveryErr = fmt.Errorf("failed to fetch discovery document: %w", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			v.discoveryErr = fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
			return
		}

		var doc struct {
			Issuer  string `json:"issuer"`
			JWKSURI string `json:"jwks_uri"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			v.discoveryErr = fmt.Errorf("failed to decode discovery document: %w", err)
			return
		}

		// Validate issuer matches
		if strings.TrimSuffix(doc.Issuer, "/") != v.issuer {
			v.discoveryErr = fmt.Errorf("issuer mismatch: expected %s, got %s", v.issuer, doc.Issuer)
			return
		}

		v.jwksURI = doc.JWKSURI
	})

	return v.discoveryErr
}

// parseRSAPublicKey parses an RSA public key from base64url-encoded n and e.
func parseRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
