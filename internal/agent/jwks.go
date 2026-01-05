package agent

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

// JWKSValidator validates JWTs using a cached JWKS from the SaaS.
type JWKSValidator struct {
	jwksURL  string
	audience string

	mu       sync.RWMutex
	keys     map[string]*rsa.PublicKey
	keysExp  time.Time
	cacheTTL time.Duration

	client *http.Client
}

// JWKSValidatorConfig configures the JWKS validator.
type JWKSValidatorConfig struct {
	JWKSURL  string        // URL to fetch JWKS from
	Audience string        // Expected audience claim (optional)
	CacheTTL time.Duration // How long to cache JWKS (default: 1 hour)
}

// TokenClaims contains validated JWT claims.
type TokenClaims struct {
	Subject   string   // sub claim
	Issuer    string   // iss claim
	Audience  []string // aud claim
	ExpiresAt time.Time
	IssuedAt  time.Time
	TenantID  string   // tenant_id custom claim (if present)
	Scopes    []string // Parsed scopes
}

// NewJWKSValidator creates a new JWKS-based JWT validator.
func NewJWKSValidator(config *JWKSValidatorConfig) *JWKSValidator {
	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = time.Hour
	}

	return &JWKSValidator{
		jwksURL:  config.JWKSURL,
		audience: config.Audience,
		keys:     make(map[string]*rsa.PublicKey),
		cacheTTL: cacheTTL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// ValidateToken implements mcp.JWKSValidatorInterface.
// Validates a JWT and returns subject and scopes for MCP authentication.
func (v *JWKSValidator) ValidateToken(ctx context.Context, tokenString string) (string, []string, error) {
	claims, err := v.ValidateTokenClaims(ctx, tokenString)
	if err != nil {
		return "", nil, err
	}
	return claims.Subject, claims.Scopes, nil
}

// ValidateTokenClaims validates a JWT and returns full claims.
func (v *JWKSValidator) ValidateTokenClaims(ctx context.Context, tokenString string) (*TokenClaims, error) {
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

	// Validate audience if configured
	if v.audience != "" {
		if !v.validateAudience(claims) {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	// Extract claims
	result := &TokenClaims{}

	if sub, ok := claims["sub"].(string); ok {
		result.Subject = sub
	}
	if iss, ok := claims["iss"].(string); ok {
		result.Issuer = iss
	}
	if exp, ok := claims["exp"].(float64); ok {
		result.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claims["iat"].(float64); ok {
		result.IssuedAt = time.Unix(int64(iat), 0)
	}
	if tid, ok := claims["tenant_id"].(string); ok {
		result.TenantID = tid
	}

	// Extract audience
	result.Audience = v.extractAudience(claims)

	// Extract scopes
	result.Scopes = v.extractScopes(claims)

	return result, nil
}

// validateAudience checks the audience claim.
func (v *JWKSValidator) validateAudience(claims jwt.MapClaims) bool {
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

// extractAudience extracts audience as a string slice.
func (v *JWKSValidator) extractAudience(claims jwt.MapClaims) []string {
	aud, ok := claims["aud"]
	if !ok {
		return nil
	}

	switch a := aud.(type) {
	case string:
		return []string{a}
	case []interface{}:
		result := make([]string, 0, len(a))
		for _, item := range a {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}

	return nil
}

// extractScopes extracts scopes from various claim formats.
func (v *JWKSValidator) extractScopes(claims jwt.MapClaims) []string {
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

	// Try "scopes" claim (array)
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
func (v *JWKSValidator) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
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

// fetchJWKS fetches the JSON Web Key Set from the SaaS.
func (v *JWKSValidator) fetchJWKS(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
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

// RefreshJWKS forces a refresh of the JWKS cache.
func (v *JWKSValidator) RefreshJWKS(ctx context.Context) error {
	return v.fetchJWKS(ctx)
}
