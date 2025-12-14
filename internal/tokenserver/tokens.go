package tokenserver

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenIssuer creates JWTs for authenticated clients.
type TokenIssuer struct {
	keyManager *KeyManager
	issuer     string
	audience   string
	defaultTTL time.Duration
	maxTTL     time.Duration
}

// TokenRequest represents a request for a new token.
type TokenRequest struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes,omitempty"`
	TTL      int      `json:"ttl,omitempty"` // seconds
}

// TokenResponse contains the issued token.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// JWTHeader represents the JWT header.
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// JWTClaims represents the JWT payload claims.
type JWTClaims struct {
	Iss       string   `json:"iss"`
	Sub       string   `json:"sub"`
	Aud       string   `json:"aud"`
	Exp       int64    `json:"exp"`
	Iat       int64    `json:"iat"`
	Jti       string   `json:"jti"`
	MCPScopes []string `json:"mcp_scopes,omitempty"`
}

// NewTokenIssuer creates a new token issuer.
func NewTokenIssuer(km *KeyManager, issuer, audience string, defaultTTL, maxTTL time.Duration) *TokenIssuer {
	return &TokenIssuer{
		keyManager: km,
		issuer:     issuer,
		audience:   audience,
		defaultTTL: defaultTTL,
		maxTTL:     maxTTL,
	}
}

// IssueToken creates a new JWT for the given client and scopes.
func (ti *TokenIssuer) IssueToken(clientID string, scopes []string, requestedTTL time.Duration) (*TokenResponse, error) {
	return ti.IssueTokenWithAudience(clientID, scopes, ti.audience, requestedTTL)
}

// IssueTokenWithAudience creates a new JWT with a custom audience (RFC 8707 resource indicator).
func (ti *TokenIssuer) IssueTokenWithAudience(clientID string, scopes []string, audience string, requestedTTL time.Duration) (*TokenResponse, error) {
	// Determine TTL
	ttl := ti.defaultTTL
	if requestedTTL > 0 {
		ttl = requestedTTL
	}
	if ttl > ti.maxTTL {
		ttl = ti.maxTTL
	}

	now := time.Now()
	exp := now.Add(ttl)

	// Generate unique JTI
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("failed to generate JTI: %w", err)
	}

	// Get signing key
	key, kid := ti.keyManager.GetCurrentKey()
	if key == nil {
		return nil, fmt.Errorf("no signing key available")
	}

	// Use provided audience or default
	if audience == "" {
		audience = ti.audience
	}

	// Build claims
	claims := JWTClaims{
		Iss:       ti.issuer,
		Sub:       clientID,
		Aud:       audience,
		Exp:       exp.Unix(),
		Iat:       now.Unix(),
		Jti:       jti,
		MCPScopes: scopes,
	}

	// Create JWT
	token, err := createJWT(key, kid, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT: %w", err)
	}

	// Build scope string
	scopeStr := ""
	for i, s := range scopes {
		if i > 0 {
			scopeStr += " "
		}
		scopeStr += s
	}

	return &TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
		Scope:       scopeStr,
	}, nil
}

// ValidateToken parses and validates a JWT, returning the claims if valid.
func (ti *TokenIssuer) ValidateToken(tokenStr string) (*JWTClaims, error) {
	// Split token into parts
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token header: %w", err)
	}

	var header JWTHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("invalid token header: %w", err)
	}

	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Decode payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}

	// Validate issuer
	if claims.Iss != ti.issuer {
		return nil, fmt.Errorf("invalid issuer: %s", claims.Iss)
	}

	// Validate expiration
	now := time.Now().Unix()
	if claims.Exp <= now {
		return nil, fmt.Errorf("token expired")
	}

	// Verify signature
	signingInput := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Get key by KID
	key, currentKID := ti.keyManager.GetCurrentKey()
	if header.Kid != currentKID {
		// Check previous key (for rotation grace period)
		jwks := ti.keyManager.GetJWKS()
		found := false
		for _, jwk := range jwks.Keys {
			if jwk.Kid == header.Kid {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown key ID: %s", header.Kid)
		}
		// For simplicity, we only validate with current key
		// A production implementation would look up the key by KID
	}

	// Verify RS256 signature
	hash := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], signature); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	return &claims, nil
}

// createJWT builds and signs a JWT.
func createJWT(key *rsa.PrivateKey, kid string, claims JWTClaims) (string, error) {
	// Header
	header := JWTHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: kid,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Payload
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// Signing input
	signingInput := headerB64 + "." + claimsB64

	// Sign with RS256
	hash := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

// generateJTI creates a unique token identifier.
func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
