// Package tokenserver provides a JWT token issuance server for MCP authentication.
package tokenserver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// KeyManager handles RSA key generation, storage, and rotation.
type KeyManager struct {
	mu          sync.RWMutex
	currentKey  *rsa.PrivateKey
	currentKID  string
	previousKey *rsa.PrivateKey
	previousKID string
	keyDir      string
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// NewKeyManager creates a new key manager.
func NewKeyManager(keyDir string) (*KeyManager, error) {
	km := &KeyManager{
		keyDir: keyDir,
	}

	if keyDir != "" {
		if err := os.MkdirAll(keyDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create key directory: %w", err)
		}

		// Try to load existing keys
		if err := km.loadKeys(); err == nil {
			return km, nil
		}
	}

	// Generate new key if none exists
	if err := km.generateKey(); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return km, nil
}

// generateKey creates a new RSA key pair.
func (km *KeyManager) generateKey() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	// Move current key to previous
	if km.currentKey != nil {
		km.previousKey = km.currentKey
		km.previousKID = km.currentKID
	}

	// Generate new 2048-bit RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	km.currentKey = key
	km.currentKID = generateKID(&key.PublicKey)

	// Persist if keyDir is set
	if km.keyDir != "" {
		if err := km.saveKeys(); err != nil {
			return fmt.Errorf("failed to save keys: %w", err)
		}
	}

	return nil
}

// generateKID creates a key ID from the public key.
func generateKID(pub *rsa.PublicKey) string {
	// Use SHA256 of the public key DER encoding
	der, _ := x509.MarshalPKIXPublicKey(pub)
	hash := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(hash[:8])
}

// GetCurrentKey returns the current signing key and its KID.
func (km *KeyManager) GetCurrentKey() (*rsa.PrivateKey, string) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.currentKey, km.currentKID
}

// GetJWKS returns the JSON Web Key Set containing public keys.
func (km *KeyManager) GetJWKS() *JWKS {
	km.mu.RLock()
	defer km.mu.RUnlock()

	jwks := &JWKS{Keys: make([]JWK, 0, 2)}

	if km.currentKey != nil {
		jwks.Keys = append(jwks.Keys, publicKeyToJWK(&km.currentKey.PublicKey, km.currentKID))
	}

	// Include previous key for rotation grace period
	if km.previousKey != nil {
		jwks.Keys = append(jwks.Keys, publicKeyToJWK(&km.previousKey.PublicKey, km.previousKID))
	}

	return jwks
}

// publicKeyToJWK converts an RSA public key to JWK format.
func publicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// RotateKey generates a new key, moving the current to previous.
func (km *KeyManager) RotateKey() error {
	return km.generateKey()
}

// saveKeys persists keys to disk.
func (km *KeyManager) saveKeys() error {
	// Save current key
	currentPath := filepath.Join(km.keyDir, "current.pem")
	if err := savePrivateKey(currentPath, km.currentKey); err != nil {
		return err
	}

	// Save metadata
	meta := struct {
		CurrentKID  string    `json:"current_kid"`
		PreviousKID string    `json:"previous_kid,omitempty"`
		RotatedAt   time.Time `json:"rotated_at"`
	}{
		CurrentKID:  km.currentKID,
		PreviousKID: km.previousKID,
		RotatedAt:   time.Now(),
	}

	metaPath := filepath.Join(km.keyDir, "meta.json")
	metaData, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(metaPath, metaData, 0600); err != nil {
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Save previous key if exists
	if km.previousKey != nil {
		prevPath := filepath.Join(km.keyDir, "previous.pem")
		if err := savePrivateKey(prevPath, km.previousKey); err != nil {
			return err
		}
	}

	return nil
}

// loadKeys loads keys from disk.
func (km *KeyManager) loadKeys() error {
	currentPath := filepath.Join(km.keyDir, "current.pem")
	currentKey, err := loadPrivateKey(currentPath)
	if err != nil {
		return err
	}

	km.currentKey = currentKey
	km.currentKID = generateKID(&currentKey.PublicKey)

	// Try to load previous key (optional)
	prevPath := filepath.Join(km.keyDir, "previous.pem")
	if prevKey, err := loadPrivateKey(prevPath); err == nil {
		km.previousKey = prevKey
		km.previousKID = generateKID(&prevKey.PublicKey)
	}

	return nil
}

func savePrivateKey(path string, key *rsa.PrivateKey) error {
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}

	// #nosec G304 -- path is from trusted server config
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer f.Close()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	// #nosec G304 -- path is from trusted server config
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
