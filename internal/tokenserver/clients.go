package tokenserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Client represents a registered API client.
type Client struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	SecretHash    string   `json:"secret_hash"` // SHA256 hash of the secret
	AllowedScopes []string `json:"allowed_scopes"`
	Enabled       bool     `json:"enabled"`
}

// ClientStore manages registered clients.
type ClientStore struct {
	mu      sync.RWMutex
	clients map[string]*Client
	path    string
}

// NewClientStore creates a client store, optionally loading from a file.
func NewClientStore(path string) (*ClientStore, error) {
	cs := &ClientStore{
		clients: make(map[string]*Client),
		path:    path,
	}

	if path != "" {
		if err := cs.load(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load clients: %w", err)
		}
	}

	return cs, nil
}

// Authenticate validates client credentials and returns the client if valid.
func (cs *ClientStore) Authenticate(clientID, clientSecret string) (*Client, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	client, exists := cs.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client not found")
	}

	if !client.Enabled {
		return nil, fmt.Errorf("client disabled")
	}

	// Verify secret
	secretHash := hashSecret(clientSecret)
	if subtle.ConstantTimeCompare([]byte(client.SecretHash), []byte(secretHash)) != 1 {
		return nil, fmt.Errorf("invalid credentials")
	}

	return client, nil
}

// FilterScopes returns only the scopes the client is allowed to request.
func (cs *ClientStore) FilterScopes(client *Client, requested []string) []string {
	if len(requested) == 0 {
		return client.AllowedScopes
	}

	allowed := make(map[string]bool)
	for _, s := range client.AllowedScopes {
		allowed[s] = true
	}

	filtered := make([]string, 0, len(requested))
	for _, s := range requested {
		if allowed[s] {
			filtered = append(filtered, s)
		}
	}

	return filtered
}

// AddClient registers a new client and returns the generated secret.
func (cs *ClientStore) AddClient(id, name string, scopes []string) (string, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, exists := cs.clients[id]; exists {
		return "", fmt.Errorf("client already exists")
	}

	// Generate random secret
	secret, err := generateSecret()
	if err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}

	client := &Client{
		ID:            id,
		Name:          name,
		SecretHash:    hashSecret(secret),
		AllowedScopes: scopes,
		Enabled:       true,
	}

	cs.clients[id] = client

	if cs.path != "" {
		if err := cs.save(); err != nil {
			return "", fmt.Errorf("failed to save clients: %w", err)
		}
	}

	return secret, nil
}

// RemoveClient removes a client registration.
func (cs *ClientStore) RemoveClient(id string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, exists := cs.clients[id]; !exists {
		return fmt.Errorf("client not found")
	}

	delete(cs.clients, id)

	if cs.path != "" {
		return cs.save()
	}

	return nil
}

// ListClients returns all registered clients (without secrets).
func (cs *ClientStore) ListClients() []*Client {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	clients := make([]*Client, 0, len(cs.clients))
	for _, c := range cs.clients {
		// Return copy without exposing internal state
		clients = append(clients, &Client{
			ID:            c.ID,
			Name:          c.Name,
			AllowedScopes: c.AllowedScopes,
			Enabled:       c.Enabled,
		})
	}

	return clients
}

// load reads clients from the JSON file.
func (cs *ClientStore) load() error {
	data, err := os.ReadFile(cs.path)
	if err != nil {
		return err
	}

	var clients []*Client
	if err := json.Unmarshal(data, &clients); err != nil {
		return err
	}

	for _, c := range clients {
		cs.clients[c.ID] = c
	}

	return nil
}

// save writes clients to the JSON file.
func (cs *ClientStore) save() error {
	clients := make([]*Client, 0, len(cs.clients))
	for _, c := range cs.clients {
		clients = append(clients, c)
	}

	data, err := json.MarshalIndent(clients, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(cs.path, data, 0600)
}

// hashSecret creates a SHA256 hash of a secret.
func hashSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

// generateSecret creates a random 32-byte secret.
func generateSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := cryptoRandRead(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// cryptoRandRead wraps crypto/rand.Read for secret generation.
var cryptoRandRead = rand.Read
