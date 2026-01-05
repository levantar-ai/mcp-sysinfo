// Package agent provides SaaS agent functionality including
// auto-generated TLS certificates and SaaS registration.
package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CertManager handles automatic TLS certificate generation and storage.
type CertManager struct {
	configDir string
	certPath  string
	keyPath   string
}

// CertInfo contains certificate information for registration.
type CertInfo struct {
	CertPath   string // Path to certificate file
	KeyPath    string // Path to private key file
	PublicCert string // PEM-encoded public certificate (for SaaS registration)
	NotAfter   time.Time
}

// NewCertManager creates a new certificate manager.
// If configDir is empty, uses ~/.mcp-sysinfo/
func NewCertManager(configDir string) (*CertManager, error) {
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir = filepath.Join(home, ".mcp-sysinfo")
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	return &CertManager{
		configDir: configDir,
		certPath:  filepath.Join(configDir, "agent.crt"),
		keyPath:   filepath.Join(configDir, "agent.key"),
	}, nil
}

// EnsureCert ensures a valid certificate exists, generating one if needed.
// Returns certificate info including the public cert for SaaS registration.
func (cm *CertManager) EnsureCert(hosts []string) (*CertInfo, error) {
	// Check if cert already exists and is valid
	if cm.certExists() {
		info, err := cm.loadCertInfo()
		if err == nil && time.Now().Before(info.NotAfter.Add(-24*time.Hour)) {
			// Cert exists and has more than 24 hours validity
			return info, nil
		}
		// Cert expired or expiring soon, regenerate
	}

	// Generate new certificate
	if err := cm.generateCert(hosts); err != nil {
		return nil, err
	}

	return cm.loadCertInfo()
}

// certExists checks if both cert and key files exist.
func (cm *CertManager) certExists() bool {
	_, certErr := os.Stat(cm.certPath)
	_, keyErr := os.Stat(cm.keyPath)
	return certErr == nil && keyErr == nil
}

// loadCertInfo loads existing certificate information.
func (cm *CertManager) loadCertInfo() (*CertInfo, error) {
	certPEM, err := os.ReadFile(cm.certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertInfo{
		CertPath:   cm.certPath,
		KeyPath:    cm.keyPath,
		PublicCert: string(certPEM),
		NotAfter:   cert.NotAfter,
	}, nil
}

// generateCert generates a new self-signed ECDSA certificate.
func (cm *CertManager) generateCert(hosts []string) error {
	// Generate ECDSA private key (P-256)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Certificate valid for 1 year
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	// Build certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MCP System Info Agent"},
			CommonName:   "mcp-sysinfo-agent",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add hosts as SANs
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	// Add localhost by default
	template.DNSNames = append(template.DNSNames, "localhost")
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("::1"))

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate (public cert can have 0644)
	certFile, err := os.OpenFile(cm.certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // #nosec G302 -- cert is public but keeping consistent with key
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key
	keyFile, err := os.OpenFile(cm.keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// GetCertPath returns the path to the certificate file.
func (cm *CertManager) GetCertPath() string {
	return cm.certPath
}

// GetKeyPath returns the path to the private key file.
func (cm *CertManager) GetKeyPath() string {
	return cm.keyPath
}
