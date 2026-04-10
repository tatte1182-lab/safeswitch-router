package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// CA holds the root certificate authority used to sign intercepted connections.
type CA struct {
	cert    *x509.Certificate
	key     *rsa.PrivateKey
	tlsCert tls.Certificate

	mu    sync.Mutex
	cache map[string]*tls.Certificate // hostname → signed leaf cert
}

// LoadCA reads the root CA cert and key from disk.
func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA key pair: %w", err)
	}

	parsed, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	privKey, ok := tlsCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key must be RSA")
	}

	return &CA{
		cert:    parsed,
		key:     privKey,
		tlsCert: tlsCert,
		cache:   make(map[string]*tls.Certificate),
	}, nil
}

// CertFor returns a TLS certificate for the given hostname, signing a new leaf
// cert with the root CA if one is not already cached.
func (ca *CA) CertFor(hostname string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if cert, ok := ca.cache[hostname]; ok {
		return cert, nil
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %s: %w", hostname, err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"SafeSwitch Family Security"},
		},
		DNSNames:  []string{hostname},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign cert for %s: %w", hostname, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(leafKey)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("assemble leaf cert for %s: %w", hostname, err)
	}

	// Evict cache if it grows too large (simple bounded cache)
	if len(ca.cache) >= 512 {
		for k := range ca.cache {
			delete(ca.cache, k)
			break
		}
	}

	ca.cache[hostname] = &tlsCert
	return &tlsCert, nil
}

// RawCert returns the PEM-encoded root CA certificate for distribution to devices.
func (ca *CA) RawCert() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.cert.Raw,
	})
}

// Subject returns the CA certificate's common name — satisfies api.CAProvider.
func (ca *CA) Subject() string {
	return ca.cert.Subject.CommonName
}

// NotAfter returns the CA expiry date as YYYY-MM-DD — satisfies api.CAProvider.
func (ca *CA) NotAfter() string {
	return ca.cert.NotAfter.Format("2006-01-02")
}
