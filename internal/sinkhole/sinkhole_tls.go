package sinkhole

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	HTTPSPort = 443

	// defaultCACertPath / defaultCAKeyPath can be overridden via env
	// SAFESWITCH_CA_CERT_PATH and SAFESWITCH_CA_KEY_PATH. Defaults point
	// at the Squid CA that the child enrollment flow installs on devices.
	defaultCACertPath = "/etc/squid/ssl/safeswitch-ca.crt"
	defaultCAKeyPath  = "/etc/squid/ssl/safeswitch-ca.key"

	// Leaf certs are re-minted every 24h. Cache is bounded.
	leafCacheMax = 1024
	leafValidity = 24 * time.Hour
)

// StartSinkholeTLS starts the HTTPS block-page listener on SinkholeAddr:443.
// Call AFTER StartSinkhole() and AFTER EnsureSinkholeAddr(). Uses the same
// handleBlock handler as the HTTP sinkhole so both pages are identical.
//
// The listener mints a fresh leaf cert per SNI, signed by the SafeSwitch
// root CA that was installed on the child device during enrollment. Adults
// on other devices see a cert warning if they somehow hit 10.10.0.254:443
// which is fine — they shouldn't be on the tunnel.
func StartSinkholeTLS() error {
	caCertPath := envOr("SAFESWITCH_CA_CERT_PATH", defaultCACertPath)
	caKeyPath := envOr("SAFESWITCH_CA_KEY_PATH", defaultCAKeyPath)

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("sinkhole-tls: read ca cert %s: %w", caCertPath, err)
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("sinkhole-tls: read ca key %s: %w", caKeyPath, err)
	}

	caCert, caSigner, err := parseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return fmt.Errorf("sinkhole-tls: parse CA: %w", err)
	}

	minter := &leafMinter{
		caCert: caCert,
		caKey:  caSigner,
		cache:  newLeafCache(leafCacheMax),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleBlock)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	addr := fmt.Sprintf("%s:%d", SinkholeAddr, HTTPSPort)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: minter.getCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"http/1.1"},
		},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("sinkhole-tls: listen %s: %w", addr, err)
	}

	log.Printf("[sinkhole-tls] listening on %s (ca=%s)", addr, caCertPath)
	go func() {
		// Empty cert/key paths - uses TLSConfig.GetCertificate instead.
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			log.Printf("[sinkhole-tls] serve error: %v", err)
		}
	}()
	return nil
}

// ── CA parsing ───────────────────────────────────────────────────────────────

// Signer interface covers both RSA and ECDSA keys so the CA can be either.
// crypto.Signer is technically broader but this is sufficient for x509.
type caSigner interface {
	Public() interface{}
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, interface{}, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, errors.New("no cert in CA PEM")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	// Accept RSA or ECDSA. Squid CAs are typically RSA.
	switch pair.PrivateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return cert, pair.PrivateKey, nil
	default:
		return nil, nil, errors.New("CA key must be RSA or ECDSA")
	}
}

// ── Per-SNI leaf minting ─────────────────────────────────────────────────────

type leafMinter struct {
	caCert *x509.Certificate
	caKey  interface{} // *rsa.PrivateKey or *ecdsa.PrivateKey
	cache  *leafCache
}

func (m *leafMinter) getCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := chi.ServerName
	if host == "" {
		// Direct IP connects or very old clients. Serve something so the
		// TLS handshake doesn't abort — browser will show a warning and
		// the user can click through to see the block page.
		host = "safeswitch-block.local"
	}
	if cert, ok := m.cache.get(host); ok {
		return cert, nil
	}
	cert, err := m.mintLeaf(host)
	if err != nil {
		log.Printf("[sinkhole-tls] mintLeaf %q: %v", host, err)
		return nil, err
	}
	m.cache.put(host, cert)
	return cert, nil
}

func (m *leafMinter) mintLeaf(host string) (*tls.Certificate, error) {
	// Fresh ECDSA P-256 key per leaf — fast to generate (<1ms) and
	// every modern browser supports ECDSA-signed leaves even under an
	// RSA CA.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(leafValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &leafKey.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, m.caCert.Raw},
		PrivateKey:  leafKey,
	}, nil
}

// ── Bounded LRU for leaf certs ───────────────────────────────────────────────

type leafCache struct {
	mu    sync.Mutex
	max   int
	ll    *list.List
	items map[string]*list.Element
}

type leafEntry struct {
	host string
	cert *tls.Certificate
}

func newLeafCache(max int) *leafCache {
	return &leafCache{max: max, ll: list.New(), items: make(map[string]*list.Element, max)}
}

func (c *leafCache) get(host string) (*tls.Certificate, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[host]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*leafEntry).cert, true
}

func (c *leafCache) put(host string, cert *tls.Certificate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[host]; ok {
		el.Value.(*leafEntry).cert = cert
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&leafEntry{host: host, cert: cert})
	c.items[host] = el
	if c.ll.Len() > c.max {
		if tail := c.ll.Back(); tail != nil {
			delete(c.items, tail.Value.(*leafEntry).host)
			c.ll.Remove(tail)
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
