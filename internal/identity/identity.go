package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
)

type Logger interface {
	Printf(format string, v ...any)
}

type Identity struct {
	NodeID     string
	NodeName   string
	PublicKey  string
	PrivateKey ed25519.PrivateKey
}

type Service struct {
	mu       sync.RWMutex
	dataDir  string
	nodeName string
	logger   Logger
	identity Identity
}

func NewService(dataDir, nodeName string, logger Logger) (*Service, error) {
	s := &Service{
		dataDir:  dataDir,
		nodeName: nodeName,
		logger:   logger,
	}
	if err := s.loadOrCreate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) Name() string { return "identity" }

func (s *Service) Start(ctx context.Context) error {
	s.logger.Printf("[identity] ready node_id=%s", s.identity.NodeID)
	return nil
}

func (s *Service) Stop(ctx context.Context) error  { return nil }
func (s *Service) Health(ctx context.Context) error { return nil }

func (s *Service) Current() Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.identity
}

func (s *Service) loadOrCreate() error {
	keyPath := filepath.Join(s.dataDir, "node_key.pem")
	idPath  := filepath.Join(s.dataDir, "node_id")

	// FIX: node_id is a UUID stored independently of the keypair.
	// Key rotation generates a new keypair but leaves node_id untouched,
	// so the Supabase node record is never orphaned.
	nodeID, err := s.loadOrCreateNodeID(idPath)
	if err != nil {
		return err
	}

	pub, priv, err := s.loadOrCreateKeypair(keyPath)
	if err != nil {
		return err
	}

	s.identity = Identity{
		NodeID:     nodeID,
		NodeName:   s.nodeName,
		PublicKey:  hex.EncodeToString(pub),
		PrivateKey: priv,
	}
	return nil
}

// loadOrCreateNodeID reads the UUID from disk, or generates and persists a new one.
// This file is the single source of truth for node identity — never derived from
// the keypair.
func (s *Service) loadOrCreateNodeID(idPath string) (string, error) {
	if raw, err := os.ReadFile(idPath); err == nil {
		id := string(raw)
		if _, parseErr := uuid.Parse(id); parseErr != nil {
			return "", fmt.Errorf("node_id file contains invalid UUID %q: %w", id, parseErr)
		}
		return id, nil
	}

	id := uuid.NewString()
	if err := os.WriteFile(idPath, []byte(id), 0o600); err != nil {
		return "", fmt.Errorf("write node_id: %w", err)
	}
	s.logger.Printf("[identity] generated new node_id=%s", id)
	return id, nil
}

// loadOrCreateKeypair reads an ed25519 keypair from disk, or generates and
// persists a new one. The keypair can be rotated without affecting node_id.
func (s *Service) loadOrCreateKeypair(keyPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if _, err := os.Stat(keyPath); err == nil {
		return s.loadKeypair(keyPath)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, nil, fmt.Errorf("write private key: %w", err)
	}

	s.logger.Printf("[identity] generated new ed25519 keypair")
	return pub, priv, nil
}

func (s *Service) loadKeypair(keyPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("invalid PEM in %s", keyPath)
	}

	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	priv, ok := keyAny.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not ed25519")
	}

	return priv.Public().(ed25519.PublicKey), priv, nil
}
