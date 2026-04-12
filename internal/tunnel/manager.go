package tunnel

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	contractevents "github.com/getsafeswitch/safeswitch-router/pkg/contract/events"
	policybundle "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

type Logger interface {
	Printf(format string, v ...any)
}

type Journal interface {
	Append(ctx context.Context, evt contractevents.Event) error
}

type PolicyReader interface {
	ActiveBundle(ctx context.Context) (*policybundle.Bundle, error)
}

const (
	TunnelSubnet      = "10.10.0.0/24"
	TunnelGateway     = "10.10.0.1"
	TunnelGatewayCIDR = "10.10.0.1/24"
	DefaultListenPort = 51820

	// CanonicalKeyFile is the ONLY source of truth for the WireGuard private key.
	// ss-router reads from here exclusively. No other store may supply the active key.
	CanonicalKeyFile = "/etc/safeswitch/wireguard/privatekey"
	CanonicalKeyDir  = "/etc/safeswitch/wireguard"
)

type Manager struct {
	db         *sql.DB
	logger     Logger
	journal    Journal
	policy     PolicyReader
	confWriter *ConfWriter
	devMode    bool

	mu           sync.RWMutex
	latestHealth *PeerHealthSnapshot

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewManager(
	db *sql.DB,
	logger Logger,
	journal Journal,
	policy PolicyReader,
	devMode bool,
) *Manager {
	return &Manager{
		db:         db,
		logger:     logger,
		journal:    journal,
		policy:     policy,
		confWriter: NewConfWriter(devMode),
		devMode:    devMode,
		latestHealth: &PeerHealthSnapshot{
			Interface:  wgInterface,
			CapturedAt: time.Now().UTC(),
		},
	}
}

func (m *Manager) Name() string { return "tunnel-manager" }

func (m *Manager) Start(ctx context.Context) error {
	if err := m.ensureSchema(ctx); err != nil {
		return err
	}

	// Step 1: Establish canonical identity — generate if missing, validate if present
	privKey, created, err := m.ensureCanonicalKey()
	if err != nil {
		return fmt.Errorf("canonical key: %w", err)
	}
	if created {
		m.logger.Printf("[tunnel] identity: canonical key created at %s", CanonicalKeyFile)
	} else {
		m.logger.Printf("[tunnel] identity: canonical key loaded from %s", CanonicalKeyFile)
	}

	// Step 2: Derive public key and run drift detection
	pubKey, err := derivePublicKey(privKey)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	m.logger.Printf("[tunnel] identity: public key = %s", pubKey[:12]+"...")

	// Step 3: Reconcile all other stores outward (never inward)
	m.reconcileIdentity(ctx, pubKey)

	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	if err := m.sync(ctx); err != nil {
		m.logger.Printf("[tunnel] initial sync warning: %v", err)
	}

	m.wg.Add(1)
	go m.runSyncLoop(runCtx)

	m.logger.Printf("[tunnel] manager started devMode=%v", m.devMode)
	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
	return nil
}

func (m *Manager) Health(ctx context.Context) error { return nil }

func (m *Manager) TriggerSync(ctx context.Context) error {
	return m.sync(ctx)
}

func (m *Manager) TunnelIPForMAC(ctx context.Context, mac string) string {
	var allowedIP string
	_ = m.db.QueryRowContext(ctx,
		`SELECT allowed_ip FROM tunnel_peers WHERE device_mac = ? LIMIT 1`, mac,
	).Scan(&allowedIP)
	if allowedIP == "" {
		return ""
	}
	ip, _, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return allowedIP
	}
	return ip.String()
}

func (m *Manager) LatestHealth(_ context.Context) *PeerHealthSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latestHealth
}

func (m *Manager) AddPeer(ctx context.Context, publicKey, deviceMAC, comment string) (string, error) {
	if len(publicKey) != 44 {
		return "", fmt.Errorf("invalid WireGuard public key length %d (want 44)", len(publicKey))
	}

	var existing string
	_ = m.db.QueryRowContext(ctx,
		`SELECT allowed_ip FROM tunnel_peers WHERE public_key = ?`, publicKey,
	).Scan(&existing)
	if existing != "" {
		return existing, nil
	}

	ip, err := m.allocateIP(ctx)
	if err != nil {
		return "", fmt.Errorf("allocate ip: %w", err)
	}

	allowedIP := ip + "/32"
	now := time.Now().UTC().Format(time.RFC3339)

	_, err = m.db.ExecContext(ctx, `
		INSERT INTO tunnel_peers (public_key, allowed_ip, device_mac, comment, added_at)
		VALUES (?, ?, ?, ?, ?)
	`, publicKey, allowedIP, deviceMAC, comment, now)
	if err != nil {
		return "", fmt.Errorf("insert peer: %w", err)
	}

	if err := m.sync(ctx); err != nil {
		m.logger.Printf("[tunnel] sync after add_peer: %v", err)
	}

	m.logger.Printf("[tunnel] peer added key=%s ip=%s mac=%s", publicKey[:8]+"...", ip, deviceMAC)
	return allowedIP, nil
}

func (m *Manager) RemovePeer(ctx context.Context, publicKey string) error {
	_, err := m.db.ExecContext(ctx,
		`DELETE FROM tunnel_peers WHERE public_key = ?`, publicKey)
	if err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}

	if err := m.sync(ctx); err != nil {
		m.logger.Printf("[tunnel] sync after remove_peer: %v", err)
	}

	m.logger.Printf("[tunnel] peer removed key=%s", publicKey[:8]+"...")
	return nil
}

func (m *Manager) runSyncLoop(ctx context.Context) {
	defer m.wg.Done()

	syncTicker   := time.NewTicker(60 * time.Second)
	healthTicker := time.NewTicker(30 * time.Second)
	defer syncTicker.Stop()
	defer healthTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-syncTicker.C:
			if err := m.sync(ctx); err != nil {
				m.logger.Printf("[tunnel] sync error: %v", err)
			}
		case <-healthTicker.C:
			m.checkHealth(ctx)
		}
	}
}

func (m *Manager) sync(ctx context.Context) error {
	bundle, err := m.policy.ActiveBundle(ctx)
	if err != nil {
		return nil
	}

	bundleKeys := make(map[string]bool)
	for _, child := range bundle.Children {
		if child.WireGuardPublicKey == "" || child.WireguardIP == "" {
			continue
		}
		bundleKeys[child.WireGuardPublicKey] = true

		allowedIP := child.WireguardIP
		if !strings.Contains(allowedIP, "/") {
			allowedIP = allowedIP + "/32"
		}

		var existingKey string
		_ = m.db.QueryRowContext(ctx,
			`SELECT public_key FROM tunnel_peers WHERE allowed_ip = ?`,
			allowedIP,
		).Scan(&existingKey)

		if existingKey == child.WireGuardPublicKey {
			continue
		}

		if existingKey != "" {
			m.logger.Printf("[tunnel] stale key on %s: replacing %s with %s",
				allowedIP, existingKey[:8]+"...", child.WireGuardPublicKey[:8]+"...")
			_, _ = m.db.ExecContext(ctx,
				`DELETE FROM tunnel_peers WHERE allowed_ip = ?`, allowedIP)
		}

		if _, err := m.AddPeer(ctx, child.WireGuardPublicKey, child.DeviceMAC, child.ChildID); err != nil {
			m.logger.Printf("[tunnel] auto-add peer child=%s: %v", child.ChildID, err)
		}
	}

	dbRows, err := m.db.QueryContext(ctx, `SELECT public_key FROM tunnel_peers`)
	if err != nil {
		return fmt.Errorf("query peers for reconcile: %w", err)
	}
	var toRemove []string
	for dbRows.Next() {
		var key string
		if err := dbRows.Scan(&key); err != nil {
			continue
		}
		if !bundleKeys[key] {
			toRemove = append(toRemove, key)
		}
	}
	dbRows.Close()

	for _, key := range toRemove {
		short := key
		if len(key) > 8 {
			short = key[:8] + "..."
		}
		m.logger.Printf("[tunnel] removing orphaned peer key=%s (not in bundle)", short)
		_, _ = m.db.ExecContext(ctx, `DELETE FROM tunnel_peers WHERE public_key = ?`, key)
	}

	peers, err := m.loadPeers(ctx)
	if err != nil {
		return fmt.Errorf("load peers: %w", err)
	}

	iface, err := m.loadInterfaceConfig(ctx)
	if err != nil {
		return fmt.Errorf("load interface config: %w", err)
	}

	if err := m.confWriter.Apply(iface, peers); err != nil {
		return fmt.Errorf("apply wg conf: %w", err)
	}

	m.logger.Printf("[tunnel] synced peers=%d", len(peers))
	return nil
}

func (m *Manager) checkHealth(ctx context.Context) {
	snap, err := ReadHealth(m.devMode)
	if err != nil {
		m.logger.Printf("[tunnel] health check failed: %v", err)
		return
	}

	m.mu.Lock()
	m.latestHealth = snap
	m.mu.Unlock()

	for _, p := range snap.StalePeers() {
		m.logger.Printf("[tunnel] stale peer key=%s last_handshake=%v",
			p.PublicKey[:8]+"...", p.LastHandshake)

		raw, _ := json.Marshal(map[string]any{
			"public_key":     p.PublicKey,
			"last_handshake": p.LastHandshake.Format(time.RFC3339),
		})
		_ = m.journal.Append(ctx, contractevents.Event{
			ID:       uuid.NewString(),
			Type:     "tunnel.peer_stale",
			Severity: "warn",
			Payload:  json.RawMessage(raw),
		})
	}

	m.logger.Printf("[tunnel] health %s", snap.Summary())
}

func (m *Manager) allocateIP(ctx context.Context) (string, error) {
	_, subnet, err := net.ParseCIDR(TunnelSubnet)
	if err != nil {
		return "", fmt.Errorf("parse subnet: %w", err)
	}

	rows, err := m.db.QueryContext(ctx, `SELECT allowed_ip FROM tunnel_peers`)
	if err != nil {
		return "", fmt.Errorf("query peers: %w", err)
	}
	defer rows.Close()

	used := map[string]bool{TunnelGateway: true}
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			continue
		}
		ip, _, _ := net.ParseCIDR(cidr)
		if ip != nil {
			used[ip.String()] = true
		}
	}

	base := subnet.IP.To4()
	for i := 2; i <= 254; i++ {
		candidate := fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], i)
		if !used[candidate] {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("tunnel subnet exhausted")
}

func (m *Manager) loadPeers(ctx context.Context) ([]PeerConfig, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT public_key, allowed_ip, device_mac, comment FROM tunnel_peers`)
	if err != nil {
		return nil, fmt.Errorf("query tunnel_peers: %w", err)
	}
	defer rows.Close()

	var peers []PeerConfig
	for rows.Next() {
		var p PeerConfig
		if err := rows.Scan(&p.PublicKey, &p.AllowedIP, &p.DeviceMAC, &p.Comment); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}

// loadInterfaceConfig returns the WireGuard interface config.
// The private key is loaded EXCLUSIVELY from the canonical key file.
// SQLite is not consulted for key material — only for tunnel settings.
func (m *Manager) loadInterfaceConfig(ctx context.Context) (InterfaceConfig, error) {
	privKey, _, err := m.ensureCanonicalKey()
	if err != nil {
		return InterfaceConfig{}, fmt.Errorf("canonical key unavailable: %w", err)
	}

	return InterfaceConfig{
		PrivateKey: privKey,
		ListenPort: DefaultListenPort,
		Address:    TunnelGatewayCIDR,
	}, nil
}

// ── Identity management ───────────────────────────────────────────────────────

// ensureCanonicalKey loads the private key from the canonical file.
// If the file doesn't exist, generates a new key and persists it.
// Returns (key, created, error).
func (m *Manager) ensureCanonicalKey() (string, bool, error) {
	// Try to load existing key
	key, err := loadCanonicalKey()
	if err == nil {
		return key, false, nil
	}

	// Only generate if file is genuinely missing
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("read canonical key: %w — refusing to generate replacement (manual intervention required)", err)
	}

	// First boot: generate and persist
	m.logger.Printf("[tunnel] canonical key file missing — generating new identity (first boot)")
	key, err = generatePrivateKey()
	if err != nil {
		return "", false, fmt.Errorf("generate key: %w", err)
	}

	if err := persistCanonicalKey(key); err != nil {
		return "", false, fmt.Errorf("persist canonical key: %w", err)
	}

	return key, true, nil
}

// reconcileIdentity checks all stores against the canonical public key
// and reconciles them outward. Never mutates the local key to match a remote store.
func (m *Manager) reconcileIdentity(ctx context.Context, canonicalPubKey string) {
	// Check SQLite cache
	var sqlitePubKey string
	_ = m.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'wireguard_public_key'`,
	).Scan(&sqlitePubKey)

	if sqlitePubKey != canonicalPubKey {
		if sqlitePubKey != "" {
			m.logger.Printf("[tunnel] identity drift: SQLite has %s..., canonical is %s... — reconciling",
				safePrefix(sqlitePubKey), safePrefix(canonicalPubKey))
		}
		_, _ = m.db.ExecContext(ctx,
			`INSERT OR REPLACE INTO tunnel_config (key, value) VALUES ('wireguard_public_key', ?)`,
			canonicalPubKey)
		// Clear any stale private key from SQLite — it must not be used
		_, _ = m.db.ExecContext(ctx,
			`DELETE FROM tunnel_config WHERE key = 'private_key'`)
		m.logger.Printf("[tunnel] identity: SQLite reconciled, stale private_key removed")
	} else {
		m.logger.Printf("[tunnel] identity: SQLite consistent ✓")
	}

	// Check runtime wg0 if not in devMode
	if !m.devMode {
		out, err := exec.Command("wg", "show", wgInterface, "public-key").Output()
		if err == nil {
			runtimePubKey := strings.TrimSpace(string(out))
			if runtimePubKey != "" && runtimePubKey != canonicalPubKey {
				m.logger.Printf("[tunnel] identity drift: wg0 has %s..., canonical is %s... — will rebuild on next sync",
					safePrefix(runtimePubKey), safePrefix(canonicalPubKey))
			} else if runtimePubKey == canonicalPubKey {
				m.logger.Printf("[tunnel] identity: wg0 runtime consistent ✓")
			}
		}
	}
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

func loadCanonicalKey() (string, error) {
	data, err := os.ReadFile(CanonicalKeyFile)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("canonical key file is empty")
	}
	if len(key) != 44 {
		return "", fmt.Errorf("canonical key has unexpected length %d (want 44 base64 chars)", len(key))
	}
	return key, nil
}

func persistCanonicalKey(privKey string) error {
	if err := os.MkdirAll(CanonicalKeyDir, 0o700); err != nil {
		return fmt.Errorf("create key dir: %w", err)
	}
	dir := filepath.Dir(CanonicalKeyFile)
	tmp, err := os.CreateTemp(dir, ".privatekey-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.WriteString(privKey + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	return os.Rename(tmpPath, CanonicalKeyFile)
}

// generatePrivateKey generates a Curve25519 WireGuard private key.
// Uses the same method as `wg genkey`: random 32 bytes clamped per RFC 7748.
func generatePrivateKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	// Clamp per RFC 7748 §5
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// derivePublicKey derives the WireGuard public key from a private key using `wg pubkey`.
func derivePublicKey(privKey string) (string, error) {
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privKey)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("wg pubkey: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (m *Manager) ensureSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tunnel_peers (
			public_key  TEXT PRIMARY KEY,
			allowed_ip  TEXT NOT NULL UNIQUE,
			device_mac  TEXT NOT NULL DEFAULT '',
			comment     TEXT NOT NULL DEFAULT '',
			added_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS tunnel_config (
			key    TEXT PRIMARY KEY,
			value  TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := m.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("tunnel schema: %w", err)
		}
	}
	return nil
}

func safePrefix(s string) string {
	if len(s) >= 8 {
		return s[:8] + "..."
	}
	return s
}
