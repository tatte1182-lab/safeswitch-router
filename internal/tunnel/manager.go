package tunnel

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
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
)

type Manager struct {
	db         *sql.DB
	logger     Logger
	journal    Journal
	policy     PolicyReader
	confWriter *ConfWriter
	wgKeyFile  string
	devMode    bool

	mu           sync.RWMutex
	latestHealth *PeerHealthSnapshot

	cancel context.CancelFunc
	done   sync.WaitGroup
}

func NewManager(
	db *sql.DB,
	logger Logger,
	journal Journal,
	policy PolicyReader,
	wgKeyFile string,
	devMode bool,
) *Manager {
	return &Manager{
		db:         db,
		logger:     logger,
		journal:    journal,
		policy:     policy,
		confWriter: NewConfWriter(devMode),
		wgKeyFile:  wgKeyFile,
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

	// Validate key is available before starting — fail fast, not silently
	if !m.devMode {
		if _, _, err := m.loadCanonicalPrivateKey(ctx); err != nil {
			return fmt.Errorf("tunnel manager: cannot start without WireGuard private key: %w", err)
		}
	}

	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	if err := m.sync(ctx); err != nil {
		// Log but don't fatal — wg0 may not be up yet on first boot.
		// The 60s ticker will retry, and TriggerSync fires on every bundle swap.
		m.logger.Printf("[tunnel] initial sync warning: %v", err)
	}

	m.done.Add(1)
	go m.runSyncLoop(runCtx)

	m.logger.Printf("[tunnel] manager started devMode=%v keyFile=%s", m.devMode, m.wgKeyFile)
	return nil
}

func (m *Manager) Stop(ctx context.Context) error {
	if m.cancel != nil {
		m.cancel()
	}
	m.done.Wait()
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
	if err := validateWireGuardKey(publicKey, "public"); err != nil {
		return "", err
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
	if err := m.upsertPeer(ctx, publicKey, allowedIP, deviceMAC, comment); err != nil {
		return "", err
	}
	if err := m.sync(ctx); err != nil {
		m.logger.Printf("[tunnel] sync after add_peer: %v", err)
	}
	m.logger.Printf("[tunnel] peer added key=%s ip=%s mac=%s", shortKey(publicKey), ip, deviceMAC)
	return allowedIP, nil
}

func (m *Manager) RemovePeer(ctx context.Context, publicKey string) error {
	if _, err := m.db.ExecContext(ctx,
		`DELETE FROM tunnel_peers WHERE public_key = ?`, publicKey); err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	if err := m.sync(ctx); err != nil {
		m.logger.Printf("[tunnel] sync after remove_peer: %v", err)
	}
	m.logger.Printf("[tunnel] peer removed key=%s", shortKey(publicKey))
	return nil
}

// RemovePeersByChildID removes all tunnel peers whose comment matches the given
// child_id. This is the authoritative cleanup path when a child is deleted —
// it bypasses the bundle reconcile loop so stale peers are gone immediately
// regardless of bundle fetch state.
func (m *Manager) RemovePeersByChildID(ctx context.Context, childID string) error {
	res, err := m.db.ExecContext(ctx,
		`DELETE FROM tunnel_peers WHERE comment = ?`, childID)
	if err != nil {
		return fmt.Errorf("remove peers for child %s: %w", childID, err)
	}
	n, _ := res.RowsAffected()
	m.logger.Printf("[tunnel] removed %d peers for child_id=%s", n, childID)
	if n > 0 {
		if err := m.sync(ctx); err != nil {
			m.logger.Printf("[tunnel] sync after child removal: %v", err)
		}
	}
	return nil
}

func (m *Manager) runSyncLoop(ctx context.Context) {
	defer m.done.Done()
	syncTicker := time.NewTicker(60 * time.Second)
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

// sync reconciles tunnel_peers against the active bundle, then applies
// the diff to wg0 using the non-disruptive peer-by-peer approach.
func (m *Manager) sync(ctx context.Context) error {
	bundle, err := m.policy.ActiveBundle(ctx)
	if err != nil {
		return nil // no bundle yet
	}

	// Guard: bootstrap-local bundles have no children and no real signature.
	// Never treat an empty bootstrap as authoritative — it would wipe all peers.
	isBootstrap := bundle.Signature == "bootstrap-local" || bundle.Version == ""
	if isBootstrap {
		m.logger.Printf("[tunnel] sync skipped: bundle is bootstrap-local (peers unchanged)")
		// Still apply current SQLite state to wg0 so wg0 reflects reality on startup.
		peers, err := m.loadPeers(ctx)
		if err != nil {
			return fmt.Errorf("load peers: %w", err)
		}
		iface, err := m.loadInterfaceConfig(ctx)
		if err != nil {
			return fmt.Errorf("load interface config: %w", err)
		}
		return m.confWriter.Apply(iface, peers)
	}

	// Reconcile tunnel_peers table against bundle
	bundleKeys := make(map[string]bool)
	added, rekeyed := 0, 0

	for _, child := range bundle.Children {
		if child.WireGuardPublicKey == "" || child.WireguardIP == "" {
			continue
		}
		bundleKeys[child.WireGuardPublicKey] = true
		allowedIP := normalizeAllowedIP(child.WireguardIP)

		var existingKey string
		_ = m.db.QueryRowContext(ctx,
			`SELECT public_key FROM tunnel_peers WHERE allowed_ip = ?`, allowedIP,
		).Scan(&existingKey)

		if existingKey == child.WireGuardPublicKey {
			_ = m.upsertPeer(ctx, child.WireGuardPublicKey, allowedIP, child.DeviceMAC, child.ChildID)
			continue
		}
		if existingKey != "" {
			m.logger.Printf("[tunnel] rekey ip=%s old=%s new=%s child=%s",
				allowedIP, shortKey(existingKey), shortKey(child.WireGuardPublicKey), child.ChildID)
			rekeyed++
		} else {
			m.logger.Printf("[tunnel] new peer ip=%s key=%s child=%s",
				allowedIP, shortKey(child.WireGuardPublicKey), child.ChildID)
			added++
		}
		_ = m.upsertPeer(ctx, child.WireGuardPublicKey, allowedIP, child.DeviceMAC, child.ChildID)
	}

	// Remove orphaned peers from SQLite
	rows, err := m.db.QueryContext(ctx, `SELECT public_key FROM tunnel_peers`)
	if err != nil {
		return fmt.Errorf("query peers: %w", err)
	}
	var toRemove []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			continue
		}
		if !bundleKeys[key] {
			toRemove = append(toRemove, key)
		}
	}
	rows.Close()
	for _, key := range toRemove {
		m.logger.Printf("[tunnel] removing orphaned peer key=%s", shortKey(key))
		_, _ = m.db.ExecContext(ctx, `DELETE FROM tunnel_peers WHERE public_key = ?`, key)
	}

	if added > 0 || rekeyed > 0 || len(toRemove) > 0 {
		m.logger.Printf("[tunnel] reconcile added=%d rekeyed=%d removed=%d", added, rekeyed, len(toRemove))
	}

	// Load desired state and apply to wg0
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
			shortKey(p.PublicKey), p.LastHandshake)
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

// ── Key management ────────────────────────────────────────────────────────────
//
// Single source of truth: SQLite tunnel_config.private_key
//
// Written once during enrollment (by the enroll Edge Function response,
// persisted by enrollment/service.go). Never regenerated automatically.
//
// The canonical key FILE at SS_ROUTER_WG_PRIVATE_KEY_FILE is a boot-time
// cache only. On every start we:
//   1. Try to read from the file (fast path, survives restarts)
//   2. Fall back to SQLite and backfill the file
//
// If NEITHER has the key, we fail hard with a clear error — not silently.
// This forces a deliberate re-enrollment rather than generating a new key
// that would mismatch Supabase.

func (m *Manager) loadInterfaceConfig(ctx context.Context) (InterfaceConfig, error) {
	privKey, source, err := m.loadCanonicalPrivateKey(ctx)
	if err != nil {
		return InterfaceConfig{}, err
	}

	// Mirror public key to SQLite so heartbeat can read it
	if pubKey, err := derivePublicKey(privKey); err == nil {
		_ = m.mirrorWGKeysToDB(ctx, privKey, pubKey)
	} else {
		m.logger.Printf("[tunnel] warning: derive public key: %v", err)
	}

	m.logger.Printf("[tunnel] interface key from %s", source)
	return InterfaceConfig{
		PrivateKey: privKey,
		ListenPort: DefaultListenPort,
		Address:    TunnelGatewayCIDR,
	}, nil
}

func (m *Manager) loadCanonicalPrivateKey(ctx context.Context) (string, string, error) {
	path := m.wgKeyFile
	if path == "" {
		if v := strings.TrimSpace(os.Getenv("SS_ROUTER_WG_PRIVATE_KEY_FILE")); v != "" {
			path = v
		} else {
			path = "/etc/safeswitch/wireguard/privatekey"
		}
	}

	// 1. Try file (boot-time cache)
	if raw, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(raw))
		if err := validateWireGuardKey(key, "private"); err != nil {
			return "", "", fmt.Errorf("invalid key in %s: %w — delete the file to force re-enrollment", path, err)
		}
		return key, path, nil
	}

	// 2. Fall back to SQLite (source of truth)
	var privKey string
	_ = m.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'private_key'`,
	).Scan(&privKey)
	privKey = strings.TrimSpace(privKey)

	if privKey == "" {
		return "", "", fmt.Errorf(
			"WireGuard private key not found — checked file %q and tunnel_config.private_key\n"+
				"This node needs to be enrolled. Run the enroll API or re-enroll from the parent app.",
			path,
		)
	}
	if err := validateWireGuardKey(privKey, "private"); err != nil {
		return "", "", fmt.Errorf("invalid key in tunnel_config.private_key: %w", err)
	}

	// Backfill the file so next boot uses the fast path
	if err := writeCanonicalPrivateKey(path, privKey); err != nil {
		m.logger.Printf("[tunnel] warning: could not backfill key to %s: %v", path, err)
		// Non-fatal — SQLite is the source of truth
	} else {
		m.logger.Printf("[tunnel] key backfilled from SQLite to %s", path)
	}
	return privKey, "sqlite", nil
}

func (m *Manager) mirrorWGKeysToDB(ctx context.Context, privKey, pubKey string) error {
	entries := map[string]string{"private_key": privKey}
	if pubKey != "" {
		entries["wireguard_public_key"] = pubKey
	}
	for key, value := range entries {
		if _, err := m.db.ExecContext(ctx, `
			INSERT INTO tunnel_config (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value
		`, key, value); err != nil {
			return err
		}
	}
	return nil
}

// ── SQLite helpers ────────────────────────────────────────────────────────────

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
	used := map[string]bool{TunnelGateway: true, "10.10.0.254": true}
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
	for i := 2; i <= 253; i++ {
		candidate := fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], i)
		if !used[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("tunnel subnet exhausted")
}

func (m *Manager) loadPeers(ctx context.Context) ([]PeerConfig, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT public_key, allowed_ip, device_mac, comment FROM tunnel_peers ORDER BY allowed_ip ASC`)
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

func (m *Manager) upsertPeer(ctx context.Context, publicKey, allowedIP, deviceMAC, comment string) error {
	if err := validateWireGuardKey(publicKey, "public"); err != nil {
		return err
	}
	allowedIP = normalizeAllowedIP(allowedIP)
	if _, _, err := net.ParseCIDR(allowedIP); err != nil {
		return fmt.Errorf("invalid allowed_ip %q: %w", allowedIP, err)
	}
	// INSERT OR REPLACE handles conflicts on BOTH public_key (PK) and allowed_ip (UNIQUE)
	// atomically — avoids the double-ON CONFLICT limitation in SQLite.
	// This is safe: the only rows replaced are stale ones for this key or IP.
	_, err := m.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO tunnel_peers (public_key, allowed_ip, device_mac, comment, added_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, publicKey, allowedIP, deviceMAC, comment)
	if err != nil {
		return fmt.Errorf("upsert peer: %w", err)
	}
	return nil
}

func (m *Manager) ensureSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tunnel_peers (
			public_key TEXT PRIMARY KEY,
			allowed_ip TEXT NOT NULL UNIQUE,
			device_mac TEXT NOT NULL DEFAULT '',
			comment    TEXT NOT NULL DEFAULT '',
			added_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS tunnel_config (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := m.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("tunnel schema: %w", err)
		}
	}
	return nil
}

// ── Static helpers ────────────────────────────────────────────────────────────

func normalizeAllowedIP(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	if !strings.Contains(v, "/") {
		return v + "/32"
	}
	return v
}

func shortKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:8] + "..."
}

func writeCanonicalPrivateKey(path, key string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(key+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func derivePublicKey(privateKey string) (string, error) {
	if strings.TrimSpace(privateKey) == "" {
		return "", fmt.Errorf("empty private key")
	}
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(strings.TrimSpace(privateKey) + "\n")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", fmt.Errorf("wg pubkey: %s", msg)
	}
	pub := strings.TrimSpace(out.String())
	if err := validateWireGuardKey(pub, "public"); err != nil {
		return "", err
	}
	return pub, nil
}

func validateWireGuardKey(key, kind string) error {
	key = strings.TrimSpace(key)
	if len(key) != 44 {
		return fmt.Errorf("invalid %s key: length %d (want 44)", kind, len(key))
	}
	return nil
}
