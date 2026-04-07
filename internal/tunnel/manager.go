package tunnel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	contractevents "github.com/getsafeswitch/safeswitch-router/pkg/contract/events"
	policybundle "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

// Logger is the minimal logging interface the manager needs.
type Logger interface {
	Printf(format string, v ...any)
}

// Journal is the subset of events.Journal the manager uses.
type Journal interface {
	Append(ctx context.Context, evt contractevents.Event) error
}

// PolicyReader is the subset of policy.Runtime the manager needs.
type PolicyReader interface {
	ActiveBundle(ctx context.Context) (*policybundle.Bundle, error)
}

const (
	// TunnelSubnet is the WireGuard tunnel address space.
	// .1 is the router (server), .2+ are client peers.
	TunnelSubnet      = "10.10.0.0/24"
	TunnelGateway     = "10.10.0.1"
	TunnelGatewayCIDR = "10.10.0.1/24"
	DefaultListenPort = 51820
)

// Manager owns the WireGuard configuration and keeps it in sync with the
// active policy bundle. It runs a periodic sync loop and responds to
// add_peer / remove_peer commands.
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

// NewManager constructs the tunnel manager. devMode=true skips wg CLI calls
// so the binary runs without root or a live WireGuard interface.
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
	// Ensure peer table exists
	if err := m.ensureSchema(ctx); err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	// Initial sync — apply current bundle to wg0 immediately
	if err := m.sync(ctx); err != nil {
		m.logger.Printf("[tunnel] initial sync warning: %v", err)
		// non-fatal — WireGuard may not be up yet on first boot
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

// TriggerSync is called by wiring.go on every policy bundle swap so that
// new enrollments appear in wg0 immediately — without waiting for the
// 60-second background ticker.
func (m *Manager) TriggerSync(ctx context.Context) error {
	return m.sync(ctx)
}

// TunnelIPForMAC returns the tunnel IP allocated to a device by MAC address.
// Returns empty string if not found. Used by the firewall enforcer.
func (m *Manager) TunnelIPForMAC(ctx context.Context, mac string) string {
	var allowedIP string
	_ = m.db.QueryRowContext(ctx,
		`SELECT allowed_ip FROM tunnel_peers WHERE device_mac = ? LIMIT 1`, mac,
	).Scan(&allowedIP)
	if allowedIP == "" {
		return ""
	}
	// Strip the /32 suffix — enforcer wants just the IP
	ip, _, err := net.ParseCIDR(allowedIP)
	if err != nil {
		return allowedIP
	}
	return ip.String()
}

// LatestHealth returns the most recent peer health snapshot.
func (m *Manager) LatestHealth(_ context.Context) *PeerHealthSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.latestHealth
}

// AddPeer adds a new WireGuard peer and persists it.
// Allocates the next available tunnel IP from TunnelSubnet.
// Called by the add_peer command handler.
func (m *Manager) AddPeer(ctx context.Context, publicKey, deviceMAC, comment string) (string, error) {
	// Validate public key format (base64, 44 chars)
	if len(publicKey) != 44 {
		return "", fmt.Errorf("invalid WireGuard public key length %d (want 44)", len(publicKey))
	}

	// Check for duplicate
	var existing string
	_ = m.db.QueryRowContext(ctx,
		`SELECT allowed_ip FROM tunnel_peers WHERE public_key = ?`, publicKey,
	).Scan(&existing)
	if existing != "" {
		return existing, nil // idempotent
	}

	// Allocate next IP
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

// RemovePeer removes a peer by public key and resyncs.
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

// runSyncLoop periodically syncs the peer list and checks tunnel health.
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

// sync diffs the policy bundle against tunnel_peers, upserts any missing
// peers, then writes wg0.conf and applies it.
func (m *Manager) sync(ctx context.Context) error {
	bundle, err := m.policy.ActiveBundle(ctx)
	if err != nil {
		// No bundle yet — nothing to sync
		return nil
	}

	// Reconcile tunnel_peers against bundle using WireguardIP as stable identity.
	// If a device re-enrolls with a new key, the IP stays the same but the key
	// changes — update the key rather than accumulating stale rows.
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
			continue // already correct
		}

		if existingKey != "" {
			// Stale key on this IP slot — evict before re-adding
			m.logger.Printf("[tunnel] stale key on %s: replacing %s with %s",
				allowedIP, existingKey[:8]+"...", child.WireGuardPublicKey[:8]+"...")
			_, _ = m.db.ExecContext(ctx,
				`DELETE FROM tunnel_peers WHERE allowed_ip = ?`, allowedIP)
		}

		if _, err := m.AddPeer(ctx, child.WireGuardPublicKey, child.DeviceMAC, child.ChildID); err != nil {
			m.logger.Printf("[tunnel] auto-add peer child=%s: %v", child.ChildID, err)
		}
	}

	// Load all peers from DB
	peers, err := m.loadPeers(ctx)
	if err != nil {
		return fmt.Errorf("load peers: %w", err)
	}

	// Load interface config
	iface, err := m.loadInterfaceConfig(ctx)
	if err != nil {
		return fmt.Errorf("load interface config: %w", err)
	}

	// Write and apply
	if err := m.confWriter.Apply(iface, peers); err != nil {
		return fmt.Errorf("apply wg conf: %w", err)
	}

	m.logger.Printf("[tunnel] synced peers=%d", len(peers))
	return nil
}

// checkHealth reads wg show dump and emits stale peer events.
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

// allocateIP finds the next free .x address in TunnelSubnet.
func (m *Manager) allocateIP(ctx context.Context) (string, error) {
	_, subnet, err := net.ParseCIDR(TunnelSubnet)
	if err != nil {
		return "", fmt.Errorf("parse subnet: %w", err)
	}

	// Collect used IPs
	rows, err := m.db.QueryContext(ctx, `SELECT allowed_ip FROM tunnel_peers`)
	if err != nil {
		return "", fmt.Errorf("query peers: %w", err)
	}
	defer rows.Close()

	used := map[string]bool{TunnelGateway: true} // gateway is reserved
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

	// Walk .2 → .254
	base := subnet.IP.To4()
	for i := 2; i <= 254; i++ {
		candidate := fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], i)
		if !used[candidate] {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("tunnel subnet exhausted")
}

// loadPeers reads all peers from tunnel_peers table.
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

// loadInterfaceConfig reads the node's WireGuard private key and builds
// the [Interface] section.
func (m *Manager) loadInterfaceConfig(ctx context.Context) (InterfaceConfig, error) {
	var privKey string
	_ = m.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'private_key'`,
	).Scan(&privKey)

	if privKey == "" {
		privKey = "PLACEHOLDER_REPLACE_WITH_WG_GENKEY_OUTPUT="
	}

	return InterfaceConfig{
		PrivateKey: privKey,
		ListenPort: DefaultListenPort,
		Address:    TunnelGatewayCIDR,
	}, nil
}

// ensureSchema creates the tunnel_peers and tunnel_config tables if needed.
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
