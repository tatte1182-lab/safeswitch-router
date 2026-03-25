package tunnel

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// PeerHealth holds the live health metrics for one WireGuard peer.
type PeerHealth struct {
	PublicKey     string
	Endpoint      string
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
	// Stale is true when no handshake has been seen in the last 3 minutes.
	Stale         bool
}

// PeerHealthSnapshot is the full health state of all peers at a point in time.
type PeerHealthSnapshot struct {
	Interface string
	ListenPort int
	PeerCount  int
	Peers      []PeerHealth
	CapturedAt time.Time
}

// ReadHealth runs `wg show wg0 dump` and parses the output.
// Returns an empty snapshot (not an error) when WireGuard is not available —
// the caller treats this as "not yet running" in dev mode.
func ReadHealth(devMode bool) (*PeerHealthSnapshot, error) {
	if devMode {
		return &PeerHealthSnapshot{
			Interface:  wgInterface,
			ListenPort: 51820,
			CapturedAt: time.Now().UTC(),
		}, nil
	}

	out, err := exec.Command("wg", "show", wgInterface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show dump: %w", err)
	}

	return parseDump(string(out))
}

// parseDump parses the tab-separated output of `wg show <iface> dump`.
//
// First line (interface):
//
//	private_key  public_key  listen_port  fwmark
//
// Subsequent lines (peers):
//
//	public_key  preshared_key  endpoint  allowed_ips  latest_handshake  rx_bytes  tx_bytes  persistent_keepalive
func parseDump(dump string) (*PeerHealthSnapshot, error) {
	snap := &PeerHealthSnapshot{
		Interface:  wgInterface,
		CapturedAt: time.Now().UTC(),
	}

	lines := strings.Split(strings.TrimSpace(dump), "\n")
	if len(lines) == 0 {
		return snap, nil
	}

	// Parse interface line
	ifFields := strings.Split(lines[0], "\t")
	if len(ifFields) >= 3 {
		port, _ := strconv.Atoi(ifFields[2])
		snap.ListenPort = port
	}

	// Parse peer lines
	staleThreshold := 3 * time.Minute
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}

		ph := PeerHealth{
			PublicKey: fields[0],
			Endpoint:  fields[2],
		}

		// last handshake is a unix timestamp (0 = never)
		if ts, err := strconv.ParseInt(fields[4], 10, 64); err == nil && ts > 0 {
			ph.LastHandshake = time.Unix(ts, 0)
			ph.Stale = time.Since(ph.LastHandshake) > staleThreshold
		} else {
			ph.Stale = true // never handshaked
		}

		ph.RxBytes, _ = strconv.ParseInt(fields[5], 10, 64)
		ph.TxBytes, _ = strconv.ParseInt(fields[6], 10, 64)

		snap.Peers = append(snap.Peers, ph)
	}

	snap.PeerCount = len(snap.Peers)
	return snap, nil
}

// StalePeers returns the subset of peers that have not completed a handshake
// within the stale threshold. Used by the manager to emit events.
func (s *PeerHealthSnapshot) StalePeers() []PeerHealth {
	var stale []PeerHealth
	for _, p := range s.Peers {
		if p.Stale {
			stale = append(stale, p)
		}
	}
	return stale
}

// Summary returns a compact string for logging.
func (s *PeerHealthSnapshot) Summary() string {
	staleCount := len(s.StalePeers())
	return fmt.Sprintf("peers=%d stale=%d port=%d", s.PeerCount, staleCount, s.ListenPort)
}

// ToMap serialises the snapshot for inclusion in heartbeat payloads.
func (s *PeerHealthSnapshot) ToMap() map[string]any {
	peers := make([]map[string]any, 0, len(s.Peers))
	for _, p := range s.Peers {
		m := map[string]any{
			"public_key":     p.PublicKey,
			"endpoint":       p.Endpoint,
			"rx_bytes":       p.RxBytes,
			"tx_bytes":       p.TxBytes,
			"stale":          p.Stale,
		}
		if !p.LastHandshake.IsZero() {
			m["last_handshake"] = p.LastHandshake.Format(time.RFC3339)
		}
		peers = append(peers, m)
	}
	return map[string]any{
		"interface":   s.Interface,
		"listen_port": s.ListenPort,
		"peer_count":  s.PeerCount,
		"peers":       peers,
		"captured_at": s.CapturedAt.Format(time.RFC3339),
	}
}

// TunnelHealth is the interface used by the API handler.
type TunnelHealth interface {
	LatestHealth(ctx context.Context) *PeerHealthSnapshot
}
