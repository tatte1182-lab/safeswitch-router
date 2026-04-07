package controlsync

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// tunnelPeerStat holds parsed stats for a single WireGuard peer.
type tunnelPeerStat struct {
	PublicKey         string `json:"public_key"`
	LastHandshakeUnix int64  `json:"last_handshake_unix"`
	BytesTx           int64  `json:"bytes_tx"`
	BytesRx           int64  `json:"bytes_rx"`
	Connected         bool   `json:"connected"`
}

// syncTunnelStatsPayload is the request body for the sync-tunnel-stats Edge Function.
type syncTunnelStatsPayload struct {
	NodeID string           `json:"node_id"`
	Peers  []tunnelPeerStat `json:"peers"`
}

// syncTunnelStats parses `wg show wg0 dump` and posts peer stats to Supabase.
// Called once per heartbeat cycle. Errors are logged but never fatal.
func (s *Service) syncTunnelStats(ctx context.Context) {
	peers, err := parseWGDump(ctx)
	if err != nil {
		s.logger.Printf("[controlsync] tunnel stats: wg dump failed: %v", err)
		return
	}
	if len(peers) == 0 {
		s.logger.Printf("[controlsync] tunnel stats: no peers in wg0")
		return
	}

	id := s.identity.Current()
	payload := syncTunnelStatsPayload{
		NodeID: id.NodeID,
		Peers:  peers,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		s.logger.Printf("[controlsync] tunnel stats: marshal failed: %v", err)
		return
	}

	_, status, err := s.client.post(ctx, "/functions/v1/sync-tunnel-stats", raw)
	if err != nil || status >= 400 {
		s.logger.Printf("[controlsync] tunnel stats: post failed status=%d: %v", status, err)
		return
	}

	connected := 0
	for _, p := range peers {
		if p.Connected {
			connected++
		}
	}
	s.logger.Printf("[controlsync] tunnel stats: synced peers=%d connected=%d", len(peers), connected)
}

// parseWGDump runs `wg show wg0 dump` and returns one stat per peer.
// Output format (tab-separated, one peer per line after the interface line):
//
//	public_key  preshared_key  endpoint  allowed_ips  last_handshake  bytes_rx  bytes_tx  keepalive
func parseWGDump(ctx context.Context) ([]tunnelPeerStat, error) {
	out, err := exec.CommandContext(ctx, "wg", "show", "wg0", "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show wg0 dump: %w", err)
	}

	var peers []tunnelPeerStat
	scanner := bufio.NewScanner(bytes.NewReader(out))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			// First line is the interface itself — skip it.
			continue
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}

		pubKey := fields[0]
		// fields[1] = preshared_key
		// fields[2] = endpoint
		// fields[3] = allowed_ips
		handshakeUnix, _ := strconv.ParseInt(fields[4], 10, 64)
		bytesRx, _        := strconv.ParseInt(fields[5], 10, 64)
		bytesTx, _        := strconv.ParseInt(fields[6], 10, 64)

		// A peer is considered connected if it had a handshake within 3 minutes.
		connected := false
		if handshakeUnix > 0 {
			age := time.Now().Unix() - handshakeUnix
			connected = age < 180
		}

		peers = append(peers, tunnelPeerStat{
			PublicKey:         pubKey,
			LastHandshakeUnix: handshakeUnix,
			BytesTx:           bytesTx,
			BytesRx:           bytesRx,
			Connected:         connected,
		})
	}
	return peers, scanner.Err()
}
