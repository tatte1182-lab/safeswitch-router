package commands

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	policybundle "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

// PolicySwapper is the subset of policy.Runtime the handlers need.
type PolicySwapper interface {
	SwapBundle(ctx context.Context, b *policybundle.Bundle) error
}

// DNSReloader is the subset of dns.Server the handlers need.
type DNSReloader interface {
	Reload(ctx context.Context) error
}

// TunnelManager is the subset of tunnel.Manager the handlers need.
type TunnelManager interface {
	AddPeer(ctx context.Context, publicKey, deviceMAC, comment string) (string, error)
	RemovePeer(ctx context.Context, publicKey string) error
}

// FirewallEnforcer is the subset of firewall.Enforcer the handlers need.
type FirewallEnforcer interface {
	PauseDevice(ctx context.Context, mac string) error
	UnpauseDevice(ctx context.Context, mac string) error
	SyncFromBundle(ctx context.Context) error
}

// RouteProfileStore persists route profile intent per device.
type RouteProfileStore interface {
	SetRouteProfile(ctx context.Context, mac, profile, source string) error
}

// RegisterHandlers wires all built-in command handlers into the executor.
func RegisterHandlers(e *Executor, policy PolicySwapper, dnsServer DNSReloader, tunnelMgr TunnelManager, fw FirewallEnforcer, rps RouteProfileStore, logger Logger) {
	e.Register("ping", makePingHandler(logger))
	e.Register("pause_device", makePauseDeviceHandler(fw, logger))
	e.Register("unpause_device", makeUnpauseDeviceHandler(fw, logger))
	e.Register("update_policy", makeUpdatePolicyHandler(policy, logger))
	e.Register("set_route_profile", makeSetRouteProfileHandler(fw, rps, logger))
	e.Register("reload_dns_profile", makeReloadDNSProfileHandler(dnsServer, logger))
	e.Register("add_peer", makeAddPeerHandler(tunnelMgr, logger))
	e.Register("remove_peer", makeRemovePeerHandler(tunnelMgr, logger))
	e.Register("restart", makeRestartHandler(logger))
}

// ── ping ─────────────────────────────────────────────────────────────────────

func makePingHandler(logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		logger.Printf("[cmd:ping] pong")
		return map[string]any{
			"pong":      true,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}, nil
	}
}

// ── pause_device ──────────────────────────────────────────────────────────────

func makePauseDeviceHandler(fw FirewallEnforcer, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		mac, err := requireString(payload, "device_mac")
		if err != nil {
			return nil, err
		}
		if fw == nil {
			logger.Printf("[cmd:pause_device] firewall not running — recorded only mac=%s", mac)
			return map[string]any{"mac": mac, "paused": true, "enforced": false}, nil
		}
		if err := fw.PauseDevice(ctx, mac); err != nil {
			return nil, fmt.Errorf("pause_device: %w", err)
		}
		logger.Printf("[cmd:pause_device] enforced mac=%s", mac)
		return map[string]any{"mac": mac, "paused": true, "enforced": true}, nil
	}
}

func makeUnpauseDeviceHandler(fw FirewallEnforcer, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		mac, err := requireString(payload, "device_mac")
		if err != nil {
			return nil, err
		}
		if fw == nil {
			logger.Printf("[cmd:unpause_device] firewall not running — recorded only mac=%s", mac)
			return map[string]any{"mac": mac, "paused": false, "enforced": false}, nil
		}
		if err := fw.UnpauseDevice(ctx, mac); err != nil {
			return nil, fmt.Errorf("unpause_device: %w", err)
		}
		logger.Printf("[cmd:unpause_device] enforced mac=%s", mac)
		return map[string]any{"mac": mac, "paused": false, "enforced": true}, nil
	}
}

// ── update_policy ─────────────────────────────────────────────────────────────

func makeUpdatePolicyHandler(policy PolicySwapper, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		version, err := requireString(payload, "version")
		if err != nil {
			return nil, err
		}
		issuedAtStr, err := requireString(payload, "issued_at")
		if err != nil {
			return nil, err
		}
		issuedAt, err := time.Parse(time.RFC3339, issuedAtStr)
		if err != nil {
			return nil, fmt.Errorf("invalid issued_at: %w", err)
		}
		expiresAtStr, err := requireString(payload, "expires_at")
		if err != nil {
			return nil, err
		}
		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at: %w", err)
		}
		signature, _ := payload["signature"].(string)

		var children []policybundle.ChildEffectiveState
		if raw, ok := payload["children"]; ok {
			if arr, ok := raw.([]any); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						child := policybundle.ChildEffectiveState{
							ChildID:            stringVal(m, "child_id"),
							DeviceMAC:          stringVal(m, "device_mac"),
							WireGuardPublicKey: stringVal(m, "wireguard_public_key"),
							WireguardIP:        stringVal(m, "wireguard_ip"),
							Mode:               stringVal(m, "mode"),
							LockEnabled:        boolVal(m, "lock_enabled"),
							DNSProfileID:       stringVal(m, "dns_profile_id"),
						}
						children = append(children, child)
					}
				}
			}
		}

		bundle := &policybundle.Bundle{
			Version:   version,
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
			Signature: signature,
			Children:  children,
		}

		if err := policy.SwapBundle(ctx, bundle); err != nil {
			return nil, fmt.Errorf("swap bundle: %w", err)
		}
		logger.Printf("[cmd:update_policy] bundle swapped version=%s children=%d", version, len(children))
		return map[string]any{"version": version, "children": len(children)}, nil
	}
}

// ── set_route_profile ─────────────────────────────────────────────────────────
// Payload: {"profile": "full_tunnel|split_tunnel|service_only", "device_mac": "aa:bb:cc:dd:ee:ff"}
//
// Enforcement model: A-first, B-assisted.
//
//  A (mandatory): persists intent to device_route_profiles, triggers firewall
//     resync so egress rules are updated immediately regardless of client state.
//
//  B (best-effort): records client_applied=false so the command dispatcher can
//     push a cooperative update to the child app on next poll. The child app
//     reconfigures its WireGuard AllowedIPs for cleaner routing, but this is
//     not relied upon for security.

func makeSetRouteProfileHandler(fw FirewallEnforcer, rps RouteProfileStore, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		profile, err := requireString(payload, "profile")
		if err != nil {
			return nil, err
		}
		validProfiles := map[string]bool{
			"full_tunnel":  true,
			"split_tunnel": true,
			"service_only": true,
		}
		if !validProfiles[profile] {
			return nil, fmt.Errorf("unknown profile %q: must be full_tunnel, split_tunnel, or service_only", profile)
		}

		mac, err := requireString(payload, "device_mac")
		if err != nil {
			return nil, err
		}
		source := stringVal(payload, "source")
		if source == "" {
			source = "guardian"
		}

		// Option A — persist intent and enforce immediately at the node.
		enforced := false
		if rps != nil {
			if err := rps.SetRouteProfile(ctx, mac, profile, source); err != nil {
				logger.Printf("[cmd:set_route_profile] store failed mac=%s: %v", mac, err)
			} else {
				logger.Printf("[cmd:set_route_profile] intent stored mac=%s profile=%s source=%s", mac, profile, source)
				// Trigger immediate firewall resync so egress rules reflect new profile.
				if fw != nil {
					if err := fw.SyncFromBundle(ctx); err != nil {
						logger.Printf("[cmd:set_route_profile] firewall sync warning: %v", err)
					} else {
						enforced = true
					}
				}
			}
		}

		// Option B — mark client_applied=false so dispatcher can push cooperative
		// update to child app. The dispatcher will send a set_route_profile command
		// to the device, which updates its WireGuard AllowedIPs client-side.
		// This is best-effort only — enforcement does not depend on it.
		logger.Printf("[cmd:set_route_profile] applied mac=%s profile=%s enforced=%v client_sync=pending", mac, profile, enforced)

		return map[string]any{
			"mac":           mac,
			"profile":       profile,
			"source":        source,
			"enforced":      enforced,
			"client_synced": false, // updated to true when child app acks cooperative update
		}, nil
	}
}

// ── reload_dns_profile ────────────────────────────────────────────────────────

func makeReloadDNSProfileHandler(dns DNSReloader, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		if dns == nil {
			logger.Printf("[cmd:reload_dns_profile] dns server not running — skipping")
			return map[string]any{"reloaded": false, "reason": "dns_server_not_running"}, nil
		}
		if err := dns.Reload(ctx); err != nil {
			return nil, fmt.Errorf("dns reload: %w", err)
		}
		logger.Printf("[cmd:reload_dns_profile] blocklist reloaded")
		return map[string]any{"reloaded": true}, nil
	}
}

// ── add_peer ──────────────────────────────────────────────────────────────────

func makeAddPeerHandler(mgr TunnelManager, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		if mgr == nil {
			return map[string]any{"added": false, "reason": "tunnel_manager_not_running"}, nil
		}
		pubKey, err := requireString(payload, "public_key")
		if err != nil {
			return nil, err
		}
		mac := stringVal(payload, "device_mac")
		comment := stringVal(payload, "comment")

		allowedIP, err := mgr.AddPeer(ctx, pubKey, mac, comment)
		if err != nil {
			return nil, fmt.Errorf("add_peer: %w", err)
		}
		logger.Printf("[cmd:add_peer] key=%s ip=%s mac=%s", pubKey[:8]+"...", allowedIP, mac)
		return map[string]any{
			"public_key": pubKey,
			"allowed_ip": allowedIP,
			"added":      true,
		}, nil
	}
}

// ── remove_peer ───────────────────────────────────────────────────────────────

func makeRemovePeerHandler(mgr TunnelManager, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		if mgr == nil {
			return map[string]any{"removed": false, "reason": "tunnel_manager_not_running"}, nil
		}
		pubKey, err := requireString(payload, "public_key")
		if err != nil {
			return nil, err
		}
		if err := mgr.RemovePeer(ctx, pubKey); err != nil {
			return nil, fmt.Errorf("remove_peer: %w", err)
		}
		logger.Printf("[cmd:remove_peer] key=%s", pubKey[:8]+"...")
		return map[string]any{"public_key": pubKey, "removed": true}, nil
	}
}

// ── restart ───────────────────────────────────────────────────────────────────

func makeRestartHandler(logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		logger.Printf("[cmd:restart] restarting process")
		go func() {
			time.Sleep(500 * time.Millisecond)
			os.Exit(0)
		}()
		return map[string]any{"restarting": true}, nil
	}
}

// ── payload helpers ───────────────────────────────────────────────────────────

func requireString(payload map[string]any, key string) (string, error) {
	v, ok := payload[key]
	if !ok {
		return "", fmt.Errorf("missing required field %q", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("field %q must be a string", key)
	}
	if s == "" {
		return "", fmt.Errorf("field %q cannot be empty", key)
	}
	return s, nil
}

func stringVal(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func boolVal(m map[string]any, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// DB-backed RouteProfileStore — used by the firewall enforcer and wiring.
type DBRouteProfileStore struct {
	db *sql.DB
}

func NewDBRouteProfileStore(db *sql.DB) *DBRouteProfileStore {
	return &DBRouteProfileStore{db: db}
}

func (s *DBRouteProfileStore) SetRouteProfile(ctx context.Context, mac, profile, source string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO device_route_profiles (mac, route_profile, route_profile_source, client_applied, updated_at)
		VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP)
		ON CONFLICT(mac) DO UPDATE SET
			route_profile        = excluded.route_profile,
			route_profile_source = excluded.route_profile_source,
			route_profile_version = route_profile_version + 1,
			client_applied       = 0,
			updated_at           = CURRENT_TIMESTAMP
	`, mac, profile, source)
	return err
}

func (s *DBRouteProfileStore) RouteProfileForKey(ctx context.Context, publicKey string) string {
	if publicKey == "" {
		return ""
	}
	var profile string
	_ = s.db.QueryRowContext(ctx,
		`SELECT route_profile FROM device_route_profiles WHERE public_key = ? ORDER BY rowid DESC LIMIT 1`,
		publicKey,
	).Scan(&profile)
	return profile
}

func (s *DBRouteProfileStore) RouteProfileForMAC(ctx context.Context, mac string) string {
	var profile string
	_ = s.db.QueryRowContext(ctx,
		`SELECT route_profile FROM device_route_profiles WHERE mac = ?`, mac,
	).Scan(&profile)
	if profile == "" {
		return "split_tunnel" // safe default
	}
	return profile
}
