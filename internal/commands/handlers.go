package commands

import (
	"context"
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
}

// RegisterHandlers wires all built-in command handlers into the executor.
// Any dependency may be nil — its commands become logged no-ops until wired.
func RegisterHandlers(e *Executor, policy PolicySwapper, dnsServer DNSReloader, tunnelMgr TunnelManager, fw FirewallEnforcer, logger Logger) {
	e.Register("ping",               makePingHandler(logger))
	e.Register("pause_device",       makePauseDeviceHandler(fw, logger))
	e.Register("unpause_device",     makeUnpauseDeviceHandler(fw, logger))
	e.Register("update_policy",      makeUpdatePolicyHandler(policy, logger))
	e.Register("set_route_profile",  makeSetRouteProfileHandler(logger))
	e.Register("reload_dns_profile", makeReloadDNSProfileHandler(dnsServer, logger))
	e.Register("add_peer",           makeAddPeerHandler(tunnelMgr, logger))
	e.Register("remove_peer",        makeRemovePeerHandler(tunnelMgr, logger))
	e.Register("restart",            makeRestartHandler(logger))
}

// ── ping ─────────────────────────────────────────────────────────────────────
// Simplest possible command. Used by Supabase to verify the command pipeline
// is live end-to-end without side effects.

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
// Payload: {"device_mac": "aa:bb:cc:dd:ee:ff"}
// Phase R2: writes the pause state to policy cache. Phase R5 (firewall enforcer)
// will add the actual iptables DROP rule on top of this.

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
// Payload: full policy bundle JSON matching policybundle.Bundle schema.
// Swaps the active bundle atomically — triggers policy runtime to recompute
// child effective states. R5 will chain firewall sync onto this.

func makeUpdatePolicyHandler(policy PolicySwapper, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		// Extract required fields from the raw payload map
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

		// Parse children array
		var children []policybundle.ChildEffectiveState
		if raw, ok := payload["children"]; ok {
			if arr, ok := raw.([]any); ok {
				for _, item := range arr {
					if m, ok := item.(map[string]any); ok {
						child := policybundle.ChildEffectiveState{
							ChildID:      stringVal(m, "child_id"),
							DeviceMAC:    stringVal(m, "device_mac"),
							Mode:         stringVal(m, "mode"),
							LockEnabled:  boolVal(m, "lock_enabled"),
							DNSProfileID: stringVal(m, "dns_profile_id"),
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

		logger.Printf("[cmd:update_policy] bundle swapped version=%s children=%d",
			version, len(children))

		return map[string]any{
			"version":  version,
			"children": len(children),
		}, nil
	}
}

// ── set_route_profile ─────────────────────────────────────────────────────────
// Payload: {"profile": "full_tunnel" | "split_tunnel" | "service_only", "device_mac": "..."}
// R2: logs and stores intent. R4 (tunnel manager) will apply the actual
// ip rule / ip route changes when it comes online.

func makeSetRouteProfileHandler(logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		profile, err := requireString(payload, "profile")
		if err != nil {
			return nil, err
		}

		validProfiles := map[string]bool{
			"full_tunnel":   true,
			"split_tunnel":  true,
			"service_only":  true,
		}
		if !validProfiles[profile] {
			return nil, fmt.Errorf("unknown profile %q: must be full_tunnel, split_tunnel, or service_only", profile)
		}

		mac := stringVal(payload, "device_mac") // optional — empty means all devices
		logger.Printf("[cmd:set_route_profile] profile=%s mac=%q", profile, mac)

		// R4 hook: tunnel manager will intercept here and apply ip rule changes.
		return map[string]any{
			"profile": profile,
			"mac":     mac,
			"applied": false, // true once R4 tunnel manager is wired
		}, nil
	}
}

// ── reload_dns_profile ────────────────────────────────────────────────────────
// Payload: {} — no parameters needed; re-reads dns_blocklist from DB.
// Sent by Supabase after pushing a new threat feed to the router's DB.

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
// Payload: {"public_key": "<base64>", "device_mac": "aa:bb:cc:dd:ee:ff", "comment": "optional"}
// Adds a WireGuard peer, allocates a tunnel IP, and resyncs wg0.conf.

func makeAddPeerHandler(mgr TunnelManager, logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		if mgr == nil {
			return map[string]any{"added": false, "reason": "tunnel_manager_not_running"}, nil
		}
		pubKey, err := requireString(payload, "public_key")
		if err != nil {
			return nil, err
		}
		mac     := stringVal(payload, "device_mac")
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
// Payload: {"public_key": "<base64>"}
// Removes a WireGuard peer and resyncs wg0.conf.

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
		return map[string]any{
			"public_key": pubKey,
			"removed":    true,
		}, nil
	}
}

// ── restart ───────────────────────────────────────────────────────────────────
// Payload: {} (no parameters needed)
// Exits cleanly — procd/systemd restarts the binary automatically.
// Used for OTA updates (R6) and remote recovery.

func makeRestartHandler(logger Logger) Handler {
	return func(ctx context.Context, payload map[string]any) (map[string]any, error) {
		logger.Printf("[cmd:restart] restarting process")
		// Give the executor time to write the done status before we exit
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
