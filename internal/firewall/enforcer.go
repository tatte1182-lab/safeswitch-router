package firewall

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	policybundle "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

// Logger is the minimal logging interface the enforcer needs.
type Logger interface {
	Printf(format string, v ...any)
}

// PolicyReader is the subset of policy.Runtime the enforcer needs.
type PolicyReader interface {
	ActiveBundle(ctx context.Context) (*policybundle.Bundle, error)
}

// TunnelIPReader maps a device MAC to its current tunnel IP.
type TunnelIPReader interface {
	TunnelIPForMAC(ctx context.Context, mac string) string
}

// RouteProfileReader returns the stored route profile for a device MAC.
// Returns "split_tunnel" when no profile is set (safe default).
type RouteProfileReader interface {
	RouteProfileForMAC(ctx context.Context, mac string) string
}

// Enforcer manages the SAFESWITCH iptables chain.
//
// Enforcement model: A-first (node authority), B-assisted (client cooperation).
//
// On every Sync() call it:
//  1. Flushes the SAFESWITCH chain
//  2. Re-reads the active policy bundle
//  3. For each child device, resolves effective state from:
//     - pause_overrides (highest priority — immediate command)
//     - device_route_profiles (guardian-set route intent)
//     - policy bundle lock_enabled / mode (scheduled / agreement state)
//  4. Rebuilds iptables rules accordingly
//
// This means full_tunnel enforcement fires at the node even if the child
// app has not yet reconfigured its WireGuard AllowedIPs client-side.
type Enforcer struct {
	db           *sql.DB
	logger       Logger
	policy       PolicyReader
	tunnel       TunnelIPReader
	routeProfile RouteProfileReader
	devMode      bool

	mu sync.Mutex
}

// NewEnforcer constructs the Enforcer.
func NewEnforcer(
	db *sql.DB,
	logger Logger,
	policy PolicyReader,
	tunnel TunnelIPReader,
	routeProfile RouteProfileReader,
	devMode bool,
) *Enforcer {
	return &Enforcer{
		db:           db,
		logger:       logger,
		policy:       policy,
		tunnel:       tunnel,
		routeProfile: routeProfile,
		devMode:      devMode,
	}
}

func (e *Enforcer) Name() string { return "firewall-enforcer" }

func (e *Enforcer) Start(ctx context.Context) error {
	if err := e.ensureSchema(ctx); err != nil {
		return err
	}
	if err := e.ensureChain(); err != nil {
		e.logger.Printf("[firewall] chain setup warning: %v", err)
	}
	if err := e.Sync(ctx); err != nil {
		e.logger.Printf("[firewall] initial sync warning: %v", err)
	}
	e.logger.Printf("[firewall] enforcer started devMode=%v", e.devMode)
	return nil
}

func (e *Enforcer) Stop(ctx context.Context) error  { return nil }
func (e *Enforcer) Health(ctx context.Context) error { return nil }

// Sync rebuilds the entire SAFESWITCH chain from current state.
// Idempotent — flush then reapply. Called on bundle swap, pause/unpause,
// and set_route_profile commands.
func (e *Enforcer) Sync(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.ipt(ChainFlushArgs()...); err != nil {
		e.logger.Printf("[firewall] flush warning: %v", err)
	}

	bundle, err := e.policy.ActiveBundle(ctx)
	if err != nil {
		return nil // no bundle yet
	}

	applied := 0
	for _, child := range bundle.Children {
		if child.DeviceMAC == "" {
			continue
		}

		ip := e.tunnel.TunnelIPForMAC(ctx, child.DeviceMAC)
		if ip == "" {
			e.logger.Printf("[firewall] no tunnel IP for mac=%s child=%s — skipping",
				child.DeviceMAC, child.ChildID)
			continue
		}

		state := e.resolveState(ctx, child)
		rs := BuildRules(ip, state)

		for _, rule := range rs.Rules {
			if err := e.ipt(rule.Args...); err != nil {
				e.logger.Printf("[firewall] rule failed (%s): %v", rule.Comment, err)
				continue
			}
			e.logger.Printf("[firewall] rule applied: %s", rule.Comment)
		}
		applied++
	}

	e.logger.Printf("[firewall] sync complete children=%d applied=%d", len(bundle.Children), applied)
	return nil
}

// PauseDevice immediately pauses a device by MAC address.
func (e *Enforcer) PauseDevice(ctx context.Context, mac string) error {
	if err := e.setPauseOverride(ctx, mac, true); err != nil {
		return err
	}
	e.logger.Printf("[firewall] pause_device mac=%s", mac)
	return e.Sync(ctx)
}

// UnpauseDevice removes the pause override and resyncs.
func (e *Enforcer) UnpauseDevice(ctx context.Context, mac string) error {
	if err := e.setPauseOverride(ctx, mac, false); err != nil {
		return err
	}
	e.logger.Printf("[firewall] unpause_device mac=%s", mac)
	return e.Sync(ctx)
}

// resolveState determines effective enforcement state for a child device.
//
// Priority order (highest to lowest):
//  1. pause_overrides — immediate command from guardian (always wins)
//  2. device_route_profiles — guardian-set route profile (full_tunnel, service_only)
//  3. policy bundle lock_enabled — scheduled or agreement lock
//  4. policy bundle mode — default routing mode
func (e *Enforcer) resolveState(ctx context.Context, child policybundle.ChildEffectiveState) string {
	// 1. Check immediate pause override
	var paused int
	_ = e.db.QueryRowContext(ctx,
		`SELECT paused FROM pause_overrides WHERE mac = ?`, child.DeviceMAC,
	).Scan(&paused)
	if paused == 1 {
		return StatePaused
	}

	// 2. Check guardian-set route profile (Option A enforcement)
	if e.routeProfile != nil {
		profile := e.routeProfile.RouteProfileForMAC(ctx, child.DeviceMAC)
		switch profile {
		case "full_tunnel":
			// Full tunnel — device must route all traffic through the node.
			// Drop any traffic that isn't arriving via wg0 (enforced at FORWARD level).
			// The child app is also asked cooperatively to set AllowedIPs=0.0.0.0/0.
			return StateFullTunnel
		case "service_only":
			return StateServiceOnly
		// split_tunnel falls through to policy bundle
		}
	}

	// 3. Policy bundle lock
	if child.LockEnabled {
		return StatePaused
	}

	// 4. Policy bundle mode
	switch child.Mode {
	case "service_only":
		return StateServiceOnly
	default:
		return StateFullAccess
	}
}

func (e *Enforcer) setPauseOverride(ctx context.Context, mac string, paused bool) error {
	p := 0
	if paused {
		p = 1
	}
	_, err := e.db.ExecContext(ctx, `
		INSERT INTO pause_overrides (mac, paused, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(mac) DO UPDATE SET paused = excluded.paused, updated_at = CURRENT_TIMESTAMP
	`, mac, p)
	if err != nil {
		return fmt.Errorf("set pause override: %w", err)
	}
	return nil
}

func (e *Enforcer) ensureChain() error {
	for _, args := range ChainEnsureArgs() {
		_ = e.ipt(args...)
	}
	return nil
}

func (e *Enforcer) ipt(args ...string) error {
	if e.devMode {
		e.logger.Printf("[firewall:dry-run] iptables %s", strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %s: %w (output: %s)",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *Enforcer) ensureSchema(ctx context.Context) error {
	_, err := e.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS pause_overrides (
			mac        TEXT PRIMARY KEY,
			paused     INTEGER NOT NULL DEFAULT 0,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return fmt.Errorf("pause_overrides schema: %w", err)
	}
	return nil
}
