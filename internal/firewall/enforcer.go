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

// Enforcer manages the SAFESWITCH iptables chain.
//
// On every Sync() call it:
//  1. Flushes the SAFESWITCH chain
//  2. Re-reads the active policy bundle
//  3. Rebuilds rules for every child device based on their effective state
//
// Individual pause/unpause commands call Sync() after updating the local
// pause_state table so the chain reflects the new state immediately.
type Enforcer struct {
	db      *sql.DB
	logger  Logger
	policy  PolicyReader
	tunnel  TunnelIPReader
	devMode bool // true = log rules but skip iptables calls

	mu sync.Mutex // serialise all iptables operations
}

// NewEnforcer constructs the Enforcer. devMode=true logs rules without
// executing them — safe to run without root or iptables installed.
func NewEnforcer(
	db *sql.DB,
	logger Logger,
	policy PolicyReader,
	tunnel TunnelIPReader,
	devMode bool,
) *Enforcer {
	return &Enforcer{
		db:      db,
		logger:  logger,
		policy:  policy,
		tunnel:  tunnel,
		devMode: devMode,
	}
}

func (e *Enforcer) Name() string { return "firewall-enforcer" }

func (e *Enforcer) Start(ctx context.Context) error {
	if err := e.ensureSchema(ctx); err != nil {
		return err
	}
	if err := e.ensureChain(); err != nil {
		// Non-fatal — iptables may not be available on first boot
		e.logger.Printf("[firewall] chain setup warning: %v", err)
	}
	if err := e.Sync(ctx); err != nil {
		e.logger.Printf("[firewall] initial sync warning: %v", err)
	}
	e.logger.Printf("[firewall] enforcer started devMode=%v", e.devMode)
	return nil
}

func (e *Enforcer) Stop(ctx context.Context) error { return nil }
func (e *Enforcer) Health(ctx context.Context) error { return nil }

// Sync rebuilds the entire SAFESWITCH chain from the active policy bundle.
// Called on every bundle swap and after individual pause/unpause commands.
// Idempotent — flush then reapply.
func (e *Enforcer) Sync(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Flush existing rules
	if err := e.ipt(ChainFlushArgs()...); err != nil {
		e.logger.Printf("[firewall] flush warning: %v", err)
	}

	bundle, err := e.policy.ActiveBundle(ctx)
	if err != nil {
		// No bundle yet — nothing to enforce
		return nil
	}

	applied := 0
	for _, child := range bundle.Children {
		if child.DeviceMAC == "" {
			continue
		}

		// Get the tunnel IP for this device
		ip := e.tunnel.TunnelIPForMAC(ctx, child.DeviceMAC)
		if ip == "" {
			e.logger.Printf("[firewall] no tunnel IP for mac=%s child=%s — skipping",
				child.DeviceMAC, child.ChildID)
			continue
		}

		// Determine state: check pause_overrides first, then bundle lock state
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
// Records the pause in pause_overrides then calls Sync to apply the DROP rule.
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

// resolveState determines the enforcement state for a child.
// pause_overrides takes precedence over the bundle's lock_enabled flag.
func (e *Enforcer) resolveState(ctx context.Context, child policybundle.ChildEffectiveState) string {
	// Check local pause override first
	var paused int
	_ = e.db.QueryRowContext(ctx,
		`SELECT paused FROM pause_overrides WHERE mac = ?`, child.DeviceMAC,
	).Scan(&paused)
	if paused == 1 {
		return StatePaused
	}

	// Then check bundle lock
	if child.LockEnabled {
		return StatePaused
	}

	// Route profile from mode
	switch child.Mode {
	case "service_only":
		return StateServiceOnly
	default:
		return StateFullAccess
	}
}

// setPauseOverride writes or clears a pause override for a MAC.
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

// ensureChain creates the SAFESWITCH chain and installs the FORWARD jump.
func (e *Enforcer) ensureChain() error {
	for _, args := range ChainEnsureArgs() {
		// -N returns exit code 1 if chain already exists — that's fine
		_ = e.ipt(args...)
	}
	return nil
}

// ipt executes one iptables command. In devMode it logs instead of executing.
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

// ensureSchema creates the pause_overrides table.
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
