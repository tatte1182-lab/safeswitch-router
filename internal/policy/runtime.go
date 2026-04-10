package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	contract "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

type Logger interface{ Printf(format string, v ...any) }

type Runtime struct {
	db     *sql.DB
	logger Logger
	mu     sync.RWMutex
	active *contract.Bundle
	onSwap func(ctx context.Context)
}

func NewRuntime(db *sql.DB, logger Logger) *Runtime { return &Runtime{db: db, logger: logger} }

func (r *Runtime) SetOnSwap(fn func(ctx context.Context)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onSwap = fn
}

func (r *Runtime) Name() string                     { return "policy-runtime" }
func (r *Runtime) Stop(ctx context.Context) error   { return nil }
func (r *Runtime) Health(ctx context.Context) error { return nil }

func (r *Runtime) Start(ctx context.Context) error {
	if err := r.loadActive(ctx); err != nil {
		return err
	}
	r.logger.Printf("[policy] runtime ready")
	return nil
}

func (r *Runtime) ActiveBundle(ctx context.Context) (*contract.Bundle, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return nil, fmt.Errorf("no active bundle")
	}
	copied := *r.active
	return &copied, nil
}

func (r *Runtime) SwapBundle(ctx context.Context, b *contract.Bundle) error {
	if b == nil {
		return fmt.Errorf("bundle cannot be nil")
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("marshal bundle: %w", err)
	}
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO active_policy_bundle (id, version, issued_at, expires_at, signature, payload_json, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET version=excluded.version, issued_at=excluded.issued_at,
		expires_at=excluded.expires_at, signature=excluded.signature,
		payload_json=excluded.payload_json, updated_at=CURRENT_TIMESTAMP`,
		b.Version, b.IssuedAt.Format(time.RFC3339), b.ExpiresAt.Format(time.RFC3339), b.Signature, string(raw))
	if err != nil {
		return fmt.Errorf("upsert bundle: %w", err)
	}
	r.mu.Lock()
	r.active = b
	cb := r.onSwap
	r.mu.Unlock()
	r.logger.Printf("[policy] swapped bundle version=%s", b.Version)
	if cb != nil {
		cb(ctx)
	}
	return nil
}

// DNSProfileForMAC returns the dns_profile_id for the child whose enrolled
// device MAC matches. Returns "default" when no match is found or no bundle loaded.
func (r *Runtime) DNSProfileForMAC(mac string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return "default"
	}
	for _, child := range r.active.Children {
		if child.DeviceMAC == mac {
			if child.DNSProfileID != "" {
				return child.DNSProfileID
			}
			return "default"
		}
	}
	return "default"
}

// BlockedCategoriesForIP returns the blocked DNS categories for the child device
// with the given WireGuard tunnel IP. Returns nil when no bundle is loaded or the
// IP is not found — the resolver treats nil as no extra category blocking.
// In-memory only, safe to call on the hot DNS path.
func (r *Runtime) BlockedCategoriesForIP(ip string) []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return nil
	}
	cleanIP := strings.TrimSuffix(ip, "/32")
	for _, child := range r.active.Children {
		childIP := strings.TrimSuffix(child.WireguardIP, "/32")
		if childIP == cleanIP {
			return child.BlockedCategories
		}
	}
	return nil
}

// InternetPausedForIP returns true when the policy engine has marked the
// device with the given tunnel IP as paused (internet blocked).
func (r *Runtime) InternetPausedForIP(ip string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return false
	}
	cleanIP := strings.TrimSuffix(ip, "/32")
	for _, child := range r.active.Children {
		childIP := strings.TrimSuffix(child.WireguardIP, "/32")
		if childIP == cleanIP {
			return child.LockEnabled || child.Mode == "paused"
		}
	}
	return false
}

// EnrolledMACs returns a set of device MACs present in the active policy bundle.
func (r *Runtime) EnrolledMACs(ctx context.Context) map[string]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]bool)
	if r.active == nil {
		return result
	}
	for _, child := range r.active.Children {
		if child.DeviceMAC != "" {
			result[child.DeviceMAC] = true
		}
	}
	return result
}

func (r *Runtime) loadActive(ctx context.Context) error {
	var raw string
	err := r.db.QueryRowContext(ctx, `SELECT payload_json FROM active_policy_bundle WHERE id = 1`).Scan(&raw)
	if err == sql.ErrNoRows {
		r.logger.Printf("[policy] no active bundle yet")
		return nil
	}
	if err != nil {
		return fmt.Errorf("query active bundle: %w", err)
	}
	var b contract.Bundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return fmt.Errorf("unmarshal active bundle: %w", err)
	}
	r.mu.Lock()
	r.active = &b
	r.mu.Unlock()
	r.logger.Printf("[policy] loaded active bundle version=%s", b.Version)
	return nil
}
