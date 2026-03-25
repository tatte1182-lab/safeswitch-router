package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	contract "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

type Logger interface { Printf(format string, v ...any) }

type Runtime struct {
	db     *sql.DB
	logger Logger
	mu     sync.RWMutex
	active *contract.Bundle
}

func NewRuntime(db *sql.DB, logger Logger) *Runtime { return &Runtime{db: db, logger: logger} }
func (r *Runtime) Name() string                     { return "policy-runtime" }
func (r *Runtime) Stop(ctx context.Context) error   { return nil }
func (r *Runtime) Health(ctx context.Context) error { return nil }

func (r *Runtime) Start(ctx context.Context) error {
	if err := r.loadActive(ctx); err != nil { return err }
	r.logger.Printf("[policy] runtime ready")
	return nil
}

func (r *Runtime) ActiveBundle(ctx context.Context) (*contract.Bundle, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil { return nil, fmt.Errorf("no active bundle") }
	copied := *r.active
	return &copied, nil
}

func (r *Runtime) SwapBundle(ctx context.Context, b *contract.Bundle) error {
	if b == nil { return fmt.Errorf("bundle cannot be nil") }
	raw, err := json.Marshal(b)
	if err != nil { return fmt.Errorf("marshal bundle: %w", err) }
	_, err = r.db.ExecContext(ctx, `
		INSERT INTO active_policy_bundle (id, version, issued_at, expires_at, signature, payload_json, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET version=excluded.version, issued_at=excluded.issued_at,
		expires_at=excluded.expires_at, signature=excluded.signature,
		payload_json=excluded.payload_json, updated_at=CURRENT_TIMESTAMP`,
		b.Version, b.IssuedAt.Format(time.RFC3339), b.ExpiresAt.Format(time.RFC3339), b.Signature, string(raw))
	if err != nil { return fmt.Errorf("upsert bundle: %w", err) }
	r.mu.Lock()
	r.active = b
	r.mu.Unlock()
	r.logger.Printf("[policy] swapped bundle version=%s", b.Version)
	return nil
}

// EnrolledMACs returns a set of device MACs present in the active policy bundle.
// The presence engine uses this to mark devices as enrolled without importing
// the full policy package.
// Returns an empty map (never nil) when no bundle is loaded.
func (r *Runtime) EnrolledMACs(ctx context.Context) map[string]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]bool)
	if r.active == nil {
		return result
	}
	for _, child := range r.active.Children {
		// ChildEffectiveState carries a DeviceMAC field.
		// We add it here; the field is populated when Supabase pushes a real bundle.
		if child.DeviceMAC != "" {
			result[child.DeviceMAC] = true
		}
	}
	return result
}

func (r *Runtime) loadActive(ctx context.Context) error {
	var raw string
	err := r.db.QueryRowContext(ctx, `SELECT payload_json FROM active_policy_bundle WHERE id = 1`).Scan(&raw)
	if err == sql.ErrNoRows { r.logger.Printf("[policy] no active bundle yet"); return nil }
	if err != nil { return fmt.Errorf("query active bundle: %w", err) }
	var b contract.Bundle
	if err := json.Unmarshal([]byte(raw), &b); err != nil { return fmt.Errorf("unmarshal active bundle: %w", err) }
	r.mu.Lock()
	r.active = &b
	r.mu.Unlock()
	r.logger.Printf("[policy] loaded active bundle version=%s", b.Version)
	return nil
}
