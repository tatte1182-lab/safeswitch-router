package dns

import (
	"context"
	"database/sql"
	"strings"
	"sync"
	"sync/atomic"
)

// NRDBlocklist is the in-memory NRD lookup. Sibling of Blocklist, but for
// newly-registered domains pulled from cenk.app via Supabase.
//
// Read path is lock-free and allocation-free — the underlying map is swapped
// atomically by Reload(). Concurrent reads are safe under load.
//
// At ~2M domains the in-memory footprint is ~50 MB. Negligible on the VPS.
type NRDBlocklist struct {
	current atomic.Pointer[map[string]struct{}]
	mu      sync.Mutex // serialises Reload() against itself only
	db      *sql.DB
	logger  Logger
}

// NewNRDBlocklist constructs an empty blocklist. Call Reload() once at
// startup (after the SQLite schema exists); the resolver hot-path returns
// false until Reload completes.
func NewNRDBlocklist(db *sql.DB, logger Logger) *NRDBlocklist {
	b := &NRDBlocklist{db: db, logger: logger}
	empty := map[string]struct{}{}
	b.current.Store(&empty)
	return b
}

// Reload reads the SQLite mirror table into a fresh map and atomically swaps
// it in. Called at startup and from blocklistsync whenever syncNRDBlocklist
// returns changed=true.
//
// Implements controlsync.NRDReloader.
func (b *NRDBlocklist) Reload(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	rows, err := b.db.QueryContext(ctx, `SELECT domain FROM nrd_blocklist`)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Pre-size for ~2 M to avoid rehash churn during load. Over- or under-
	// allocating slightly is fine.
	m := make(map[string]struct{}, 2_500_000)
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return err
		}
		m[d] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	b.current.Store(&m)
	if b.logger != nil {
		b.logger.Printf("[dns] nrd blocklist loaded domains=%d", len(m))
	}
	return nil
}

// IsNRD returns true if the given domain (or any of its registrable
// parents) is in the NRD blocklist.
//
// Subdomain matching is intentional: phishing campaigns rarely use the
// apex. If "phishy-2026.com" is in the list, login.phishy-2026.com is
// also blocked. We stop walking before reaching a bare TLD so we never
// block "com" even if a misbehaving feed includes it.
//
// Hot path. Allocation-free, lock-free.
func (b *NRDBlocklist) IsNRD(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return false
	}
	m := *b.current.Load()
	if len(m) == 0 {
		return false
	}

	current := domain
	for {
		if _, ok := m[current]; ok {
			return true
		}
		dot := strings.IndexByte(current, '.')
		if dot < 0 {
			return false
		}
		next := current[dot+1:]
		if strings.IndexByte(next, '.') < 0 {
			// "next" is a bare TLD — check it once then stop.
			if _, ok := m[next]; ok {
				return true
			}
			return false
		}
		current = next
	}
}

// Size returns the current loaded NRD count. For startup logs and metrics.
func (b *NRDBlocklist) Size() int {
	return len(*b.current.Load())
}
