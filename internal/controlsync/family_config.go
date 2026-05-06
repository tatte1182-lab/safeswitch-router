package controlsync

// File: internal/controlsync/family_config.go
//
// Implements terminator.ConfigSource by fetching per-family WG
// terminator config from the relay-family-config Supabase edge
// function.
//
// Caching: 5-min TTL Go-side LRU. Family configs change rarely
// (only on enrollment / device swap / key rotation). The 5-min
// TTL aligns with the terminator's idle teardown — at most one
// upstream fetch per active fallback family per 5 minutes.
//
// We deliberately do NOT use Realtime invalidation: the relay's
// data path must not depend on a long-lived Supabase WebSocket.
// 5 minutes of staleness on a fallback config is acceptable
// (fallback is already a degraded mode).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/terminator"
)

// familyConfigCacheTTL is how long a fetched config is considered
// fresh. See file comment for the rationale.
const familyConfigCacheTTL = 5 * time.Minute

// familyConfigResponse mirrors the relay-family-config edge
// function's response shape.
type familyConfigResponse struct {
	FamilyID          string   `json:"family_id"`
	PrivateKey        string   `json:"private_key"`
	ListenPort        int      `json:"listen_port"`
	BlockedCategories []string `json:"blocked_categories"`
	Peers             []struct {
		PublicKey  string   `json:"public_key"`
		AllowedIPs []string `json:"allowed_ips"`
	} `json:"peers"`
}

// familyConfigCacheEntry is one row in the in-process LRU. We
// cache the parsed *terminator.FamilyConfig directly so callers
// don't pay for re-decoding.
type familyConfigCacheEntry struct {
	cfg       *terminator.FamilyConfig
	fetchedAt time.Time
}

// familyConfigCache guards in-flight fetches with singleflight-
// style coalescing: if 100 fallback packets for a fresh family
// arrive at once, only one HTTP fetch runs and the rest wait on
// its completion. Prevents fetch storms when an ISP outage hits.
type familyConfigCache struct {
	mu      sync.Mutex
	entries map[string]*familyConfigCacheEntry

	// inflight maps family_id to a pending fetch. Subsequent
	// callers for the same family_id wait on the same channel.
	inflight map[string]chan struct{}
}

func newFamilyConfigCache() *familyConfigCache {
	return &familyConfigCache{
		entries:  make(map[string]*familyConfigCacheEntry),
		inflight: make(map[string]chan struct{}),
	}
}

// get returns the cached config if fresh, nil if stale or absent.
// Caller must hold no locks.
func (c *familyConfigCache) get(familyID string) *terminator.FamilyConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[familyID]
	if !ok {
		return nil
	}
	if time.Since(e.fetchedAt) > familyConfigCacheTTL {
		return nil
	}
	return e.cfg
}

// set stores a fetched config.
func (c *familyConfigCache) set(familyID string, cfg *terminator.FamilyConfig) {
	c.mu.Lock()
	c.entries[familyID] = &familyConfigCacheEntry{
		cfg:       cfg,
		fetchedAt: time.Now(),
	}
	c.mu.Unlock()
}

// invalidate drops a cached entry — call when we know the upstream
// changed (e.g. on a key rotation command). Currently unused but
// hooked up for future use.
func (c *familyConfigCache) invalidate(familyID string) {
	c.mu.Lock()
	delete(c.entries, familyID)
	c.mu.Unlock()
}

// FetchFamilyConfig retrieves the per-family terminator config.
// Implements terminator.ConfigSource. Cached; safe to call from
// multiple goroutines for the same family at once.
func (s *Service) FetchFamilyConfig(ctx context.Context, familyID string) (*terminator.FamilyConfig, error) {
	if familyID == "" {
		return nil, errors.New("controlsync: empty family id")
	}

	// Lazy-init cache on first call. The Service struct doesn't
	// have a familyConfigCache field today; we attach it via
	// sync.Once-style guarded init so we don't have to touch the
	// constructor (which lives in service.go and would create a
	// merge mess if we widened its signature).
	cache := s.getOrInitFamilyConfigCache()

	if cfg := cache.get(familyID); cfg != nil {
		return cfg, nil
	}

	// Singleflight: dedupe concurrent fetches for the same family.
	cache.mu.Lock()
	if wait, busy := cache.inflight[familyID]; busy {
		cache.mu.Unlock()
		// Another goroutine is fetching; wait for it then re-check
		// the cache.
		select {
		case <-wait:
			if cfg := cache.get(familyID); cfg != nil {
				return cfg, nil
			}
			// Fetch failed (no cache entry); fall through to retry
			// with our own fetch.
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		cache.mu.Lock()
	}
	done := make(chan struct{})
	cache.inflight[familyID] = done
	cache.mu.Unlock()

	defer func() {
		cache.mu.Lock()
		delete(cache.inflight, familyID)
		cache.mu.Unlock()
		close(done)
	}()

	cfg, err := s.fetchFamilyConfigUncached(ctx, familyID)
	if err != nil {
		return nil, err
	}
	cache.set(familyID, cfg)
	return cfg, nil
}

func (s *Service) fetchFamilyConfigUncached(ctx context.Context, familyID string) (*terminator.FamilyConfig, error) {
	path := fmt.Sprintf("/functions/v1/relay-family-config?family_id=%s", url.QueryEscape(familyID))
	body, status, err := s.client.get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("controlsync: fetch family config: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("controlsync: fetch family config: status %d body=%s", status, truncateBytes(body, 200))
	}

	var resp familyConfigResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("controlsync: decode family config: %w", err)
	}
	if resp.PrivateKey == "" {
		return nil, fmt.Errorf("controlsync: empty private key in family config response")
	}

	out := &terminator.FamilyConfig{
		FamilyID:    resp.FamilyID,
		PrivateKey:  resp.PrivateKey,
		ListenPort:  resp.ListenPort,
		BlockedCats: resp.BlockedCategories,
	}
	for _, p := range resp.Peers {
		out.Peers = append(out.Peers, terminator.Peer{
			PublicKey:  p.PublicKey,
			AllowedIPs: p.AllowedIPs,
		})
	}
	return out, nil
}

// truncateBytes is for log lines; we don't want to spam an entire 64KB
// edge function error response into the journal.
func truncateBytes(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...[truncated]"
}

// ── Cache lazy-init (no constructor edit) ────────────────────────────
//
// We could add a familyConfigCache field to Service and wire it in
// service.go's NewService, but that means editing the controlsync
// constructor and every call site. Instead we attach the cache to a
// package-level map keyed by *Service identity. Simpler, no
// constructor churn, and Service has a stable lifetime (created
// once in app/wiring.go).
//
// If Service ever becomes plural per-process (it isn't today), this
// scheme still works — each *Service gets its own cache.

var (
	familyConfigCacheMu  sync.Mutex
	familyConfigCacheMap = make(map[*Service]*familyConfigCache)
)

func (s *Service) getOrInitFamilyConfigCache() *familyConfigCache {
	familyConfigCacheMu.Lock()
	defer familyConfigCacheMu.Unlock()
	c, ok := familyConfigCacheMap[s]
	if !ok {
		c = newFamilyConfigCache()
		familyConfigCacheMap[s] = c
	}
	return c
}