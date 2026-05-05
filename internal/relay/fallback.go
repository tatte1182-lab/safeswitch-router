package relay

import (
	"sync"
	"sync/atomic"
	"time"
)

// FallbackResolver runs the relay's degraded-mode data path when no
// healthy home node exists for a family.
//
// Design intent: the customer must not perceive an outage. When a
// home node disappears we keep the child device's traffic flowing
// — just without the home node's caching, compression, or per-child
// content filter. We still apply a coarse DNS sinkhole at the VPS
// so the family's basic block list keeps working.
//
// In Phase 1 the fallback is "DNS-only filter at VPS, no per-child
// granularity." Phase 2 lifts a slim copy of each family's child
// policies into the VPS so per-child filtering survives a home node
// outage. Phase 3 routes overflow to peer home nodes.
//
// IMPORTANT: this resolver does NOT decrypt WireGuard. The relay is
// still a tunnel forwarder. What it does is: when there's no node
// to forward to, redirect WG handshake/data toward a local
// wireguard-go endpoint on the VPS that terminates the tunnel,
// runs the family's blocklist against DNS lookups, and NATs the
// rest straight out. The endpoint is shared across all fallback
// families — it's intentionally cheap because it's idle 99% of the
// time. See cmd/ss-router/relay/fallback_endpoint.go for the
// terminator wiring.
type FallbackResolver struct {
	// fallbackEndpoint is the local UDP addr where the VPS's
	// shared wireguard-go terminator listens. Set at startup;
	// nil disables fallback (silent-drop behaviour, current).
	fallbackEndpoint string

	// active tracks which families are currently in fallback so
	// metrics can surface "X families degraded" without re-querying
	// the registry on every packet.
	mu     sync.RWMutex
	active map[string]time.Time // familyID -> entered fallback at

	// counters are atomic so the hot path doesn't take the lock.
	packetsForwarded uint64
	packetsDropped   uint64
	familiesDegraded int64
}

// NewFallbackResolver constructs a resolver. Pass an empty
// endpoint string in dev or when the VPS terminator isn't
// configured — packets will be counted-and-dropped, matching the
// existing silent-drop behaviour but with observability.
func NewFallbackResolver(endpoint string) *FallbackResolver {
	return &FallbackResolver{
		fallbackEndpoint: endpoint,
		active:           make(map[string]time.Time),
	}
}

// EnterFallback marks a family as degraded. Idempotent. Returns
// true if this is a state transition (was healthy, now degraded)
// so the caller can fire a one-shot event to the cloud.
func (f *FallbackResolver) EnterFallback(familyID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, already := f.active[familyID]; already {
		return false
	}
	f.active[familyID] = time.Now()
	atomic.AddInt64(&f.familiesDegraded, 1)
	return true
}

// ExitFallback clears the degraded flag. Idempotent. Returns
// true if this is a state transition.
func (f *FallbackResolver) ExitFallback(familyID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, was := f.active[familyID]; !was {
		return false
	}
	delete(f.active, familyID)
	atomic.AddInt64(&f.familiesDegraded, -1)
	return true
}

// IsActive reports whether a family is currently in fallback.
func (f *FallbackResolver) IsActive(familyID string) bool {
	f.mu.RLock()
	_, ok := f.active[familyID]
	f.mu.RUnlock()
	return ok
}

// Endpoint returns the local UDP addr to forward to when a family
// is in fallback. Empty string means fallback is disabled — the
// caller should drop the packet (with a counter bump).
func (f *FallbackResolver) Endpoint() string {
	return f.fallbackEndpoint
}

// RecordForwarded / RecordDropped maintain hot-path metrics
// without touching the lock.
func (f *FallbackResolver) RecordForwarded() {
	atomic.AddUint64(&f.packetsForwarded, 1)
}

func (f *FallbackResolver) RecordDropped() {
	atomic.AddUint64(&f.packetsDropped, 1)
}

// Stats snapshots current counter values for /relay/status etc.
type FallbackStats struct {
	PacketsForwarded uint64
	PacketsDropped   uint64
	FamiliesDegraded int64
	ActiveFamilies   []string
	OldestEntry      time.Duration // how long the longest-running degraded family has been down
}

func (f *FallbackResolver) Stats() FallbackStats {
	now := time.Now()
	out := FallbackStats{
		PacketsForwarded: atomic.LoadUint64(&f.packetsForwarded),
		PacketsDropped:   atomic.LoadUint64(&f.packetsDropped),
		FamiliesDegraded: atomic.LoadInt64(&f.familiesDegraded),
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	out.ActiveFamilies = make([]string, 0, len(f.active))
	var oldest time.Time
	for fam, since := range f.active {
		out.ActiveFamilies = append(out.ActiveFamilies, fam)
		if oldest.IsZero() || since.Before(oldest) {
			oldest = since
		}
	}
	if !oldest.IsZero() {
		out.OldestEntry = now.Sub(oldest)
	}
	return out
}