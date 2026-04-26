// Package dns - blocklist with bloom filter front-end.
//
// Drop-in replacement for /root/safeswitch-router/internal/dns/blocklist.go.
//
// Preserves the exact same public API as Tee's existing blocklist.go:
//   - NewBlocklist()
//   - IsBlocked(domain) bool
//   - IsBlockedForCategories(domain, cats) bool
//   - Load(ctx, db) error
//   - Size() int
//   - Categories() []string
//
// Adds a bloom filter (~3.6 MB RAM) that fronts both lookup paths. The hot
// path — domains that are NOT blocked — is answered by the bloom filter in
// nanoseconds without touching either map. Bloom hits fall through to the
// existing exact-match map walk (which preserves parent-domain blocking).
//
// Behaviour identical, performance dramatically better at scale.

package dns

import (
	"context"
	"database/sql"
	"hash/fnv"
	"math"
	"strings"
	"sync"
)

// Bloom filter sizing. Tuned for 2M domain headroom @ 0.1% target FPR.
//
// n = 2,000,000  expected items
// p = 0.001      target false positive rate
// m = ceil(-n * ln(p) / ln(2)^2) = ~28,755,176 bits ~= 3.6 MB
// k = round((m/n) * ln(2)) = 10 hash functions
//
// At Tee's current 506k domains, load is ~25%, so effective FPR is far
// below 0.1%. Recompute when crossing 1.5M domains.
const (
	bloomBits      = 28_755_176
	bloomHashFuncs = 10
)

type Blocklist struct {
	mu      sync.RWMutex
	domains map[string]struct{}
	// catDomains maps category -> set of domains in that category.
	// Populated by Load alongside the main domain set.
	catDomains map[string]map[string]struct{}

	// bloom fronts both IsBlocked and IsBlockedForCategories. Holds every
	// domain in the blocklist regardless of category. Rebuilt on each Load.
	bloom *bloomFilter
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		domains:    make(map[string]struct{}),
		catDomains: make(map[string]map[string]struct{}),
		bloom:      newBloom(bloomBits, bloomHashFuncs),
	}
}

// IsBlocked returns true if domain (or any parent domain) is in the global
// blocklist - regardless of category. Used for the malware/phishing baseline.
//
// Hot path: most queries return false. The bloom filter answers those in
// nanoseconds without locking or touching the map.
func (b *Blocklist) IsBlocked(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	d := domain
	for {
		// Bloom check first. If bloom says no, definitely not blocked.
		if b.bloom.maybeContains(d) {
			if _, ok := b.domains[d]; ok {
				return true
			}
			// False positive on this label - keep walking parents.
		}
		dot := strings.Index(d, ".")
		if dot < 0 {
			return false
		}
		d = d[dot+1:]
	}
}

// IsBlockedForCategories returns true if the domain (or any parent domain) is
// in any of the given categories. Used for per-child category enforcement.
// An empty cats slice always returns false.
//
// Bloom optimisation: if the domain's parent walk has zero bloom hits, we
// know no category contains it either (the bloom holds every blocked domain),
// so we can skip the expensive nested loop over catDomains entirely.
func (b *Blocklist) IsBlockedForCategories(domain string, cats []string) bool {
	if len(cats) == 0 {
		return false
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Build a quick lookup set from the provided categories.
	catSet := make(map[string]struct{}, len(cats))
	for _, c := range cats {
		catSet[strings.ToLower(c)] = struct{}{}
	}

	d := domain
	for {
		// Bloom-gate the nested category check. Only if the bloom says
		// "this label might be blocked" do we scan the cat maps.
		if b.bloom.maybeContains(d) {
			for cat, domains := range b.catDomains {
				if _, wantCat := catSet[cat]; !wantCat {
					continue
				}
				if _, blocked := domains[d]; blocked {
					return true
				}
			}
		}
		dot := strings.Index(d, ".")
		if dot < 0 {
			return false
		}
		d = d[dot+1:]
	}
}

// Load fetches all domains from the DB and populates both the global domain
// set and the per-category maps. Bloom filter is rebuilt atomically.
func (b *Blocklist) Load(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT domain, category FROM dns_blocklist`)
	if err != nil {
		return err
	}
	defer rows.Close()

	freshAll := make(map[string]struct{}, 600_000)
	freshCat := make(map[string]map[string]struct{})
	freshBloom := newBloom(bloomBits, bloomHashFuncs)

	for rows.Next() {
		var d, cat string
		if err := rows.Scan(&d, &cat); err != nil {
			continue
		}
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		if d == "" {
			continue
		}
		cat = strings.ToLower(cat)

		freshAll[d] = struct{}{}
		freshBloom.add(d)

		if freshCat[cat] == nil {
			freshCat[cat] = make(map[string]struct{})
		}
		freshCat[cat][d] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	b.domains = freshAll
	b.catDomains = freshCat
	b.bloom = freshBloom
	b.mu.Unlock()

	return nil
}

func (b *Blocklist) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.domains)
}

// Categories returns the list of categories currently loaded.
func (b *Blocklist) Categories() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	cats := make([]string, 0, len(b.catDomains))
	for c := range b.catDomains {
		cats = append(cats, c)
	}
	return cats
}

// EstimatedFPR returns the bloom filter's current false-positive rate based
// on actual load. Useful for telemetry / scaling alarms when you want to
// know "how full is the bloom?" without a separate counter.
//
// Formula: (1 - e^(-k*n/m))^k
func (b *Blocklist) EstimatedFPR() float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := float64(len(b.domains))
	m := float64(bloomBits)
	k := float64(bloomHashFuncs)
	return math.Pow(1-math.Exp(-k*n/m), k)
}

// ---------------------------------------------------------------------------
// Bloom filter internals. Standard double-hashing (Kirsch-Mitzenmacher) so we
// only compute 2 hashes per item and derive the rest.
// ---------------------------------------------------------------------------

type bloomFilter struct {
	bits []uint64
	m    uint64
	k    uint64
}

func newBloom(bits, k int) *bloomFilter {
	words := (bits + 63) / 64
	return &bloomFilter{
		bits: make([]uint64, words),
		m:    uint64(bits),
		k:    uint64(k),
	}
}

func (bf *bloomFilter) hashes(s string) (uint64, uint64) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	h1 := h.Sum64()
	h.Reset()
	_, _ = h.Write([]byte{0x5a})
	_, _ = h.Write([]byte(s))
	h2 := h.Sum64()
	return h1, h2
}

func (bf *bloomFilter) add(s string) {
	h1, h2 := bf.hashes(s)
	for i := uint64(0); i < bf.k; i++ {
		idx := (h1 + i*h2) % bf.m
		bf.bits[idx/64] |= 1 << (idx % 64)
	}
}

func (bf *bloomFilter) maybeContains(s string) bool {
	h1, h2 := bf.hashes(s)
	for i := uint64(0); i < bf.k; i++ {
		idx := (h1 + i*h2) % bf.m
		if bf.bits[idx/64]&(1<<(idx%64)) == 0 {
			return false
		}
	}
	return true
}
