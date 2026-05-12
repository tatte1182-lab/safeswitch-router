// Package dns - blocklist with bloom filter front-end.
//
// Drop-in replacement for /root/safeswitch-router/internal/dns/blocklist.go.
//
// Preserves the public API as Tee's prior blocklist.go:
//   - NewBlocklist()
//   - IsBlocked(domain) bool
//   - IsBlockedForCategories(domain, cats) bool
//   - Load(ctx, db) error
//   - Size() int
//   - Categories() []string
//
// Adds CategoryFor(domain) for the activity_log path so the matched-row
// category propagates to Supabase without an extra SQLite roundtrip per
// block. Backed by a domain->category reverse map populated during Load()
// atomically alongside the other indexes - same lifecycle, no extra DB IO.
//
// Bloom filter (~3.6 MB RAM) fronts both lookup paths. The hot path -
// domains that are NOT blocked - is answered by the bloom filter in
// nanoseconds without touching any map. Bloom hits fall through to the
// existing exact-match map walk (which preserves parent-domain blocking).

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

// categoryPriority orders categories so a domain appearing in multiple
// lists (e.g. a row in both 'malware' and 'tracking') is reported as the
// most user-protective category. Protective tiers win over policy tiers
// win over hygiene tiers. Used by domainCategory during Load() to pick
// which single category to record in the reverse map.
//
// Lower number = higher priority. Unlisted categories get the default
// (large value via the lookup helper).
var categoryPriority = map[string]int{
	// Protective (visible to child on Shield)
	"malware":          1,
	"phishing":         2,
	"scam":             3,
	"ransomware":       4,
	"cryptojacking":    5,
	"fake_banking":     6,
	"newly_registered": 7,

	// Policy (parent-configured)
	"gambling":      20,
	"adult":         21,
	"social_media":  22,
	"games":         23,
	"entertainment": 24,
	"browsing":      25,

	// Hygiene (background noise, never user-facing)
	"ads":        50,
	"tracking":   51,
	"telemetry":  52,
	"doh_bypass": 53,
}

func priorityOf(cat string) int {
	if p, ok := categoryPriority[cat]; ok {
		return p
	}
	return 1 << 30 // unknown categories sort last
}

type Blocklist struct {
	mu      sync.RWMutex
	domains map[string]struct{}
	// catDomains maps category -> set of domains in that category.
	// Populated by Load alongside the main domain set.
	catDomains map[string]map[string]struct{}

	// domainCategory is the reverse index: domain -> single best category.
	// Populated by Load() in lockstep with catDomains. When a domain
	// appears in multiple categories, the highest-priority one wins
	// (see categoryPriority above).
	//
	// Used by CategoryFor() to give the activity_writer the right tag
	// for the matched block - no SQLite roundtrip on the DNS hot path.
	domainCategory map[string]string

	// bloom fronts both IsBlocked and IsBlockedForCategories. Holds every
	// domain in the blocklist regardless of category. Rebuilt on each Load.
	bloom *bloomFilter
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		domains:        make(map[string]struct{}),
		catDomains:     make(map[string]map[string]struct{}),
		domainCategory: make(map[string]string),
		bloom:          newBloom(bloomBits, bloomHashFuncs),
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

// CategoryFor returns the matched-row category for a blocked domain, walking
// parent labels the same way IsBlocked does. Returns "" if not blocked.
//
// Categories are not unique per domain - a single domain can appear in
// several Hagezi feeds. We return the highest-priority category by the
// table at the top of this file so a domain in both 'malware' and 'tracking'
// is correctly reported as 'malware' for the child shield.
//
// Called from the DNS hot path immediately after IsBlocked /
// IsBlockedForCategories returns true. O(1) map lookup per label, bloom-
// gated to match IsBlocked's parent-walk behaviour.
func (b *Blocklist) CategoryFor(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return ""
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	d := domain
	for {
		if b.bloom.maybeContains(d) {
			if cat, ok := b.domainCategory[d]; ok {
				return cat
			}
		}
		dot := strings.Index(d, ".")
		if dot < 0 {
			return ""
		}
		d = d[dot+1:]
	}
}

// Load fetches all domains from the DB and populates the global domain set,
// per-category maps, and the domain->category reverse index. Bloom filter is
// rebuilt atomically.
//
// When a domain appears in multiple rows with different categories (e.g.
// malware-list AND tracking-list), the highest-priority category wins for
// the reverse index. Both per-category maps still contain the domain, so
// category-specific enforcement (IsBlockedForCategories) is unaffected.
func (b *Blocklist) Load(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT domain, category FROM dns_blocklist`)
	if err != nil {
		return err
	}
	defer rows.Close()

	freshAll := make(map[string]struct{}, 600_000)
	freshCat := make(map[string]map[string]struct{})
	freshDomainCat := make(map[string]string, 600_000)
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

		// Reverse index: keep the higher-priority (lower number) category
		// when a domain shows up in multiple rows. First-write wins for
		// equal priority, which is fine - equal priority means equivalent
		// classification tier.
		if existing, seen := freshDomainCat[d]; !seen || priorityOf(cat) < priorityOf(existing) {
			freshDomainCat[d] = cat
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	b.mu.Lock()
	b.domains = freshAll
	b.catDomains = freshCat
	b.domainCategory = freshDomainCat
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