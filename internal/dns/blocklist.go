package dns

import (
	"context"
	"database/sql"
	"strings"
	"sync"
)

type Blocklist struct {
	mu      sync.RWMutex
	domains map[string]struct{}
	// catDomains maps category → set of domains in that category.
	// Populated by Load alongside the main domain set.
	catDomains map[string]map[string]struct{}
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		domains:    make(map[string]struct{}),
		catDomains: make(map[string]map[string]struct{}),
	}
}

// IsBlocked returns true if domain (or any parent domain) is in the global
// blocklist — regardless of category. Used for the malware/phishing baseline.
func (b *Blocklist) IsBlocked(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	b.mu.RLock()
	defer b.mu.RUnlock()
	for {
		if _, ok := b.domains[domain]; ok {
			return true
		}
		dot := strings.Index(domain, ".")
		if dot < 0 {
			return false
		}
		domain = domain[dot+1:]
	}
}

// IsBlockedForCategories returns true if the domain (or any parent domain) is
// in any of the given categories. Used for per-child category enforcement.
// An empty cats slice always returns false.
func (b *Blocklist) IsBlockedForCategories(domain string, cats []string) bool {
	if len(cats) == 0 {
		return false
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Build a quick lookup set from the provided categories
	catSet := make(map[string]struct{}, len(cats))
	for _, c := range cats {
		catSet[strings.ToLower(c)] = struct{}{}
	}

	d := domain
	for {
		for cat, domains := range b.catDomains {
			if _, wantCat := catSet[cat]; !wantCat {
				continue
			}
			if _, blocked := domains[d]; blocked {
				return true
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
// set and the per-category maps.
func (b *Blocklist) Load(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT domain, category FROM dns_blocklist`)
	if err != nil {
		return err
	}
	defer rows.Close()

	freshAll := make(map[string]struct{})
	freshCat := make(map[string]map[string]struct{})

	for rows.Next() {
		var d, cat string
		if err := rows.Scan(&d, &cat); err != nil {
			continue
		}
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		cat = strings.ToLower(cat)
		freshAll[d] = struct{}{}
		if freshCat[cat] == nil {
			freshCat[cat] = make(map[string]struct{})
		}
		freshCat[cat][d] = struct{}{}
	}

	b.mu.Lock()
	b.domains = freshAll
	b.catDomains = freshCat
	b.mu.Unlock()

	return rows.Err()
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
