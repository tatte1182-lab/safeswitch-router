// internal/dns/safesearch.go
//
// SafeSearch enforcement.
//
// Always-on for every wg0 client. When a child queries a search engine or
// YouTube hostname, the resolver returns the IP of the corresponding "safe"
// variant instead of the real one. The browser is none the wiser; the search
// engine itself sees a connection arriving on its SafeSearch endpoint and
// serves a SafeSearch-restricted result page.
//
// This is the same trick NextDNS, Cloudflare for Families, and OpenDNS use.
//
//   www.google.com         -> forcesafesearch.google.com (216.239.38.120)
//   www.bing.com           -> strict.bing.com           (Azure Front Door)
//   duckduckgo.com         -> safe.duckduckgo.com       (Azure)
//   www.youtube.com et al  -> restrict.youtube.com      (216.239.38.120)
//
// The IPs above are the documented stable addresses used by every major
// SafeSearch-enforcing DNS service, so they are reasonable hardcoded
// fallbacks. We still re-resolve them at startup and every 24h via the
// upstream resolver to pick up any future changes.
//
// Wiring: call NewSafeSearch() once at startup, store on the Resolver,
// and consult it from Resolve() before the blocklist check (see resolver.go).

package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// safeTarget is one rewrite rule: any name in `triggers` returns the IP of
// `safeHost`. The IP is resolved at startup and refreshed periodically.
type safeTarget struct {
	safeHost string   // canonical SafeSearch host to look up
	fallback [4]byte  // hardcoded IP used if upstream resolution fails
	triggers []string // exact lowercase FQDNs that trigger the rewrite
}

// safeTargets is the static list of SafeSearch rewrites.
//
// Triggers are exact-match FQDNs (lowercased, no trailing dot). To support
// every Google ccTLD without listing them all, we also do a suffix match
// against `googleSuffixes` below; everything else stays exact-match for
// safety (we don't want to rewrite "www.duckduckgo-blog.example").
var safeTargets = []safeTarget{
	{
		safeHost: "forcesafesearch.google.com",
		fallback: [4]byte{216, 239, 38, 120},
		// Plain "google.com" plus the most common subdomains. ccTLDs are
		// handled by suffix match below.
		triggers: []string{
			"google.com", "www.google.com",
			"images.google.com", "www.images.google.com",
			"encrypted.google.com",
		},
	},
	{
		safeHost: "strict.bing.com",
		// strict.bing.com now resolves via Azure Front Door
		// (ax-msedge.net). The IP rotates more aggressively than Google's;
		// startup resolution gives us the current value, this is only the
		// last-resort fallback.
		fallback: [4]byte{150, 171, 27, 16},
		triggers: []string{
			"bing.com", "www.bing.com",
		},
	},
	{
		safeHost: "safe.duckduckgo.com",
		// safe.duckduckgo.com is served from Microsoft Azure and rotates;
		// the hardcoded fallback may go stale faster than Google.
		// If startup resolution succeeds we use that; otherwise this.
		fallback: [4]byte{40, 89, 244, 237},
		triggers: []string{
			"duckduckgo.com", "www.duckduckgo.com",
		},
	},
	{
		safeHost: "restrict.youtube.com",
		fallback: [4]byte{216, 239, 38, 120},
		triggers: []string{
			"youtube.com", "www.youtube.com", "m.youtube.com",
			"youtubei.googleapis.com", "youtube.googleapis.com",
			"www.youtube-nocookie.com", "youtube-nocookie.com",
		},
	},
}

// googleSuffixes catches Google search ccTLDs without enumerating every one.
// The suffix list is kept small and conservative: it covers the search
// hostnames only, not Google services that should resolve normally
// (gmail.com, drive.google.com, etc. are NOT in this list).
var googleSuffixes = []string{
	".google.co.uk", ".google.com.au", ".google.ca", ".google.de",
	".google.fr", ".google.it", ".google.es", ".google.nl",
	".google.com.br", ".google.co.in", ".google.co.jp", ".google.co.nz",
	".google.ie", ".google.com.mx", ".google.pl", ".google.ru",
	".google.com.sg", ".google.com.hk", ".google.com.tw", ".google.co.za",
}

// SafeSearch holds the resolved IPs for each rewrite target. Lookups are
// O(1) against a map populated from safeTargets at startup.
type SafeSearch struct {
	mu      sync.RWMutex
	exact   map[string][4]byte // exact-match FQDN -> rewrite IP
	google  [4]byte            // shared Google rewrite IP, used for ccTLD suffix match
	logger  Logger
	stopCh  chan struct{}
}

// NewSafeSearch builds the rewrite table. It performs an initial resolution
// of each safeHost and falls back to the hardcoded IP on failure. A
// background goroutine refreshes the table every 24h.
//
// Pass nil for logger if you want it to be quiet.
func NewSafeSearch(logger Logger) *SafeSearch {
	s := &SafeSearch{
		exact:  make(map[string][4]byte),
		logger: logger,
		stopCh: make(chan struct{}),
	}
	s.refresh()
	go s.refreshLoop()
	return s
}

// Stop cancels the background refresh loop. Optional; safe to skip in
// programs that exit by process termination.
func (s *SafeSearch) Stop() {
	close(s.stopCh)
}

func (s *SafeSearch) refreshLoop() {
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.refresh()
		}
	}
}

// refresh re-resolves every safeHost and rebuilds the exact-match map.
// Failures fall back to the hardcoded IP for that target.
func (s *SafeSearch) refresh() {
	exact := make(map[string][4]byte, 32)
	var googleIP [4]byte

	for _, t := range safeTargets {
		ip := resolveOrFallback(t.safeHost, t.fallback, s.logger)
		for _, name := range t.triggers {
			exact[strings.ToLower(name)] = ip
		}
		if t.safeHost == "forcesafesearch.google.com" {
			googleIP = ip
		}
	}

	s.mu.Lock()
	s.exact = exact
	s.google = googleIP
	s.mu.Unlock()

	if s.logger != nil {
		s.logger.Printf("[safesearch] table refreshed: %d hosts, google=%d.%d.%d.%d",
			len(exact), googleIP[0], googleIP[1], googleIP[2], googleIP[3])
	}
}

// Lookup returns the rewrite IP for the given query name and true if a
// rewrite applies. The name should be the bare lowercased FQDN with no
// trailing dot (matching what wire.go's parseQuery produces).
//
// Returns false for any name not in the SafeSearch list, in which case the
// resolver should continue with its normal path.
func (s *SafeSearch) Lookup(name string) ([4]byte, bool) {
	if name == "" {
		return [4]byte{}, false
	}
	name = strings.ToLower(name)

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Exact-match path covers Google.com, Bing, DuckDuckGo, YouTube hosts.
	if ip, ok := s.exact[name]; ok {
		return ip, true
	}

	// Google ccTLD suffix match: "www.google.co.uk" -> google rewrite IP.
	// We require the name to be the bare ccTLD root or start with "www."
	// or "images." to avoid accidentally rewriting non-search Google
	// subdomains like "translate.google.co.uk".
	for _, suffix := range googleSuffixes {
		bare := strings.TrimPrefix(suffix, ".") // e.g. "google.co.uk"
		// Match either the bare root or a www./images. subdomain.
		if name == bare ||
			name == "www."+bare ||
			name == "images."+bare {
			return s.google, true
		}
	}

	return [4]byte{}, false
}

// resolveOrFallback does a single A lookup against the system resolver
// with a short timeout. On any failure (including no IPv4 record) it
// returns the hardcoded fallback so SafeSearch always has a usable IP.
func resolveOrFallback(host string, fallback [4]byte, logger Logger) [4]byte {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		if logger != nil {
			logger.Printf("[safesearch] resolve %s failed (%v) — using fallback", host, err)
		}
		return fallback
	}
	v4 := ips[0].To4()
	if v4 == nil {
		return fallback
	}
	var out [4]byte
	copy(out[:], v4)
	return out
}
