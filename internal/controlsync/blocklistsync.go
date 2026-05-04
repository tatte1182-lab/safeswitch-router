package controlsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DNSReloader is implemented by dns.Server. Declared here to avoid import cycle.
type DNSReloader interface {
	Reload(ctx context.Context) error
}

const (
	blocklistFetchTimeout = 10 * time.Second

	// Source tags — one row in dns_blocklist per (domain, source) pair.
	// Keeping sources separate lets us replace one feed without disturbing
	// the others (critical: manual safeswitch-seed rows survive all syncs).
	blocklistSourceThreatFeeds = "threat_feeds"
	blocklistSourceCategoryMap = "domain_category_map"
)

type threatFeedRow struct {
	Domain   string `json:"domain"`
	Category string `json:"category"`
}

// WithDNS wires the DNS server so blocklist sync can trigger a reload after
// SQLite changes. Follows the same late-binding pattern as WithTunnel.
func (s *Service) WithDNS(d DNSReloader) *Service {
	s.dns = d
	return s
}

// runBlocklistSync fetches the blocklist feeds from Supabase every ~5 minutes,
// compares to last-applied hash per source, and applies changes only when a
// feed has moved. Runs threat_feeds, domain_category_map, AND nrd each cycle.
//
// Interval is longer than bundle fetch (30s) because these lists are slow-
// moving and writing thousands of rows is not free.
func (s *Service) runBlocklistSync(ctx context.Context) {
	defer s.wg.Done()

	// VPS relay doesn't serve DNS to clients, so it doesn't need the sync.
	if s.nodeType == "vps_relay" {
		return
	}

	// First sync 15s after startup — give everything else time to settle.
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	interval := 5 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			changed := 0
			if err := s.syncBlocklistSource(ctx,
				blocklistSourceThreatFeeds,
				"/rest/v1/threat_feeds?select=domain,category&active=is.true",
				"malware",
			); err != nil {
				s.logger.Printf("[blocklist-sync] threat_feeds error: %v", err)
			} else {
				changed++
			}

			if err := s.syncBlocklistSource(ctx,
				blocklistSourceCategoryMap,
				"/rest/v1/domain_category_map?select=domain,category&active=is.true",
				"", // no fallback — category_map rows always have a category
			); err != nil {
				s.logger.Printf("[blocklist-sync] domain_category_map error: %v", err)
			} else {
				changed++
			}

			// Reload the in-memory DNS blocklist once per cycle if any source
			// wrote. syncBlocklistSource returns nil on no-op (hash match) too,
			// so this is belt+braces; reload is cheap.
			if changed > 0 && s.dns != nil {
				if err := s.dns.Reload(ctx); err != nil {
					s.logger.Printf("[blocklist-sync] reload warning: %v", err)
				}
			}

			// NRD sync disabled 2026-05-01 — Postgres ingest was burning daily
			// disk IO budget. Re-enable via R2 distribution path.

			timer.Reset(interval)
		}
	}
}

// syncBlocklistSource fetches rows from `path`, compares against the stored
// hash for `source`, and replaces the slice of dns_blocklist tagged with
// that source when the list has moved. fallbackCategory is used when a row
// has an empty category field (shouldn't happen, but defensive).
func (s *Service) syncBlocklistSource(
	ctx context.Context, source, path, fallbackCategory string,
) error {
	reqCtx, cancel := context.WithTimeout(ctx, blocklistFetchTimeout)
	defer cancel()

	body, status, err := s.client.getREST(reqCtx, path)
	if err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	if status >= 400 {
		return fmt.Errorf("fetch status=%d", status)
	}

	var rows []threatFeedRow
	if err := json.Unmarshal(body, &rows); err != nil {
		preview := string(body)
		if len(preview) > 256 {
			preview = preview[:256] + "…"
		}
		return fmt.Errorf("parse: %w (body: %s)", err, preview)
	}

	incomingHash := hashRows(rows)

	hashKey := "blocklist_" + source + "_hash"
	var lastHash string
	_ = s.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = ?`, hashKey,
	).Scan(&lastHash)

	if lastHash == incomingHash {
		return nil // no-op — upstream unchanged
	}

	if err := s.applyBlocklistSource(ctx, source, rows, incomingHash, fallbackCategory); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	s.logger.Printf("[blocklist-sync] applied source=%s domains=%d hash=%s",
		source, len(rows), incomingHash[:8])
	return nil
}

// applyBlocklistSource replaces all rows with the given source in a single
// transaction, then records the new content hash. Other sources untouched.
func (s *Service) applyBlocklistSource(
	ctx context.Context, source string, rows []threatFeedRow, newHash, fallbackCategory string,
) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Scope the delete by source so other feeds (and manual seeds) survive.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM dns_blocklist WHERE source = ?`, source); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO dns_blocklist (domain, category, source, added_at)
 VALUES (?, ?, ?, CURRENT_TIMESTAMP)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, r := range rows {
		d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(r.Domain, ".")))
		if d == "" {
			continue
		}
		cat := strings.ToLower(strings.TrimSpace(r.Category))
		if cat == "" {
			cat = fallbackCategory
		}
		if cat == "" {
			continue // skip rows with no category and no fallback
		}
		if _, err := stmt.ExecContext(ctx, d, cat, source); err != nil {
			return fmt.Errorf("insert %s: %w", d, err)
		}
	}

	// Record the hash for next-cycle change detection (per-source key).
	hashKey := "blocklist_" + source + "_hash"
	if _, err := tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO tunnel_config (key, value) VALUES (?, ?)`,
		hashKey, newHash); err != nil {
		return fmt.Errorf("hash write: %w", err)
	}

	return tx.Commit()
}

// hashRows returns a stable hash over domain+category pairs. Sorting makes
// the hash independent of row order from the server.
func hashRows(rows []threatFeedRow) string {
	pairs := make([]string, 0, len(rows))
	for _, r := range rows {
		d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(r.Domain, ".")))
		if d == "" {
			continue
		}
		c := strings.ToLower(strings.TrimSpace(r.Category))
		pairs = append(pairs, d+"|"+c)
	}
	sort.Strings(pairs)
	h := sha256.New()
	for _, p := range pairs {
		h.Write([]byte(p))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
