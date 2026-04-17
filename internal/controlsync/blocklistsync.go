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
	blocklistSource       = "threat_feeds"
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

// runBlocklistSync fetches threat_feeds from Supabase every ~5 minutes,
// compares to the last-applied hash, and applies changes only if the
// upstream list has moved. Full-replace strategy within source='threat_feeds',
// so manually-seeded rows (source='safeswitch-seed', etc.) are preserved.
//
// Interval is longer than bundle fetch (30s) because the threat list is slow-
// moving and writing tens of thousands of rows is not free.
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
			if err := s.syncBlocklist(ctx); err != nil {
				s.logger.Printf("[blocklist-sync] error: %v", err)
			}
			timer.Reset(interval)
		}
	}
}

func (s *Service) syncBlocklist(ctx context.Context) error {
	reqCtx, cancel := context.WithTimeout(ctx, blocklistFetchTimeout)
	defer cancel()

	// Fetch active threat feed rows. PostgREST with no filter returns all rows;
	// we keep the query narrow to reduce payload.
	body, status, err := s.client.getREST(reqCtx,
		"/rest/v1/threat_feeds?select=domain,category&active=is.true")
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

	// Compute hash of the incoming list for change detection.
	// Sorted so order changes alone don't force a rewrite.
	incomingHash := hashRows(rows)

	var lastHash string
	_ = s.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'blocklist_threat_feeds_hash'`,
	).Scan(&lastHash)

	if lastHash == incomingHash {
		return nil // no-op — upstream unchanged
	}

	// Apply the new list inside a transaction.
	if err := s.applyBlocklist(ctx, rows, incomingHash); err != nil {
		return fmt.Errorf("apply: %w", err)
	}

	// Reload the in-memory DNS blocklist so changes are live immediately.
	if s.dns != nil {
		if err := s.dns.Reload(ctx); err != nil {
			s.logger.Printf("[blocklist-sync] reload warning: %v", err)
		}
	}

	s.logger.Printf("[blocklist-sync] applied source=%s domains=%d hash=%s",
		blocklistSource, len(rows), incomingHash[:8])
	return nil
}

// applyBlocklist replaces all rows with source=threat_feeds in a single
// transaction, then records the new content hash.
func (s *Service) applyBlocklist(ctx context.Context, rows []threatFeedRow, newHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Scope the delete to source='threat_feeds' so manually-seeded rows survive.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM dns_blocklist WHERE source = ?`, blocklistSource); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	stmt, err := tx.PrepareContext(ctx,
		`INSERT OR IGNORE INTO dns_blocklist (domain, category, source, added_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	inserted := 0
	for _, r := range rows {
		d := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(r.Domain, ".")))
		if d == "" {
			continue
		}
		cat := strings.ToLower(strings.TrimSpace(r.Category))
		if cat == "" {
			cat = "malware"
		}
		if _, err := stmt.ExecContext(ctx, d, cat, blocklistSource); err != nil {
			return fmt.Errorf("insert %s: %w", d, err)
		}
		inserted++
	}

	// Record the hash for next-cycle change detection.
	if _, err := tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO tunnel_config (key, value)
		 VALUES ('blocklist_threat_feeds_hash', ?)`, newHash); err != nil {
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
