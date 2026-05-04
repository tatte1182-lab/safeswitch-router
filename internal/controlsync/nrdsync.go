package controlsync

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// NRDReloader is implemented by *dns.NRDBlocklist. Declared here to avoid
// import cycle. Mirror of DNSReloader in blocklistsync.go.
type NRDReloader interface {
	Reload(ctx context.Context) error
}

const (
	// NRDFeedURL is the canonical primary source. cenk.app refreshes once
	// per day around 08:15 UTC. No-auth, plain text, ~35 MB.
	NRDFeedURL = "https://dl.cenk.app/nrd/nrd-last-30-days.txt"

	// NRDSourceTag is the value written to nrd_blocklist.source. Layering
	// a second mirror later just uses a different tag.
	NRDSourceTag = "cenk_nrd_30d"

	// NRDIngestInterval — how often runNRDIngest fires after the first run.
	// cenk.app refreshes once per day; 23h gives slight cadence drift so
	// we don't pin to a fixed wall-clock minute forever.
	NRDIngestInterval = 23 * time.Hour

	// nrdFetchTimeout — hard cap on the cenk.app GET. The file is ~35 MB
	// and usually completes in 2-5s on reasonable networks.
	nrdFetchTimeout = 10 * time.Minute

	// nrdBatchSize — rows per Supabase upsert call. Each row is ~150 bytes
	// of JSON; 5000 rows ≈ 750 KB body, well under PostgREST's limits.
	nrdBatchSize = 5000

	// nrdMirrorPageSize — rows per page when pulling Supabase nrd_blocklist
	// via PostgREST Range header during the SQLite mirror sync.
	nrdMirrorPageSize = 50000

	// nrdHashKey — tunnel_config key for the SQLite mirror's freshness gate.
	// Naming mirrors blocklist_<source>_hash from the existing sync.
	nrdHashKey = "blocklist_nrd_hash"
)

// WithNRD wires the in-memory NRD blocklist so the SQLite mirror sync can
// trigger a reload after writes. Mirror of WithDNS().
func (s *Service) WithNRD(n NRDReloader) *Service {
	s.nrd = n
	return s
}

// runNRDIngest runs the daily cenk.app → Supabase ingest. Sibling of
// runBlocklistSync. Different cadence (23h vs 5m) — the source itself
// only refreshes daily, and the ingest is heavier (2 M rows vs ~24).
func (s *Service) runNRDIngest(ctx context.Context) {
	defer s.wg.Done()

	if s.nodeType == "vps_relay" {
		return
	}

	// First run 30s after startup — let the existing 5-min sync get its
	// first tick in before we kick off a heavy operation.
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if err := s.ingestNRDOnce(ctx); err != nil {
				s.logger.Printf("[nrd-ingest] error: %v", err)
				// Don't tight-loop. Wait an hour, try again.
				timer.Reset(1 * time.Hour)
				continue
			}
			timer.Reset(NRDIngestInterval)
		}
	}
}

// ingestNRDOnce executes one full ingest cycle: start audit row →
// fetch feed → batched upsert → prune stale → finalize audit.
//
// Idempotent. The prune step ensures the table reflects exactly what's
// in cenk.app's current 30-day window, so calling repeatedly converges.
func (s *Service) ingestNRDOnce(ctx context.Context) error {
	runID, err := s.nrdStartRun(ctx)
	if err != nil {
		return fmt.Errorf("start run: %w", err)
	}
	s.logger.Printf("[nrd-ingest] run %s started", runID)

	result, runErr := s.nrdRunInner(ctx)

	// Always finalize the audit row, even on error.
	if finErr := s.nrdFinalizeRun(ctx, runID, result, runErr); finErr != nil {
		s.logger.Printf("[nrd-ingest] WARN: finalize failed for %s: %v", runID, finErr)
	}
	if runErr != nil {
		return runErr
	}

	s.logger.Printf("[nrd-ingest] run %s done: fetched=%d upserted=%d pruned=%d",
		runID, result.fetched, result.upserted, result.pruned)
	return nil
}

type nrdRunResult struct {
	fetched        int
	upserted       int
	pruned         int
	sourceHash     string
	sourceModified string
}

func (s *Service) nrdRunInner(ctx context.Context) (*nrdRunResult, error) {
	result := &nrdRunResult{}
	runStartedAt := time.Now().UTC()

	// 1. Fetch the file as a stream (don't buffer 35 MB into memory).
	// We use a separate http.Client here, NOT s.client, because cenk.app
	// is a third-party host that doesn't share Supabase's auth or retry
	// semantics. s.client's retry policy would do the wrong thing here.
	fetchCtx, cancel := context.WithTimeout(ctx, nrdFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, "GET", NRDFeedURL, nil)
	if err != nil {
		return result, fmt.Errorf("build feed request: %w", err)
	}
	req.Header.Set("User-Agent", "SafeSwitch-NRD/1.0")
	req.Header.Set("Accept", "text/plain")

	feedClient := &http.Client{Timeout: nrdFetchTimeout}
	resp, err := feedClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("fetch %s: %w", NRDFeedURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("fetch %s: HTTP %d", NRDFeedURL, resp.StatusCode)
	}
	result.sourceModified = resp.Header.Get("Last-Modified")

	// 2. Stream-parse: hash + line-extract + batch in one pass.
	hasher := sha256.New()
	tee := io.TeeReader(resp.Body, hasher)
	scanner := bufio.NewScanner(tee)
	scanner.Buffer(make([]byte, 4096), 4096)

	batch := make([]string, 0, nrdBatchSize)
	for scanner.Scan() {
		domain := normalizeNRDLine(scanner.Text())
		if domain == "" {
			continue
		}
		batch = append(batch, domain)
		result.fetched++

		if len(batch) >= nrdBatchSize {
			if err := s.nrdUpsertBatch(ctx, batch, runStartedAt); err != nil {
				return result, fmt.Errorf("upsert at line %d: %w", result.fetched, err)
			}
			result.upserted += len(batch)
			batch = batch[:0]
		}
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("scan body: %w", err)
	}
	if len(batch) > 0 {
		if err := s.nrdUpsertBatch(ctx, batch, runStartedAt); err != nil {
			return result, fmt.Errorf("upsert final: %w", err)
		}
		result.upserted += len(batch)
	}
	result.sourceHash = hex.EncodeToString(hasher.Sum(nil))

	// 3. Prune: rows whose last_seen_at is older than this run's start
	// have aged out of cenk.app's window. Drop them.
	pruned, err := s.nrdPruneStale(ctx, runStartedAt)
	if err != nil {
		return result, fmt.Errorf("prune: %w", err)
	}
	result.pruned = pruned

	return result, nil
}

// normalizeNRDLine returns "" when the line should be skipped, otherwise
// a clean lowercase domain.
func normalizeNRDLine(line string) string {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	s = strings.ToLower(s)
	if strings.ContainsAny(s, " \t/?:") {
		return ""
	}
	if len(s) > 253 {
		return ""
	}
	return s
}

// nrdUpsertBatch sends one batch to Supabase.
//
// Strategy: INSERT … ON CONFLICT (domain) DO UPDATE last_seen_at.
// PostgREST's Prefer: resolution=merge-duplicates triggers the upsert.
// Service-role auth is required because nrd_blocklist has RLS enabled
// with no anon-write policy.
func (s *Service) nrdUpsertBatch(ctx context.Context, domains []string, runStartedAt time.Time) error {
	type row struct {
		Domain      string `json:"domain"`
		Source      string `json:"source"`
		FirstSeenAt string `json:"first_seen_at,omitempty"`
		LastSeenAt  string `json:"last_seen_at"`
	}

	tsStr := runStartedAt.Format(time.RFC3339Nano)
	rows := make([]row, len(domains))
	for i, d := range domains {
		rows[i] = row{
			Domain:      d,
			Source:      NRDSourceTag,
			FirstSeenAt: tsStr,
			LastSeenAt:  tsStr,
		}
	}

	body, err := json.Marshal(rows)
	if err != nil {
		return err
	}

	_, status, err := s.client.postREST(ctx, "/rest/v1/nrd_blocklist", body,
		withAuth(authServiceRole),
		withHeader("Prefer", "resolution=merge-duplicates,return=minimal"),
	)
	if err != nil {
		return fmt.Errorf("upsert POST: %w", err)
	}
	if status >= 300 {
		return fmt.Errorf("upsert HTTP %d", status)
	}
	return nil
}

// nrdPruneStale deletes rows in nrd_blocklist whose last_seen_at predates
// runStartedAt. Returns the deletion count via PostgREST's Content-Range.
func (s *Service) nrdPruneStale(ctx context.Context, runStartedAt time.Time) (int, error) {
	path := fmt.Sprintf("/rest/v1/nrd_blocklist?last_seen_at=lt.%s",
		runStartedAt.Format(time.RFC3339Nano))

	_, status, hdrs, err := s.client.deleteREST(ctx, path,
		withAuth(authServiceRole),
		withHeader("Prefer", "count=exact,return=minimal"),
		withRespHeaders(),
	)
	if err != nil {
		return 0, err
	}
	if status >= 300 {
		return 0, fmt.Errorf("prune HTTP %d", status)
	}

	// Content-Range: "0-N/TOTAL" or "*/TOTAL". The number after the slash
	// is the matched (and therefore deleted) row count.
	cr := hdrs.Get("Content-Range")
	if cr == "" {
		return 0, nil
	}
	slash := strings.Index(cr, "/")
	if slash < 0 || slash == len(cr)-1 {
		return 0, nil
	}
	var n int
	if _, err := fmt.Sscanf(cr[slash+1:], "%d", &n); err != nil {
		return 0, nil
	}
	return n, nil
}

// nrdStartRun inserts a row into nrd_ingest_runs and returns its UUID.
func (s *Service) nrdStartRun(ctx context.Context) (string, error) {
	body := []byte(fmt.Sprintf(`[{"source_url":%q,"status":"running"}]`, NRDFeedURL))

	respBody, status, err := s.client.postREST(ctx, "/rest/v1/nrd_ingest_runs", body,
		withAuth(authServiceRole),
		withHeader("Prefer", "return=representation"),
	)
	if err != nil {
		return "", err
	}
	if status >= 300 {
		return "", fmt.Errorf("start run HTTP %d", status)
	}
	var rows []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &rows); err != nil {
		return "", fmt.Errorf("decode run id: %w", err)
	}
	if len(rows) == 0 {
		return "", fmt.Errorf("start run: no row returned")
	}
	return rows[0].ID, nil
}

// nrdFinalizeRun PATCHes the audit row with totals and final status.
func (s *Service) nrdFinalizeRun(ctx context.Context, runID string, r *nrdRunResult, runErr error) error {
	patch := map[string]interface{}{
		"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
		"domains_fetched":  r.fetched,
		"domains_inserted": r.upserted,
		"domains_pruned":   r.pruned,
		"source_hash":      r.sourceHash,
		"source_modified":  r.sourceModified,
	}
	if runErr != nil {
		patch["status"] = "error"
		patch["error_message"] = runErr.Error()
	} else {
		patch["status"] = "ok"
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	path := fmt.Sprintf("/rest/v1/nrd_ingest_runs?id=eq.%s", runID)
	_, status, err := s.client.patchREST(ctx, path, body,
		withAuth(authServiceRole),
		withHeader("Prefer", "return=minimal"),
	)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("finalize HTTP %d", status)
	}
	return nil
}

// =========================================================================
// SQLite mirror sync — runs inside the existing 5-min blocklistsync loop.
// Uses anon auth: nrd_blocklist reads need to work for any node, and
// adding a SELECT policy for anon is cheaper than service-role here.
// (See migration in WIRING_v3.md for the policy.)
// =========================================================================

// syncNRDBlocklist pulls Supabase nrd_blocklist into the SQLite mirror.
// Hash-gated against tunnel_config.blocklist_nrd_hash.
//
// Returns (changed, error). changed=true means caller should reload the
// in-memory NRD lookup.
func (s *Service) syncNRDBlocklist(ctx context.Context) (bool, error) {
	domains, err := s.fetchAllNRDDomains(ctx)
	if err != nil {
		return false, fmt.Errorf("fetch from supabase: %w", err)
	}

	sort.Strings(domains)
	h := sha256.New()
	for _, d := range domains {
		h.Write([]byte(d))
		h.Write([]byte{'\n'})
	}
	newHash := hex.EncodeToString(h.Sum(nil))

	var lastHash string
	_ = s.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = ?`, nrdHashKey,
	).Scan(&lastHash)
	if lastHash == newHash {
		return false, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `DELETE FROM nrd_blocklist`); err != nil {
		return false, fmt.Errorf("clear nrd_blocklist: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO nrd_blocklist (domain) VALUES (?)`)
	if err != nil {
		return false, err
	}
	defer stmt.Close()
	for _, d := range domains {
		if _, err := stmt.ExecContext(ctx, d); err != nil {
			return false, fmt.Errorf("insert %q: %w", d, err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT OR REPLACE INTO tunnel_config (key, value) VALUES (?, ?)`,
		nrdHashKey, newHash); err != nil {
		return false, fmt.Errorf("hash write: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}

	s.logger.Printf("[blocklist-sync] applied source=nrd domains=%d hash=%s",
		len(domains), newHash[:8])
	return true, nil
}

// fetchAllNRDDomains pulls every row's domain from Supabase via
// PostgREST, paginated with Range headers. Each page caps response
// body size at ~1.3 MB.
func (s *Service) fetchAllNRDDomains(ctx context.Context) ([]string, error) {
	out := make([]string, 0, 2_500_000)
	offset := 0
	for {
		path := "/rest/v1/nrd_blocklist?select=domain&order=domain.asc"
		body, status, _, err := s.client.getRESTWithHeaders(ctx, path,
			withAuth(authServiceRole),
			withHeader("Range-Unit", "items"),
			withHeader("Range", fmt.Sprintf("%d-%d", offset, offset+nrdMirrorPageSize-1)),
		)
		if err != nil {
			return nil, fmt.Errorf("fetch page offset=%d: %w", offset, err)
		}
		if status == 416 {
			break // walked past end
		}
		if status != 200 && status != 206 {
			return nil, fmt.Errorf("page offset=%d HTTP %d", offset, status)
		}
		var rows []struct {
			Domain string `json:"domain"`
		}
		if err := json.Unmarshal(body, &rows); err != nil {
			return nil, fmt.Errorf("decode page offset=%d: %w", offset, err)
		}
		for _, r := range rows {
			out = append(out, r.Domain)
		}
		// PostgREST may cap responses below the requested page size
		// (default db-max-rows = 1000 on Supabase). Break only when the
		// server returns zero rows; advance by the count actually received,
		// not by the requested page size.
		if len(rows) == 0 {
			break
		}
		offset += len(rows)
	}
	return out, nil
}

// ensureNRDSchema creates the SQLite mirror table if missing. Call once at
// service startup, before runBlocklistSync starts.
func (s *Service) ensureNRDSchema(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS nrd_blocklist (
    domain TEXT PRIMARY KEY,
    source TEXT NOT NULL DEFAULT 'cenk_nrd_30d'
);
CREATE INDEX IF NOT EXISTS nrd_blocklist_source_idx ON nrd_blocklist (source);
`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("ensure nrd schema: %w", err)
	}
	return nil
}
