package controlsync

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/dns"
)

const (
	// activityWriterBufSize is the max queued block events before oldest are
	// dropped. DNS resolution must never block on logging.
	activityWriterBufSize = 512

	// activityFlushInterval is how often the writer batches and flushes to Supabase.
	activityFlushInterval = 10 * time.Second
)

// ActivityWriter implements dns.BlockSink.
// RecordBlock is non-blocking. A background goroutine batches and flushes
// events to the Supabase activity_log table every activityFlushInterval.
type ActivityWriter struct {
	svc *Service
	ch  chan dns.BlockEvent
}

// NewActivityWriter creates an ActivityWriter and starts its flush goroutine.
// The goroutine is tracked by svc.wg and exits when ctx is cancelled.
func (s *Service) NewActivityWriter(ctx context.Context) *ActivityWriter {
	aw := &ActivityWriter{
		svc: s,
		ch:  make(chan dns.BlockEvent, activityWriterBufSize),
	}
	s.wg.Add(1)
	go aw.run(ctx)
	return aw
}

// RecordBlock satisfies dns.BlockSink. Never blocks — drops if buffer full.
func (aw *ActivityWriter) RecordBlock(evt dns.BlockEvent) {
	select {
	case aw.ch <- evt:
	default:
		// buffer full — drop silently, DNS path must not stall
	}
}

func (aw *ActivityWriter) run(ctx context.Context) {
	defer aw.svc.wg.Done()
	ticker := time.NewTicker(activityFlushInterval)
	defer ticker.Stop()

	var batch []dns.BlockEvent

	for {
		select {
		case <-ctx.Done():
			draining := true
			for draining {
				select {
				case evt := <-aw.ch:
					batch = append(batch, evt)
				default:
					draining = false
				}
			}
			if len(batch) > 0 {
				aw.flush(context.Background(), batch)
			}
			return

		case evt := <-aw.ch:
			batch = append(batch, evt)

		case <-ticker.C:
			draining := true
			for draining {
				select {
				case evt := <-aw.ch:
					batch = append(batch, evt)
				default:
					draining = false
				}
			}
			if len(batch) == 0 {
				continue
			}
			aw.flush(ctx, batch)
			batch = batch[:0]
		}
	}
}

// activityLogRow matches the activity_log INSERT columns.
//
// Field rationale:
//   - family_id      : already worked, kept.
//   - event_type     : "dns_blocked" — unchanged taxonomy.
//   - title          : human-readable.
//   - domain_blocked : the blocked domain.
//   - severity       : "info" — the child app uses protection_class, not
//                      severity, for shield filtering. Severity stays as
//                      a parent-side signal.
//   - threat_category: NEW — pulled from BlockEvent.Category. The server-
//                      side trigger maps this to protection_class for the
//                      child shield.
//   - actor_kind     : NEW — "system" so the activity feed RPC can route
//                      it to the system tab, not the parent-action tab.
//   - metadata       : NEW — carries src_ip. The existing trigger
//                      resolve_activity_log_src_ip BEFORE INSERT looks
//                      this up against devices.wireguard_ip to populate
//                      child_id and device_id. Without this, those FKs
//                      stay NULL and the child app can't find its own
//                      events. THIS WAS THE PRIMARY BUG.
type activityLogRow struct {
	FamilyID       string                 `json:"family_id"`
	EventType      string                 `json:"event_type"`
	Title          string                 `json:"title"`
	DomainBlocked  string                 `json:"domain_blocked"`
	Severity       string                 `json:"severity"`
	ThreatCategory string                 `json:"threat_category,omitempty"`
	ActorKind      string                 `json:"actor_kind"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

func (aw *ActivityWriter) flush(ctx context.Context, batch []dns.BlockEvent) {
	familyID := aw.svc.loadFamilyID(ctx)
	if familyID == "" {
		return
	}

	// Deduplicate within batch — one row per (domain, src_ip) pair per
	// flush window. We MUST include src_ip in the dedup key now that we
	// track per-child events: if two kids hit the same domain in the same
	// window, they're separate events and both should log.
	type dedupKey struct{ domain, srcIP string }
	seen := make(map[dedupKey]struct{}, len(batch))
	rows := make([]activityLogRow, 0, len(batch))

	for _, evt := range batch {
		domain := strings.ToLower(evt.Domain)
		if domain == "" {
			continue
		}
		k := dedupKey{domain: domain, srcIP: evt.SrcIP}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}

		row := activityLogRow{
			FamilyID:      familyID,
			EventType:     "dns_blocked",
			Title:         "Blocked: " + domain,
			DomainBlocked: domain,
			Severity:      "info",
			ActorKind:     "system",
		}
		// Only set threat_category if we actually have one — empty string
		// would override the server trigger logic. omitempty handles JSON.
		if evt.Category != "" {
			row.ThreatCategory = strings.ToLower(evt.Category)
		}
		// src_ip is what the BEFORE INSERT trigger uses to resolve child_id
		// and device_id from devices.wireguard_ip.
		if evt.SrcIP != "" {
			row.Metadata = map[string]interface{}{
				"src_ip": evt.SrcIP,
			}
		}
		rows = append(rows, row)
	}

	if len(rows) == 0 {
		return
	}

	raw, err := json.Marshal(rows)
	if err != nil {
		aw.svc.logger.Printf("[activity_writer] marshal failed: %v", err)
		return
	}

	// Short timeout so a slow Supabase response doesn't delay the next flush
	flushCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// IMPORTANT: "return=minimal" not "resolution=ignore-duplicates".
	// The latter triggers a PostgREST RLS recheck path that returns 401
	// even with service_role. "return=minimal" tells PostgREST not to
	// echo the inserted rows back, which is what we want for a fire-and-
	// forget writer. Documented in router memory; do not regress.
	_, status, err := aw.svc.client.postRESTPrefer(
		flushCtx,
		"/rest/v1/activity_log",
		"return=minimal",
		raw,
	)
	if err != nil || status >= 400 {
		aw.svc.logger.Printf("[activity_writer] flush failed status=%d domains=%d: %v",
			status, len(rows), err)
		return
	}

	aw.svc.logger.Printf("[activity_writer] flushed domains=%d", len(rows))
}

// postRESTPrefer posts to the Supabase REST API with a Prefer header.
// Single attempt — callers handle retry policy themselves.
func (c *client) postRESTPrefer(ctx context.Context, path, prefer string, body []byte) ([]byte, int, error) {
	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.serviceRoleKey)
	req.Header.Set("apikey", c.serviceRoleKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Prefer", prefer)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, nil
}
