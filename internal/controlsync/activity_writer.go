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

// activityWriterBufSize is the max queued block events before oldest are
// dropped. DNS resolution must never block on logging.
const activityWriterBufSize = 512

// activityFlushInterval controls how often queued events are sent to Supabase.
const activityFlushInterval = 10 * time.Second

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
type activityLogRow struct {
	FamilyID      string `json:"family_id"`
	EventType     string `json:"event_type"`
	Title         string `json:"title"`
	DomainBlocked string `json:"domain_blocked"`
	Severity      string `json:"severity"`
}

func (aw *ActivityWriter) flush(ctx context.Context, batch []dns.BlockEvent) {
	familyID := aw.svc.loadFamilyID(ctx)
	if familyID == "" {
		return
	}

	// Deduplicate within batch — one row per unique domain per flush window
	seen := make(map[string]struct{}, len(batch))
	rows := make([]activityLogRow, 0, len(batch))
	for _, evt := range batch {
		domain := strings.ToLower(evt.Domain)
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		rows = append(rows, activityLogRow{
			FamilyID:      familyID,
			EventType:     "dns_blocked",
			Title:         "Blocked: " + domain,
			DomainBlocked: domain,
			Severity:      "info",
		})
	}

	raw, err := json.Marshal(rows)
	if err != nil {
		aw.svc.logger.Printf("[activity_writer] marshal failed: %v", err)
		return
	}

	// Short timeout so a slow Supabase response doesn't delay the next flush
	flushCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	_, status, err := aw.svc.client.postRESTPrefer(
		flushCtx,
		"/rest/v1/activity_log",
		raw,
		"resolution=ignore-duplicates",
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
	req.Header.Set("Authorization", "Bearer "+c.anonKey)
	req.Header.Set("apikey", c.anonKey)
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
