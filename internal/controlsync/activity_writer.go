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

const activityWriterBufSize = 512
const activityFlushInterval = 10 * time.Second

type ActivityWriter struct {
	svc *Service
	ch  chan dns.BlockEvent
}

func (s *Service) NewActivityWriter(ctx context.Context) *ActivityWriter {
	aw := &ActivityWriter{svc: s, ch: make(chan dns.BlockEvent, activityWriterBufSize)}
	s.wg.Add(1)
	go aw.run(ctx)
	return aw
}

func (aw *ActivityWriter) RecordBlock(evt dns.BlockEvent) {
	select {
	case aw.ch <- evt:
	default:
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
			for done := false; !done; {
				select {
				case e := <-aw.ch:
					batch = append(batch, e)
				default:
					done = true
				}
			}
			if len(batch) > 0 {
				aw.flush(context.Background(), batch)
			}
			return
		case e := <-aw.ch:
			batch = append(batch, e)
		case <-ticker.C:
			for done := false; !done; {
				select {
				case e := <-aw.ch:
					batch = append(batch, e)
				default:
					done = true
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
	seen := make(map[string]struct{}, len(batch))
	rows := make([]activityLogRow, 0, len(batch))
	for _, evt := range batch {
		d := strings.ToLower(evt.Domain)
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		rows = append(rows, activityLogRow{
			FamilyID:      familyID,
			EventType:     "dns_blocked",
			Title:         "Blocked: " + d,
			DomainBlocked: d,
			Severity:      "info",
		})
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		aw.svc.logger.Printf("[activity_writer] marshal failed: %v", err)
		return
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	// Wrap rows in {"p_rows": [...]} for the RPC
	import_json := append([]byte(`{"p_rows":`), append(raw, '}')...)
	_, status, err := aw.svc.client.postREST(flushCtx, "/rest/v1/rpc/insert_dns_block_activity", import_json)
	if err != nil || status >= 400 {
		aw.svc.logger.Printf("[activity_writer] flush failed status=%d domains=%d: %v", status, len(rows), err)
		return
	}
	aw.svc.logger.Printf("[activity_writer] flushed domains=%d", len(rows))
}

func (c *client) postRESTPrefer(ctx context.Context, path string, body []byte, prefer string) ([]byte, int, error) {
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
	body2, _ := io.ReadAll(resp.Body)
	return body2, resp.StatusCode, nil
}
