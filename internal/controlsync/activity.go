package controlsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/dns"
)

const (
	activityFlushInterval = 10 * time.Second
	activityBatchMax      = 50  // max rows per flush
	activityChanCap       = 500 // drop-on-full rather than block the DNS path
)

// activityRow is a single row for the activity_log bulk insert.
type activityRow struct {
	FamilyID  string `json:"family_id"`
	ChildID   string `json:"child_id,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
	EventType string `json:"event_type"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Domain    string `json:"domain_blocked,omitempty"`
	Metadata  string `json:"metadata,omitempty"`
}

// ActivitySink implements dns.BlockSink.
// It enqueues block events and a background goroutine flushes them to Supabase.
type ActivitySink struct {
	ch     chan dns.BlockEvent
	db     *sql.DB
	client *client
	logger interface{ Printf(string, ...any) }
}

func NewActivitySink(
	db *sql.DB,
	client *client,
	logger interface{ Printf(string, ...any) },
) *ActivitySink {
	return &ActivitySink{
		ch:     make(chan dns.BlockEvent, activityChanCap),
		db:     db,
		client: client,
		logger: logger,
	}
}

// RecordBlock is called by the DNS resolver on every blocked query.
// Non-blocking: drops the event if the buffer is full.
func (a *ActivitySink) RecordBlock(evt dns.BlockEvent) {
	select {
	case a.ch <- evt:
	default:
		// Buffer full — drop rather than slow the DNS path
	}
}

// Run drains the channel and flushes to Supabase on a ticker.
// Call as a goroutine; returns when ctx is cancelled.
func (a *ActivitySink) Run(ctx context.Context) {
	ticker := time.NewTicker(activityFlushInterval)
	defer ticker.Stop()

	var pending []dns.BlockEvent

	flush := func() {
		if len(pending) == 0 {
			return
		}
		batch := pending
		if len(batch) > activityBatchMax {
			batch = batch[:activityBatchMax]
			pending = pending[activityBatchMax:]
		} else {
			pending = pending[:0]
		}
		a.flush(ctx, batch)
	}

	for {
		select {
		case <-ctx.Done():
			// Final flush on shutdown
			for {
				select {
				case evt := <-a.ch:
					pending = append(pending, evt)
				default:
					goto done
				}
			}
		done:
			flush()
			return

		case evt := <-a.ch:
			pending = append(pending, evt)
			// Eager flush if batch is full
			if len(pending) >= activityBatchMax {
				flush()
			}

		case <-ticker.C:
			flush()
		}
	}
}

// flush resolves device/child IDs for each event and bulk-inserts to activity_log.
func (a *ActivitySink) flush(ctx context.Context, events []dns.BlockEvent) {
	familyID := a.loadFamilyID(ctx)

	rows := make([]activityRow, 0, len(events))
	for _, evt := range events {
		childID, deviceID := a.lookupDevice(ctx, evt.SrcIP)
		row := activityRow{
			FamilyID:  familyID,
			ChildID:   childID,
			DeviceID:  deviceID,
			EventType: "dns_blocked",
			Title:     fmt.Sprintf("Blocked: %s", evt.Domain),
			Severity:  "info",
			Domain:    evt.Domain,
			Metadata:  fmt.Sprintf(`{"src_ip":%q}`, evt.SrcIP),
		}
		rows = append(rows, row)
	}

	body, err := json.Marshal(rows)
	if err != nil {
		a.logger.Printf("[activity] marshal failed: %v", err)
		return
	}

	_, status, err := a.client.postREST(ctx, "/rest/v1/activity_log", body)
	if err != nil || status >= 400 {
		a.logger.Printf("[activity] flush failed status=%d rows=%d: %v", status, len(rows), err)
		return
	}
	a.logger.Printf("[activity] flushed dns_blocked rows=%d", len(rows))
}

// lookupDevice maps a WireGuard srcIP to child_id + device_id via local SQLite.
// Returns empty strings if not found — activity_log accepts nulls on both.
func (a *ActivitySink) lookupDevice(ctx context.Context, srcIP string) (childID, deviceID string) {
	// Strip /32 suffix if present (tunnel_peers stores IPs with prefix)
	ip := strings.TrimSuffix(srcIP, "/32")

	_ = a.db.QueryRowContext(ctx,
		`SELECT COALESCE(child_id,''), COALESCE(device_id,'')
		 FROM device_registry
		 WHERE wireguard_ip = ? OR wireguard_ip = ?
		 LIMIT 1`,
		ip, ip+"/32",
	).Scan(&childID, &deviceID)
	return
}

func (a *ActivitySink) loadFamilyID(ctx context.Context) string {
	var id string
	_ = a.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'family_id'`,
	).Scan(&id)
	return id
}
