package presence

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	contractevents "github.com/getsafeswitch/safeswitch-router/pkg/contract/events"
)

// Logger is the minimal logging interface the engine needs.
type Logger interface {
	Printf(format string, v ...any)
}

// Journal is the subset of events.Journal the engine uses.
type Journal interface {
	Append(ctx context.Context, evt contractevents.Event) error
}

// PolicyReader lets the engine check which MACs belong to enrolled children
// without importing the full policy package (avoids circular deps).
type PolicyReader interface {
	// EnrolledMACs returns the set of device MACs present in the active bundle.
	// Returns an empty map (not an error) when no bundle is loaded yet.
	EnrolledMACs(ctx context.Context) map[string]bool
}

// Engine watches the ARP table and DHCP leases on a ticker, upserts the
// local device_registry table, and emits a presence.device_seen event for
// every device that appears for the first time.
type Engine struct {
	db      *sql.DB
	logger  Logger
	journal Journal
	policy  PolicyReader

	interval time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewEngine constructs the presence engine. interval controls how often
// the ARP+lease scan runs (30s is a good production value).
func NewEngine(
	db *sql.DB,
	logger Logger,
	journal Journal,
	policy PolicyReader,
	interval time.Duration,
) *Engine {
	return &Engine{
		db:       db,
		logger:   logger,
		journal:  journal,
		policy:   policy,
		interval: interval,
	}
}

func (e *Engine) Name() string { return "presence-engine" }

func (e *Engine) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		ticker := time.NewTicker(e.interval)
		defer ticker.Stop()

		// scan immediately on start so the registry is populated fast
		e.scan(runCtx)

		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				e.scan(runCtx)
			}
		}
	}()

	e.logger.Printf("[presence] started interval=%s", e.interval)
	return nil
}

func (e *Engine) Stop(ctx context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
	return nil
}

func (e *Engine) Health(ctx context.Context) error { return nil }

// Devices returns a snapshot of all devices currently in the registry.
// Safe to call from the API handler concurrently with the scan loop.
func (e *Engine) Devices(ctx context.Context) ([]Device, error) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT mac, ip, hostname, first_seen, last_seen, enrolled
		FROM device_registry
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query device_registry: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var firstSeen, lastSeen string
		var enrolled int
		if err := rows.Scan(&d.MAC, &d.IP, &d.Hostname, &firstSeen, &lastSeen, &enrolled); err != nil {
			return nil, fmt.Errorf("scan device row: %w", err)
		}
		d.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
		d.LastSeen, _  = time.Parse(time.RFC3339, lastSeen)
		d.Enrolled = enrolled == 1
		devices = append(devices, d)
	}
	return devices, rows.Err()
}

// scan is the core work loop: read ARP table, enrich with lease hostnames,
// cross-ref with enrolled MACs from policy, upsert into device_registry.
func (e *Engine) scan(ctx context.Context) {
	arpEntries, err := readARP()
	if err != nil {
		e.logger.Printf("[presence] arp read failed: %v", err)
		return
	}

	hostByIP := readLeases()
	enrolled := e.policy.EnrolledMACs(ctx)
	now      := time.Now().UTC()

	for _, entry := range arpEntries {
		hostname := hostByIP[entry.IP]
		isEnrolled := enrolled[entry.MAC]

		isNew, err := e.upsert(ctx, entry.MAC, entry.IP, hostname, isEnrolled, now)
		if err != nil {
			e.logger.Printf("[presence] upsert failed mac=%s: %v", entry.MAC, err)
			continue
		}

		if isNew {
			e.logger.Printf("[presence] new device mac=%s ip=%s hostname=%q enrolled=%v",
				entry.MAC, entry.IP, hostname, isEnrolled)
			e.emitDeviceSeen(ctx, entry.MAC, entry.IP, hostname)
		}
	}

	e.logger.Printf("[presence] scan complete devices=%d", len(arpEntries))
}

// upsert inserts a new device or updates an existing one.
// Returns true if this is the first time we've seen this MAC.
func (e *Engine) upsert(ctx context.Context, mac, ip, hostname string, enrolled bool, now time.Time) (isNew bool, err error) {
	enrolledInt := 0
	if enrolled {
		enrolledInt = 1
	}

	nowStr := now.Format(time.RFC3339)

	result, err := e.db.ExecContext(ctx, `
		INSERT INTO device_registry (mac, ip, hostname, first_seen, last_seen, enrolled)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(mac) DO UPDATE SET
			ip       = excluded.ip,
			hostname = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
			last_seen = excluded.last_seen,
			enrolled = excluded.enrolled
	`, mac, ip, hostname, nowStr, nowStr, enrolledInt)
	if err != nil {
		return false, fmt.Errorf("upsert device_registry: %w", err)
	}

	rows, _ := result.RowsAffected()
	// RowsAffected == 1 on pure INSERT (new row), > 1 or different on UPDATE.
	// SQLite returns 1 for both INSERT and UPDATE via ON CONFLICT DO UPDATE,
	// so we use LastInsertId: it is non-zero only on a real INSERT.
	lastID, _ := result.LastInsertId()
	isNew = lastID > 0 && rows == 1

	// Double-check by querying first_seen == last_seen (only true on first insert)
	// This is more reliable than LastInsertId behaviour across drivers.
	var firstSeen, lastSeen string
	_ = e.db.QueryRowContext(ctx,
		`SELECT first_seen, last_seen FROM device_registry WHERE mac = ?`, mac,
	).Scan(&firstSeen, &lastSeen)
	isNew = firstSeen == lastSeen

	return isNew, nil
}

// emitDeviceSeen writes a presence.device_seen event to the journal.
func (e *Engine) emitDeviceSeen(ctx context.Context, mac, ip, hostname string) {
	payload := map[string]any{
		"mac":      mac,
		"ip":       ip,
		"hostname": hostname,
	}
	raw, _ := json.Marshal(payload)
	_ = e.journal.Append(ctx, contractevents.Event{
		ID:       uuid.NewString(),
		Type:     "presence.device_seen",
		Severity: "info",
		Payload:  json.RawMessage(raw),
	})
}
