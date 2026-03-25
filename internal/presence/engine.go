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

type Logger interface {
Printf(format string, v ...any)
}

type Journal interface {
Append(ctx context.Context, evt contractevents.Event) error
}

type PolicyReader interface {
EnrolledMACs(ctx context.Context) map[string]bool
}

type Engine struct {
db      *sql.DB
logger  Logger
journal Journal
policy  PolicyReader

interval time.Duration

cancel context.CancelFunc
wg     sync.WaitGroup
}

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
d.LastSeen, _ = time.Parse(time.RFC3339, lastSeen)
d.Enrolled = enrolled == 1
devices = append(devices, d)
}
return devices, rows.Err()
}

// MACForIP returns the MAC for a given IP from the device registry.
func (e *Engine) MACForIP(ip string) (string, bool) {
var mac string
err := e.db.QueryRowContext(context.Background(),
`SELECT mac FROM device_registry WHERE ip = ? ORDER BY last_seen DESC LIMIT 1`, ip,
).Scan(&mac)
if err != nil || mac == "" {
return "", false
}
return mac, true
}

func (e *Engine) scan(ctx context.Context) {
arpEntries, err := readARP()
if err != nil {
e.logger.Printf("[presence] arp read failed: %v", err)
return
}

hostByIP := readLeases()
enrolled := e.policy.EnrolledMACs(ctx)
now := time.Now().UTC()

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
ip        = excluded.ip,
hostname  = CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE hostname END,
last_seen = excluded.last_seen,
enrolled  = excluded.enrolled
`, mac, ip, hostname, nowStr, nowStr, enrolledInt)
if err != nil {
return false, fmt.Errorf("upsert device_registry: %w", err)
}

_, _ = result.RowsAffected()

var firstSeen, lastSeen string
_ = e.db.QueryRowContext(ctx,
`SELECT first_seen, last_seen FROM device_registry WHERE mac = ?`, mac,
).Scan(&firstSeen, &lastSeen)
isNew = firstSeen == lastSeen

return isNew, nil
}

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
