package controlsync

import (
"context"
"encoding/json"
"time"

contractevents "github.com/getsafeswitch/safeswitch-router/pkg/contract/events"
"github.com/getsafeswitch/safeswitch-router/pkg/version"
)

type heartbeatPayload struct {
NodeID              string  `json:"node_id"`
NodeName            string  `json:"node_name"`
Version             string  `json:"version"`
UptimeSeconds       int64   `json:"uptime_seconds"`
CPUPct              float64 `json:"cpu_pct"`
MemPct              float64 `json:"mem_pct"`
DiskPct             float64 `json:"disk_pct"`
TunnelPeerCount     int     `json:"tunnel_peer_count"`
ActiveBundleVersion string  `json:"active_bundle_version"`
DeviceCount         int     `json:"device_count"`
}

func (s *Service) runHeartbeat(ctx context.Context) {
defer s.wg.Done()
startedAt := time.Now()
ticker := time.NewTicker(s.heartbeatEvery)
defer ticker.Stop()
s.sendHeartbeat(ctx, startedAt)
for {
select {
case <-ctx.Done():
return
case <-ticker.C:
s.sendHeartbeat(ctx, startedAt)
}
}
}

func (s *Service) sendHeartbeat(ctx context.Context, startedAt time.Time) {
id := s.identity.Current()
cpu, mem, disk := s.latestHealth(ctx)
bundleVersion := "none"
if b, err := s.policyRuntime.ActiveBundle(ctx); err == nil && b != nil {
bundleVersion = b.Version
}
tunnelPeers := s.tunnelPeerCount(ctx)
deviceCount := s.deviceCount(ctx)
payload := heartbeatPayload{
NodeID:              id.NodeID,
NodeName:            id.NodeName,
Version:             version.Version,
UptimeSeconds:       int64(time.Since(startedAt).Seconds()),
CPUPct:              cpu,
MemPct:              mem,
DiskPct:             disk,
TunnelPeerCount:     tunnelPeers,
ActiveBundleVersion: bundleVersion,
DeviceCount:         deviceCount,
}
raw, err := json.Marshal(payload)
if err != nil {
s.logger.Printf("[controlsync] heartbeat marshal failed: %v", err)
return
}
_, status, err := s.client.post(ctx, "/functions/v1/node-heartbeat", raw)
if err != nil {
s.logger.Printf("[controlsync] heartbeat failed status=%d: %v", status, err)
} else {
s.logger.Printf("[controlsync] heartbeat sent node_id=%s uptime=%ds bundle=%s peers=%d devices=%d",
id.NodeID, payload.UptimeSeconds, bundleVersion, tunnelPeers, deviceCount)
}
_ = s.journal.Append(ctx, contractevents.Event{
Type:     "node.heartbeat.sent",
Severity: "info",
Payload: map[string]any{
"node_id": id.NodeID,
"uptime":  payload.UptimeSeconds,
"bundle":  bundleVersion,
},
})
}

func (s *Service) latestHealth(ctx context.Context) (cpu, mem, disk float64) {
_ = s.db.QueryRowContext(ctx,
`SELECT cpu_pct, mem_pct, disk_pct FROM health_snapshots ORDER BY id DESC LIMIT 1`,
).Scan(&cpu, &mem, &disk)
return
}

func (s *Service) tunnelPeerCount(ctx context.Context) int {
var count int
_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tunnel_peers`).Scan(&count)
return count
}

func (s *Service) deviceCount(ctx context.Context) int {
var count int
_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_registry`).Scan(&count)
return count
}
