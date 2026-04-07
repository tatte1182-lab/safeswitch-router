package controlsync

// enforcementsync.go
//
// Dedicated goroutine that polls for pending enforcement actions every 3s.
// Calls the fetch-enforcement-sync Edge Function (same auth as heartbeat)
// which atomically returns + acks pending enforcement_sync_log rows.
//
// When rows are found (pause/unpause/dns_profile/route_profile):
//   1. Fetches the latest policy bundle immediately
//   2. Bundle swap applies iptables rules for affected devices
//
// Worst-case enforcement lag: ~4 seconds (3s poll + ~1s bundle fetch)
// Previous lag: up to 30 seconds (heartbeat-driven bundle fetch)
//
// Applies to ALL devices routed through this node:
//   - Android phones (child app)
//   - Laptops (via WireGuard full tunnel)
//   - Sentinel desktop (when tunnelled)

import (
	"context"
	"encoding/json"
	"time"
)

const enforcementPollEvery = 3 * time.Second

type syncRow struct {
	ID        string         `json:"id"`
	SyncType  string         `json:"sync_type"`
	ChildID   string         `json:"child_id"`
	DeviceID  string         `json:"device_id"`
	Payload   map[string]any `json:"payload"`
	DedupeKey string         `json:"dedupe_key"`
	CreatedAt string         `json:"created_at"`
}

type enforcementSyncResponse struct {
	Rows  []syncRow `json:"rows"`
	Acked int       `json:"acked"`
}

func (s *Service) runEnforcementSync(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(enforcementPollEvery)
	defer ticker.Stop()

	s.logger.Printf("[enforcementsync] started poll_every=%s", enforcementPollEvery)

	for {
		select {
		case <-ctx.Done():
			s.logger.Printf("[enforcementsync] stopped")
			return
		case <-ticker.C:
			s.pollAndEnforce(ctx)
		}
	}
}

func (s *Service) pollAndEnforce(ctx context.Context) {
	id := s.identity.Current()
	if id.NodeID == "" {
		return
	}

	// Call fetch-enforcement-sync — uses nodeToken auth (same as heartbeat)
	reqBody, _ := json.Marshal(map[string]string{"node_id": id.NodeID})
	body, statusCode, err := s.client.post(ctx, "/functions/v1/fetch-enforcement-sync", reqBody)
	if err != nil || statusCode >= 400 {
		// Silent on 404 — endpoint may not be deployed yet on older installs
		return
	}

	var resp enforcementSyncResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		s.logger.Printf("[enforcementsync] parse failed: %v", err)
		return
	}

	if len(resp.Rows) == 0 {
		return
	}

	s.logger.Printf("[enforcementsync] %d pending row(s) acked=%d — applying bundle immediately",
		len(resp.Rows), resp.Acked)

	for _, row := range resp.Rows {
		s.logger.Printf("[enforcementsync] processing type=%s child=%s device=%s",
			row.SyncType, row.ChildID, row.DeviceID)
	}

	// Fetch latest policy bundle — this is what actually applies iptables
	// pause/unpause rules, DNS profiles, and route modes for affected devices.
	s.fetchBundle(ctx)

	s.logger.Printf("[enforcementsync] bundle applied for %d enforcement action(s)", len(resp.Rows))
}
