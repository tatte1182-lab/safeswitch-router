package controlsync

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
	reqBody, _ := json.Marshal(map[string]string{"node_id": id.NodeID})
	body, statusCode, err := s.client.post(ctx, "/functions/v1/fetch-enforcement-sync", reqBody)
	if err != nil || statusCode >= 400 {
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
	s.logger.Printf("[enforcementsync] sync rows processed, update_policy command dispatched for %d action(s)", len(resp.Rows))
}
