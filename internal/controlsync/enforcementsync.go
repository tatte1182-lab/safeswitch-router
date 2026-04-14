package controlsync

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

const (
	enforcementPollEvery = 3 * time.Second
	enforcementTimeout   = 5 * time.Second
	bundleCooldown       = 2 * time.Second
)

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

	var lastBundleApply time.Time
	dedupe := make(map[string]time.Time)
	var mu sync.Mutex

	for {
		select {
		case <-ctx.Done():
			s.logger.Printf("[enforcementsync] stopped")
			return

		case <-ticker.C:
			s.pollAndEnforce(ctx, dedupe, &mu, &lastBundleApply)
		}
	}
}

func (s *Service) pollAndEnforce(
	ctx context.Context,
	dedupe map[string]time.Time,
	mu *sync.Mutex,
	lastBundleApply *time.Time,
) {

	id := s.identity.Current()
	if id.NodeID == "" {
		return
	}

	reqCtx, cancel := context.WithTimeout(ctx, enforcementTimeout)
	defer cancel()

	reqBody, _ := json.Marshal(map[string]string{"node_id": id.NodeID})

	body, statusCode, err := s.client.post(reqCtx, "/functions/v1/fetch-enforcement-sync", reqBody)
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

	// 🔒 dedupe recent actions (avoid replay storms)
	filtered := make([]syncRow, 0, len(resp.Rows))

	mu.Lock()
	now := time.Now()

	for k, t := range dedupe {
		if now.Sub(t) > 30*time.Second {
			delete(dedupe, k)
		}
	}

	for _, row := range resp.Rows {
		key := row.DedupeKey
		if key == "" {
			key = row.ID
		}

		if _, exists := dedupe[key]; exists {
			continue
		}

		dedupe[key] = now
		filtered = append(filtered, row)
	}
	mu.Unlock()

	if len(filtered) == 0 {
		return
	}

	s.logger.Printf("[enforcementsync] %d new enforcement(s) — applying bundle", len(filtered))

	// 🔥 cooldown to prevent bundle thrashing
	if time.Since(*lastBundleApply) < bundleCooldown {
		s.logger.Printf("[enforcementsync] bundle cooldown active — skipping")
		return
	}

	s.fetchBundle(ctx)
	*lastBundleApply = time.Now()

	s.logger.Printf("[enforcementsync] bundle applied for %d enforcement(s)", len(filtered))
}