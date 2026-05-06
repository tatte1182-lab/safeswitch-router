package controlsync

import (
	"context"
	"encoding/json"
	"time"
)

// fallbackNotifyPayload is the body the relay-fallback-state edge
// function expects. Mirrors the Deno function's Payload interface.
type fallbackNotifyPayload struct {
	FamilyID   string `json:"family_id"`
	InFallback bool   `json:"in_fallback"`
	NodeID     string `json:"node_id"`
	OccurredAt string `json:"occurred_at"`
}

// NotifyFamilyFallback satisfies relay.CloudNotifier. Best-effort
// publish — failures are logged, never returned. The relay's data
// path must not be coupled to Supabase availability.
//
// The edge function debounces inside a 5s window so we don't need
// to throttle here. Each transition fires immediately.
func (s *Service) NotifyFamilyFallback(ctx context.Context, familyID string, inFallback bool) {
	if familyID == "" {
		return
	}

	body, err := json.Marshal(fallbackNotifyPayload{
		FamilyID:   familyID,
		InFallback: inFallback,
		NodeID:     s.identity.Current().NodeID,
		OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		s.logger.Printf("[fallback-notify] marshal: %v", err)
		return
	}

	// Path convention matches heartbeat.go: edge functions live
	// under /functions/v1/<name>. Auth (Bearer = nodeToken) is
	// handled inside client.post.
	_, status, err := s.client.post(ctx, "/functions/v1/relay-fallback-state", body)
	if err != nil {
		s.logger.Printf("[fallback-notify] post family=%s in_fallback=%v: %v",
			familyID, inFallback, err)
		return
	}
	if status >= 400 {
		s.logger.Printf("[fallback-notify] non-2xx family=%s in_fallback=%v status=%d",
			familyID, inFallback, status)
	}
}