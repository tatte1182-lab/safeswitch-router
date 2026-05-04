package controlsync

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	policybundle "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

const (
	bundleFetchTimeout = 8 * time.Second
	bundleRetryCount   = 3
)

// TunnelSyncer is implemented by tunnel.Manager. Declared here to avoid
// an import cycle between controlsync and tunnel packages.
type TunnelSyncer interface {
	TriggerSync(ctx context.Context) error
	RemovePeersByChildID(ctx context.Context, childID string) error
}

func (s *Service) fetchBundle(ctx context.Context) {
	id := s.identity.Current()
	path := fmt.Sprintf("/functions/v1/node-policy-bundle?node_id=%s", id.NodeID)

	var body []byte
	var status int
	var err error

	// 🔁 retry (critical)
	for i := 0; i < bundleRetryCount; i++ {

		reqCtx, cancel := context.WithTimeout(ctx, bundleFetchTimeout)
		body, status, err = s.client.get(reqCtx, path)
		cancel()

		if err == nil && status < 400 {
			break
		}

		time.Sleep(time.Duration(i+1) * 300 * time.Millisecond)
	}

	if err != nil || status >= 400 {
		s.logger.Printf("[controlsync] bundle fetch failed status=%d: %v", status, err)
		return
	}

	var b policybundle.Bundle
	if err := json.Unmarshal(body, &b); err != nil {
		// Log up to 512 bytes of the raw body so we can see what the Edge Function returned
		preview := string(body)
		if len(preview) > 512 {
			preview = preview[:512] + "…"
		}
		s.logger.Printf("[controlsync] bundle parse failed: %v | body: %s", err, preview)
		return
	}

	if b.Version == "" {
		s.logger.Printf("[controlsync] bundle missing version - skipping")
		return
	}

	// 🔒 expiry protection (critical)
	if !b.ExpiresAt.IsZero() && time.Now().After(b.ExpiresAt) {
		s.logger.Printf("[controlsync] bundle expired version=%s - skipping", b.Version)
		return
	}

	current, err := s.policyRuntime.ActiveBundle(ctx)

	// ⚡ stronger change detection
	if err == nil && current != nil {
		if current.Version == b.Version &&
			len(current.Children) == len(b.Children) &&
			current.ExpiresAt.Equal(b.ExpiresAt) {
			return
		}
	}

	if err := s.policyRuntime.SwapBundle(ctx, &b); err != nil {
		s.logger.Printf("[controlsync] bundle swap failed version=%s children=%d: %v",
			b.Version, len(b.Children), err)
		return
	}

	s.logger.Printf("[controlsync] bundle updated version=%s children=%d", b.Version, len(b.Children))

	// Immediately push new peer set to wg0 — don't wait for the 60s tunnel ticker.
	if s.nodeType != "vps_relay" && s.tunnel != nil {
		if err := s.tunnel.TriggerSync(ctx); err != nil {
			s.logger.Printf("[controlsync] tunnel sync after bundle swap: %v", err)
		}
	}
}

// ---- Bootstrap bundle (used for safe startup fallback) ----

type bootstrapBundle struct {
	version   string
	issuedAt  time.Time
	expiresAt time.Time
}

func (b *bootstrapBundle) toBundle() *policybundle.Bundle {
	return &policybundle.Bundle{
		Version:   b.version,
		IssuedAt:  b.issuedAt,
		ExpiresAt: b.expiresAt,
		Signature: "bootstrap-local",
		Children:  []policybundle.ChildEffectiveState{},
	}
}

// ---- Bootstrap bundle (used for safe startup fallback) ----

// runBundleFetch polls Supabase for a fresh policy bundle every 30s.
// This is the periodic path — enforcementsync also calls fetchBundle
// reactively when enforcement rows arrive, but this ensures the bundle
// is always current even when no enforcement events are queued.
func (s *Service) runBundleFetch(ctx context.Context) {
	defer s.wg.Done()

	// Fetch immediately on start so peers load without waiting 30s.
	s.fetchBundle(ctx)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.fetchBundle(ctx)
		}
	}
}
