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
		s.logger.Printf("[controlsync] bundle parse failed: %v", err)
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
		s.logger.Printf("[controlsync] bundle swap failed: %v", err)
		return
	}

	s.logger.Printf("[controlsync] bundle updated version=%s children=%d", b.Version, len(b.Children))
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