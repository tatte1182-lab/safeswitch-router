package controlsync

import (
	"context"
	"errors"

	"github.com/getsafeswitch/safeswitch-router/internal/terminator"
)

// FetchFamilyConfig retrieves the per-family terminator config used
// to bring up a fallback WireGuard endpoint on the VPS. Implements
// terminator.ConfigSource.
//
// STUB: the real implementation calls a Supabase edge function
// (`relay-family-config`) that returns the family's terminator
// private key, listen port, peer list, and category blocks. That
// edge function is on the roadmap but not yet built — see the
// "Build Supabase edge functions" task. Until it lands, this
// method returns ErrFamilyConfigNotImplemented and the bridge
// falls back to its silent-drop path (which is what production
// would have done anyway, before the terminator existed).
//
// When wiring up the real impl: POST {familyID} to
// {SyncBaseURL}/functions/v1/relay-family-config with the node
// token, decode the JSON response into a *terminator.FamilyConfig,
// return it. Cache the result for ~5 min — family configs change
// rarely (only on enrollment / device swap / preference change).
func (s *Service) FetchFamilyConfig(ctx context.Context, familyID string) (*terminator.FamilyConfig, error) {
	s.logger.Printf("[controlsync] FetchFamilyConfig called for family=%s but edge function not yet wired", familyID)
	return nil, ErrFamilyConfigNotImplemented
}

// NotifyFamilyFallback fires a one-shot event to the cloud telling
// it a family has entered or exited fallback mode. Implements
// relay.CloudNotifier.
//
// STUB: the real implementation POSTs to a Supabase edge function
// (`relay-fallback-state`) that updates the family_fallback_state
// row, which the parent app subscribes to via Supabase Realtime
// to show "running on backup" UX. Until that edge function lands
// this is a no-op log line. Best-effort by design — the data
// path doesn't depend on this succeeding.
func (s *Service) NotifyFamilyFallback(ctx context.Context, familyID string, inFallback bool) {
	state := "exit"
	if inFallback {
		state = "enter"
	}
	s.logger.Printf("[controlsync] family fallback %s family=%s (cloud notification stubbed)", state, familyID)
}

// ErrFamilyConfigNotImplemented signals to the terminator that
// family-config fetching isn't wired up yet. The bridge treats
// this as "no fallback available, drop the packet" which matches
// the original silent-drop behaviour.
var ErrFamilyConfigNotImplemented = errors.New("controlsync: relay-family-config edge function not yet implemented")