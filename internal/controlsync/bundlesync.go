package controlsync
import (
"context"
"encoding/json"
"fmt"
"time"

policybundle "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

func (s *Service) fetchBundle(ctx context.Context) {
id := s.identity.Current()
path := fmt.Sprintf("/functions/v1/node-policy-bundle?node_id=%s", id.NodeID)
body, status, err := s.client.get(ctx, path)
if err != nil {
s.logger.Printf("[controlsync] bundle fetch failed status=%d: %v", status, err)
return
}
var b policybundle.Bundle
if err := json.Unmarshal(body, &b); err != nil {
s.logger.Printf("[controlsync] bundle parse failed: %v", err)
return
}
if b.Version == "" {
s.logger.Printf("[controlsync] bundle response missing version - skipping")
return
}
current, err := s.policyRuntime.ActiveBundle(ctx)
if err == nil && current != nil && current.Version == b.Version && len(current.Children) == len(b.Children) {
s.logger.Printf("[controlsync] bundle version=%s children=%d already active - no swap needed", b.Version, len(b.Children))
return
}
if err := s.policyRuntime.SwapBundle(ctx, &b); err != nil {
s.logger.Printf("[controlsync] bundle swap failed: %v", err)
return
}
s.logger.Printf("[controlsync] bundle updated version=%s children=%d", b.Version, len(b.Children))
}

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
