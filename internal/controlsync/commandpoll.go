package controlsync

import (
"context"
"encoding/json"
"fmt"
"time"

contractcmds "github.com/getsafeswitch/safeswitch-router/pkg/contract/commands"
)

type cloudCommand struct {
ID      string         `json:"id"`
Type    string         `json:"command_type"`
Payload map[string]any `json:"payload_json"`
Status  string         `json:"status"`
}

func (s *Service) runCommandPoll(ctx context.Context) {
defer s.wg.Done()
ticker := time.NewTicker(s.commandPollEvery)
defer ticker.Stop()
bootstrapped := false
for {
select {
case <-ctx.Done():
return
case <-ticker.C:
if !bootstrapped {
bootstrapped = true
s.seedBootstrapBundle(ctx)
}
s.fetchAndEnqueue(ctx)
s.drainPending(ctx)
}
}
}

func (s *Service) fetchAndEnqueue(ctx context.Context) {
id := s.identity.Current()
path := fmt.Sprintf("/functions/v1/node-commands?node_id=%s&status=pending", id.NodeID)
body, status, err := s.client.get(ctx, path)
if err != nil {
s.logger.Printf("[controlsync] command fetch failed status=%d: %v", status, err)
return
}
var cmds []cloudCommand
if err := json.Unmarshal(body, &cmds); err != nil {
s.logger.Printf("[controlsync] command parse failed: %v", err)
return
}
if len(cmds) == 0 {
return
}
s.logger.Printf("[controlsync] fetched %d command(s) from cloud", len(cmds))
for _, c := range cmds {
cmd := contractcmds.Command{
ID:      c.ID,
Type:    c.Type,
Payload: c.Payload,
}
if err := s.executor.Enqueue(ctx, cmd); err != nil {
s.logger.Printf("[controlsync] enqueue failed id=%s: %v", c.ID, err)
continue
}
if err := s.ackCommand(ctx, c.ID); err != nil {
s.logger.Printf("[controlsync] ack failed id=%s: %v", c.ID, err)
}
}
}

func (s *Service) ackCommand(ctx context.Context, id string) error {
path := fmt.Sprintf("/functions/v1/node-commands/%s", id)
body, _ := json.Marshal(map[string]string{"status": string(contractcmds.StatusAcked)})
_, status, err := s.client.patch(ctx, path, body)
if err != nil {
return fmt.Errorf("ack http %d: %w", status, err)
}
return nil
}

func (s *Service) reportResult(ctx context.Context, cmdID string, success bool, resultJSON string) {
path := fmt.Sprintf("/functions/v1/node-commands/%s", cmdID)
status := string(contractcmds.StatusDone)
if !success {
status = string(contractcmds.StatusFailed)
}
body, _ := json.Marshal(map[string]string{
"status":      status,
"result_json": resultJSON,
})
_, httpStatus, err := s.client.patch(ctx, path, body)
if err != nil {
s.logger.Printf("[controlsync] result report failed id=%s http=%d: %v", cmdID, httpStatus, err)
}
}

func (s *Service) drainPending(ctx context.Context) {
cmds, err := s.executor.PendingCommands(ctx)
if err != nil {
s.logger.Printf("[controlsync] pending query failed: %v", err)
return
}
for _, cmd := range cmds {
s.executor.Execute(ctx, cmd)
go func(id string) {
var status, resultJSON string
_ = s.db.QueryRowContext(ctx,
`SELECT status, result_json FROM command_ledger WHERE id = ?`, id,
).Scan(&status, &resultJSON)
success := status == string(contractcmds.StatusDone)
s.reportResult(ctx, id, success, resultJSON)
}(cmd.ID)
}
}

func (s *Service) seedBootstrapBundle(ctx context.Context) {
if _, err := s.policyRuntime.ActiveBundle(ctx); err == nil {
return
}
now := time.Now().UTC()
bb := bootstrapBundle{
version:   "bootstrap-local-v1",
issuedAt:  now,
expiresAt: now.Add(24 * time.Hour),
}
_ = s.policyRuntime.SwapBundle(ctx, bb.toBundle())
}
