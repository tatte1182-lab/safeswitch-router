package controlsync

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	contractcmds "github.com/getsafeswitch/safeswitch-router/pkg/contract/commands"
)

const (
	commandFetchTimeout = 8 * time.Second
	commandAckTimeout   = 5 * time.Second
	commandExecLimit    = 8
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

	reqCtx, cancel := context.WithTimeout(ctx, commandFetchTimeout)
	defer cancel()

	path := fmt.Sprintf("/functions/v1/node-commands?node_id=%s&status=pending", id.NodeID)

	body, status, err := s.client.get(reqCtx, path)
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

	s.logger.Printf("[controlsync] fetched %d command(s)", len(cmds))

	for _, c := range cmds {

		// 🔒 dedup: skip if already in ledger
		exists, err := s.commandExists(ctx, c.ID)
		if err == nil && exists {
			continue
		}

		cmd := contractcmds.Command{
			ID:      c.ID,
			Type:    c.Type,
			Payload: c.Payload,
		}

		if err := s.executor.Enqueue(ctx, cmd); err != nil {
			s.logger.Printf("[controlsync] enqueue failed id=%s: %v", c.ID, err)
			continue
		}

		// ack AFTER enqueue success
		if err := s.ackCommand(ctx, c.ID); err != nil {
			s.logger.Printf("[controlsync] ack failed id=%s: %v", c.ID, err)
		}
	}
}

func (s *Service) commandExists(ctx context.Context, id string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM command_ledger WHERE id = ?)`, id,
	).Scan(&exists)
	return exists, err
}

func (s *Service) ackCommand(ctx context.Context, id string) error {

	reqCtx, cancel := context.WithTimeout(ctx, commandAckTimeout)
	defer cancel()

	path := fmt.Sprintf("/functions/v1/node-commands/%s", id)

	body, _ := json.Marshal(map[string]string{
		"status": string(contractcmds.StatusAcked),
	})

	_, status, err := s.client.patch(reqCtx, path, body)
	if err != nil {
		return fmt.Errorf("ack http %d: %w", status, err)
	}

	return nil
}

// reportResult PATCHes the Supabase command_ledger via the node-commands Edge
// Function with the final status, result payload, and — critically — the error
// text so failures are visible remotely without needing SSH access to the node.
func (s *Service) reportResult(ctx context.Context, cmdID string, success bool, resultJSON string, errorText string) {

	reqCtx, cancel := context.WithTimeout(ctx, commandAckTimeout)
	defer cancel()

	path := fmt.Sprintf("/functions/v1/node-commands/%s", cmdID)

	status := string(contractcmds.StatusDone)
	if !success {
		status = string(contractcmds.StatusFailed)
	}

	body, _ := json.Marshal(map[string]string{
		"status":      status,
		"result_json": resultJSON,
		"error_text":  errorText,
	})

	_, httpStatus, err := s.client.patch(reqCtx, path, body)
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

	if len(cmds) == 0 {
		return
	}

	sem := make(chan struct{}, commandExecLimit)
	var wg sync.WaitGroup

	for _, cmd := range cmds {

		sem <- struct{}{}
		wg.Add(1)

		go func(cmd contractcmds.Command) {
			defer wg.Done()
			defer func() { <-sem }()

			s.executor.Execute(ctx, cmd)

			// Read back status, result, AND error_text from local SQLite so we
			// can forward all three to Supabase in a single PATCH.
			var status, resultJSON, errorText string
			_ = s.db.QueryRowContext(ctx,
				`SELECT status, result_json, error_text FROM command_ledger WHERE id = ?`,
				cmd.ID,
			).Scan(&status, &resultJSON, &errorText)

			success := status == string(contractcmds.StatusDone)

			s.reportResult(ctx, cmd.ID, success, resultJSON, errorText)

		}(cmd)
	}

	wg.Wait()
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
