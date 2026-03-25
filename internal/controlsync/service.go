package controlsync

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/commands"
	"github.com/getsafeswitch/safeswitch-router/internal/events"
	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	contractcmds "github.com/getsafeswitch/safeswitch-router/pkg/contract/commands"
	contractevents "github.com/getsafeswitch/safeswitch-router/pkg/contract/events"
	policybundle "github.com/getsafeswitch/safeswitch-router/pkg/contract/policybundle"
)

type Logger interface {
	Printf(format string, v ...any)
}

type Service struct {
	db               *sql.DB
	logger           Logger
	baseURL          string
	nodeToken        string
	commandPollEvery time.Duration
	heartbeatEvery   time.Duration
	identity         *identity.Service
	journal          *events.Journal
	policyRuntime    *policy.Runtime
	executor         *commands.Executor

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewService(
	db *sql.DB,
	logger Logger,
	baseURL string,
	nodeToken string,
	commandPollEvery time.Duration,
	heartbeatEvery time.Duration,
	identity *identity.Service,
	journal *events.Journal,
	policyRuntime *policy.Runtime,
	executor *commands.Executor,
) *Service {
	return &Service{
		db:               db,
		logger:           logger,
		baseURL:          baseURL,
		nodeToken:        nodeToken,
		commandPollEvery: commandPollEvery,
		heartbeatEvery:   heartbeatEvery,
		identity:         identity,
		journal:          journal,
		policyRuntime:    policyRuntime,
		executor:         executor,
	}
}

func (s *Service) Name() string { return "control-sync" }

func (s *Service) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	s.wg.Add(2)
	go s.runHeartbeat(runCtx)
	go s.runCommandPoll(runCtx)

	s.logger.Printf("[controlsync] started base_url=%s", s.baseURL)
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
	return nil
}

func (s *Service) Health(ctx context.Context) error { return nil }

func (s *Service) runHeartbeat(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.heartbeatEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			id := s.identity.Current()
			s.logger.Printf("[controlsync] heartbeat node_id=%s", id.NodeID)
			_ = s.journal.Append(ctx, contractevents.Event{
				Type:     "node.heartbeat.sent",
				Severity: "info",
				Payload:  map[string]any{"node_id": id.NodeID},
			})
		}
	}
}

func (s *Service) runCommandPoll(ctx context.Context) {
	defer s.wg.Done()
	ticker := time.NewTicker(s.commandPollEvery)
	defer ticker.Stop()

	// Seed a bootstrap bundle on first poll so the runtime is never empty
	// in dev/local mode. Real Supabase bundles will overwrite this via
	// update_policy commands once the node is enrolled.
	bootstrapped := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logger.Printf("[controlsync] polling commands")

			if !bootstrapped {
				bootstrapped = true
				_ = s.policyRuntime.SwapBundle(ctx, &policybundle.Bundle{
					Version:   "bootstrap-local-v1",
					IssuedAt:  time.Now().UTC(),
					ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
					Signature: "dev-signature",
					Children:  []policybundle.ChildEffectiveState{},
				})
			}

			// Drain pending commands from the local ledger.
			// In R6 this loop will first fetch new commands from Supabase
			// and enqueue them before draining.
			s.drainPending(ctx)
		}
	}
}

// drainPending reads all pending commands from command_ledger and executes
// them in order. Each Execute call manages its own status transitions.
func (s *Service) drainPending(ctx context.Context) {
	cmds, err := s.executor.PendingCommands(ctx)
	if err != nil {
		s.logger.Printf("[controlsync] pending query failed: %v", err)
		return
	}
	for _, cmd := range cmds {
		s.executor.Execute(ctx, cmd)
	}
}

// EnqueueCommand is a convenience method so the API layer can inject
// commands directly (used in tests and local dev via the HTTP API).
func (s *Service) EnqueueCommand(ctx context.Context, cmd contractcmds.Command) error {
	return s.executor.Enqueue(ctx, cmd)
}
