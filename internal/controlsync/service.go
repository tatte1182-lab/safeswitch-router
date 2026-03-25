package controlsync

import (
	"context"
	"database/sql"
	"sync"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/events"
	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
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

	cancel context.CancelFunc
	wg     sync.WaitGroup // FIX: track goroutines so Stop() waits for clean drain
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
	}
}

func (s *Service) Name() string { return "control-sync" }

func (s *Service) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	// FIX: Add(2) before launching goroutines, defer Done() inside each
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
	// FIX: wait for both goroutines to exit before returning
	s.wg.Wait()
	return nil
}

func (s *Service) Health(ctx context.Context) error { return nil }

func (s *Service) runHeartbeat(ctx context.Context) {
	defer s.wg.Done() // FIX: signal Done when goroutine exits
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
				Payload: map[string]any{
					"node_id": id.NodeID,
				},
			})
		}
	}
}

func (s *Service) runCommandPoll(ctx context.Context) {
	defer s.wg.Done() // FIX: signal Done when goroutine exits
	ticker := time.NewTicker(s.commandPollEvery)
	defer ticker.Stop()

	firstBundle := true

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.logger.Printf("[controlsync] polling commands")

			if firstBundle {
				firstBundle = false
				_ = s.policyRuntime.SwapBundle(ctx, &policybundle.Bundle{
					Version:   "bootstrap-local-v1",
					IssuedAt:  time.Now().UTC(),
					ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
					Signature: "dev-signature",
					Children:  []policybundle.ChildEffectiveState{},
				})
			}
		}
	}
}
