// Package localclock keeps child_effective_state transitions on the clock.
//
// Problem:
//   pg_cron recomputes effective state every minute. The cron tick can lag up to
//   59s behind a schedule boundary. If a child's "homework" window ends at 18:00,
//   the transition to "screen_time" fires on the next cron tick — somewhere
//   between 18:00:00 and 18:01:00.
//
// Solution:
//   This service runs on the home node, ticks every second, and checks which
//   children have a pending transition (next_state_change_at <= now()). For
//   each, it calls compute_child_effective_state(child_id) via RPC. The trigger
//   chain downstream fires a bundlesync command that the existing command-poll
//   path picks up and applies.
//
//   The service does NOT recompute state locally — that logic stays in one place
//   (the DB function). It only forces a recompute at the exact moment of the
//   transition, instead of waiting for the next cron tick.
//
//   pg_cron stays active as a safety net (reconciliation every 15 minutes).
//
// Cost per tick:
//   One SELECT (~3 rows checked per family), and an RPC call only when a row
//   needs recomputing (usually 0, occasionally 1). Negligible.

package localclock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Service implements supervisor.Service.
type Service struct {
	cfg    Config
	httpc  *http.Client
	logger Logger

	mu      sync.Mutex
	lastHit map[string]time.Time // child_id → last time we forced a recompute

	stop chan struct{}
	done chan struct{}
}

type Config struct {
	// SupabaseURL = https://ylrdblwosarsunhwwsog.supabase.co
	SupabaseURL string
	// AnonKey is the Supabase anon JWT (service-role not needed for these calls
	// because compute_child_effective_state is SECURITY DEFINER).
	AnonKey string
	// TickInterval controls how often we scan for due transitions.
	// Default 1s. Smaller = faster transitions, more CPU.
	TickInterval time.Duration
	// LookBack is how far back we consider "overdue" transitions. Protects
	// against the scheduler missing a boundary during a brief downtime.
	// Default 2 minutes.
	LookBack time.Duration
	// PerChildDebounce keeps us from hammering the RPC if a row's
	// next_state_change_at hasn't advanced after we forced a recompute.
	// Default 30 seconds.
	PerChildDebounce time.Duration
}

type Logger interface {
	Printf(format string, v ...any)
}

func New(cfg Config, logger Logger) *Service {
	if cfg.TickInterval <= 0 {
		cfg.TickInterval = 1 * time.Second
	}
	if cfg.LookBack <= 0 {
		cfg.LookBack = 2 * time.Minute
	}
	if cfg.PerChildDebounce <= 0 {
		cfg.PerChildDebounce = 30 * time.Second
	}
	return &Service{
		cfg:     cfg,
		httpc:   &http.Client{Timeout: 8 * time.Second},
		logger:  logger,
		lastHit: make(map[string]time.Time),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// ─── supervisor.Service ──────────────────────────────────────────────────────

func (s *Service) Name() string { return "localclock" }

func (s *Service) Start(ctx context.Context) error {
	if s.cfg.SupabaseURL == "" || s.cfg.AnonKey == "" {
		return fmt.Errorf("localclock: SupabaseURL and AnonKey required")
	}
	s.cfg.SupabaseURL = strings.TrimRight(s.cfg.SupabaseURL, "/")

	go s.run(ctx)
	s.logger.Printf("[localclock] started (tick=%s, lookback=%s)",
		s.cfg.TickInterval, s.cfg.LookBack)
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	select {
	case <-s.stop:
		// already stopped
	default:
		close(s.stop)
	}
	select {
	case <-s.done:
	case <-ctx.Done():
	}
	return nil
}

func (s *Service) Health(ctx context.Context) error {
	// No special health check. If the binary is up, the ticker is up.
	return nil
}

// ─── core loop ───────────────────────────────────────────────────────────────

func (s *Service) run(ctx context.Context) {
	defer close(s.done)

	t := time.NewTicker(s.cfg.TickInterval)
	defer t.Stop()

	// First pass immediately, don't wait a full tick on startup.
	s.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stop:
			return
		case <-t.C:
			s.tick(ctx)
		}
	}
}

func (s *Service) tick(ctx context.Context) {
	due, err := s.fetchDue(ctx)
	if err != nil {
		// Don't log every tick if Supabase is briefly unavailable; fallback
		// cron will still run every 15 min.
		return
	}
	if len(due) == 0 {
		return
	}

	now := time.Now()
	for _, d := range due {
		s.mu.Lock()
		last := s.lastHit[d.ChildID]
		s.mu.Unlock()
		if now.Sub(last) < s.cfg.PerChildDebounce {
			continue
		}

		if err := s.forceRecompute(ctx, d.ChildID); err != nil {
			s.logger.Printf("[localclock] recompute child=%s: %v", d.ChildID, err)
			continue
		}

		s.mu.Lock()
		s.lastHit[d.ChildID] = now
		s.mu.Unlock()

		s.logger.Printf("[localclock] forced recompute child=%s next_change=%s (was %s overdue)",
			d.ChildID,
			d.NextChange.Format(time.RFC3339),
			now.Sub(d.NextChange).Round(time.Millisecond),
		)
	}
}

// ─── Supabase calls ──────────────────────────────────────────────────────────

type dueRow struct {
	ChildID    string    `json:"child_id"`
	NextChange time.Time `json:"next_state_change_at"`
}

// fetchDue returns children whose next_state_change_at is due (between
// now - LookBack and now). Narrow, cheap query.
func (s *Service) fetchDue(ctx context.Context) ([]dueRow, error) {
	// PostgREST query:
	//   select=child_id,next_state_change_at
	//   next_state_change_at=gte.{now-lookback}
	//   next_state_change_at=lte.{now}
	//   order=next_state_change_at.asc
	//   limit=50
	now := time.Now().UTC()
	lookback := now.Add(-s.cfg.LookBack)

	url := fmt.Sprintf(
		"%s/rest/v1/child_effective_state"+
			"?select=child_id,next_state_change_at"+
			"&next_state_change_at=gte.%s"+
			"&next_state_change_at=lte.%s"+
			"&order=next_state_change_at.asc"+
			"&limit=50",
		s.cfg.SupabaseURL,
		lookback.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("apikey", s.cfg.AnonKey)
	req.Header.Set("Authorization", "Bearer "+s.cfg.AnonKey)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("fetch due: status=%d body=%s", resp.StatusCode, string(body))
	}

	var out []dueRow
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// forceRecompute calls the RPC to re-evaluate the child's effective state.
// The DB function's state_hash gate means a no-op recompute costs nothing
// downstream (no command_ledger spam).
func (s *Service) forceRecompute(ctx context.Context, childID string) error {
	url := fmt.Sprintf("%s/rest/v1/rpc/compute_child_effective_state", s.cfg.SupabaseURL)
	payload := map[string]string{"p_child_id": childID}
	buf, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("apikey", s.cfg.AnonKey)
	req.Header.Set("Authorization", "Bearer "+s.cfg.AnonKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")

	resp, err := s.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("rpc status=%d body=%s", resp.StatusCode, string(body))
	}
	return nil
}
