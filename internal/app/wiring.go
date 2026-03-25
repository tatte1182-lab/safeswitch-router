package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/api"
	"github.com/getsafeswitch/safeswitch-router/internal/controlsync"
	"github.com/getsafeswitch/safeswitch-router/internal/events"
	"github.com/getsafeswitch/safeswitch-router/internal/health"
	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	"github.com/getsafeswitch/safeswitch-router/internal/presence"
	"github.com/getsafeswitch/safeswitch-router/internal/store"
	"github.com/getsafeswitch/safeswitch-router/internal/supervisor"
	"github.com/getsafeswitch/safeswitch-router/internal/telemetry"
)

func wire(ctx context.Context, cfg Config) (*supervisor.Supervisor, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	logger := telemetry.NewLogger(cfg.LogLevel)
	db, err := store.Open(ctx, cfg.DBPath)
	if err != nil { return nil, fmt.Errorf("open db: %w", err) }
	if err := store.RunMigrations(ctx, db); err != nil { return nil, fmt.Errorf("run migrations: %w", err) }
	idSvc, err := identity.NewService(cfg.DataDir, cfg.NodeName, logger)
	if err != nil { return nil, fmt.Errorf("init identity: %w", err) }
	journal        := events.NewJournal(db, logger)
	policyRuntime  := policy.NewRuntime(db, logger)
	healthSvc      := health.NewService(db, logger, cfg.HeartbeatEvery)
	presenceEngine := presence.NewEngine(db, logger, journal, policyRuntime, 30*time.Second)
	controlSyncSvc := controlsync.NewService(
		db, logger, cfg.SyncBaseURL, cfg.NodeToken,
		cfg.CommandPollEvery, cfg.HeartbeatEvery,
		idSvc, journal, policyRuntime,
	)
	apiSvc := api.NewService(cfg.HTTPListenAddr, db, logger, idSvc, policyRuntime, presenceEngine)
	sup := supervisor.New(logger)
	sup.Register(idSvc)
	sup.Register(journal)
	sup.Register(policyRuntime)
	sup.Register(healthSvc)
	sup.Register(presenceEngine)
	sup.Register(controlSyncSvc)
	sup.Register(apiSvc)
	return sup, nil
}

