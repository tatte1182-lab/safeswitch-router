package app

import (
	"context"
	"fmt"
	"github.com/getsafeswitch/safeswitch-router/internal/supervisor"
)

type App struct {
	cfg        Config
	supervisor *supervisor.Supervisor
}

func New(ctx context.Context, cfg Config) (*App, error) {
	sup, err := wire(ctx, cfg)
	if err != nil { return nil, fmt.Errorf("wire app: %w", err) }
	return &App{cfg: cfg, supervisor: sup}, nil
}

func (a *App) Start(ctx context.Context) error { return a.supervisor.Start(ctx) }
func (a *App) Stop(ctx context.Context) error  { return a.supervisor.Stop(ctx) }
