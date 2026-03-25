package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/getsafeswitch/safeswitch-router/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, err := app.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	a, err := app.New(ctx, cfg)
	if err != nil {
		log.Fatalf("build app: %v", err)
	}

	if err := a.Start(ctx); err != nil {
		log.Fatalf("start app: %v", err)
	}

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := a.Stop(shutdownCtx); err != nil {
		log.Fatalf("stop app: %v", err)
	}
}
