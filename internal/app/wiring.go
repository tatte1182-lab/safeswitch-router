package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/api"
	"github.com/getsafeswitch/safeswitch-router/internal/commands"
	"github.com/getsafeswitch/safeswitch-router/internal/controlsync"
	"github.com/getsafeswitch/safeswitch-router/internal/dns"
	"github.com/getsafeswitch/safeswitch-router/internal/events"
	"github.com/getsafeswitch/safeswitch-router/internal/firewall"
	"github.com/getsafeswitch/safeswitch-router/internal/health"
	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	"github.com/getsafeswitch/safeswitch-router/internal/presence"
	"github.com/getsafeswitch/safeswitch-router/internal/store"
	"github.com/getsafeswitch/safeswitch-router/internal/supervisor"
	"github.com/getsafeswitch/safeswitch-router/internal/telemetry"
	"github.com/getsafeswitch/safeswitch-router/internal/tunnel"
)

func wire(ctx context.Context, cfg Config) (*supervisor.Supervisor, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	logger := telemetry.NewLogger(cfg.LogLevel)

	db, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := store.RunMigrations(ctx, db); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	idSvc, err := identity.NewService(cfg.DataDir, cfg.NodeName, logger)
	if err != nil {
		return nil, fmt.Errorf("init identity: %w", err)
	}

	devMode := cfg.Environment != "prod"

	journal        := events.NewJournal(db, logger)
	policyRuntime  := policy.NewRuntime(db, logger)
	healthSvc      := health.NewService(db, logger, cfg.HeartbeatEvery)
	presenceEngine := presence.NewEngine(db, logger, journal, policyRuntime, 30*time.Second)

	routeProfileStore := commands.NewDBRouteProfileStore(db)

	blocklist := dns.NewBlocklist()
	resolver  := dns.NewResolver(blocklist, policyRuntime, presenceEngine, logger)
	dnsServer := dns.NewServer(db, logger, resolver, blocklist, cfg.DNSListenAddr)

	tunnelMgr := tunnel.NewManager(db, logger, journal, policyRuntime, devMode)

	enforcer := firewall.NewEnforcer(db, routeProfileStore, devMode, logger)
	policyRuntime.SetOnSwap(func(ctx context.Context) {
		if err := enforcer.SyncFromBundle(ctx); err != nil {
			logger.Printf("[wiring] firewall sync after bundle swap: %v", err)
		}
		if err := tunnelMgr.TriggerSync(ctx); err != nil {
			logger.Printf("[wiring] tunnel sync after bundle swap: %v", err)
		}
	})

	enforcer.SetBundleProvider(func() []firewall.Child {
		bundle, err := policyRuntime.ActiveBundle(context.Background())
		if err != nil || bundle == nil {
			return nil
		}
		children := make([]firewall.Child, 0, len(bundle.Children))
		for _, c := range bundle.Children {
			paused := c.LockEnabled || c.Mode == "paused"
			routeMode := "split_tunnel"
			if c.Mode == "full_tunnel" {
				routeMode = "full_tunnel"
			}
			children = append(children, firewall.Child{
				ChildID:            c.ChildID,
				DeviceMAC:          c.DeviceMAC,
				WireguardPublicKey: c.WireGuardPublicKey,
				WireguardIP:        c.WireguardIP,
				DisplayName:        c.DNSProfileID,
				Paused:             paused,
				RouteMode:          routeMode,
			})
		}
		return children
	})

	executor := commands.NewExecutor(db, logger)
	commands.RegisterHandlers(executor, policyRuntime, dnsServer, tunnelMgr, enforcer, routeProfileStore, logger)

	controlSyncSvc := controlsync.NewService(
		db, logger, cfg.SyncBaseURL, cfg.NodeToken,
		cfg.CommandPollEvery, cfg.HeartbeatEvery,
		idSvc, journal, policyRuntime, executor,
	)

	apiSvc := api.NewService(
		cfg.HTTPListenAddr, db, logger,
		idSvc, policyRuntime, presenceEngine, controlSyncSvc, tunnelMgr,
	)

	sup := supervisor.New(logger)
	sup.Register(idSvc)
	sup.Register(journal)
	sup.Register(policyRuntime)
	sup.Register(healthSvc)
	sup.Register(presenceEngine)
	sup.Register(dnsServer)
	sup.Register(tunnelMgr)
	sup.Register(enforcer)
	sup.Register(controlSyncSvc)
	sup.Register(apiSvc)

	return sup, nil
}
