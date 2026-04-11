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
	"github.com/getsafeswitch/safeswitch-router/internal/sinkhole"
	"github.com/getsafeswitch/safeswitch-router/internal/store"
	"github.com/getsafeswitch/safeswitch-router/internal/supervisor"
	"github.com/getsafeswitch/safeswitch-router/internal/telemetry"
	"github.com/getsafeswitch/safeswitch-router/internal/tunnel"
	"github.com/getsafeswitch/safeswitch-router/internal/upnp"
	"github.com/getsafeswitch/safeswitch-router/mitm"
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
				DisplayName:        c.ChildID,
				Paused:             paused,
				RouteMode:          routeMode,
			})
		}
		return children
	})

	executor := commands.NewExecutor(db, logger)
	commands.RegisterHandlers(executor, policyRuntime, dnsServer, tunnelMgr, enforcer, routeProfileStore, logger)

	controlSyncSvc := controlsync.NewService(
		db, logger, cfg.SyncBaseURL, cfg.NodeToken, cfg.AnonKey,
		cfg.CommandPollEvery, cfg.HeartbeatEvery,
		idSvc, journal, policyRuntime, executor,
		cfg.NodeType, cfg.PublicEndpoint, cfg.IsLANLocal,
	)

	// Wire DNS block events → activity_log
	resolver.SetBlockSink(controlSyncSvc.NewActivityWriter(ctx))

	apiSvc := api.NewService(
		cfg.HTTPListenAddr, db, logger,
		idSvc, policyRuntime, presenceEngine, controlSyncSvc, tunnelMgr,
	)

	// Load MITM CA and wire into API + proxy.
	// Non-fatal: if the CA doesn't exist yet (fresh install, new device),
	// the node runs without SSL inspection. CA can be provisioned later.
	caDir := os.Getenv("SS_ROUTER_CA_DIR")
	if caDir == "" {
		caDir = "/root/ss-data/ca"
	}
	ca, err := mitm.LoadCA(
		caDir+"/ca.crt",
		caDir+"/ca.key",
	)
	if err != nil {
		logger.Printf("[wiring] MITM CA not loaded: %v (SSL inspection disabled)", err)
	} else {
		apiSvc.SetCAProvider(ca)
		mitmProxy := &mitm.Proxy{
			CA:        ca,
			Blocklist: blocklist,
			Port:      8080,
		}
		go func() {
			if err := mitmProxy.ListenAndServe(); err != nil {
				logger.Printf("[mitm] proxy error: %v", err)
			}
		}()
	}

	sup := supervisor.New(logger)
	sup.Register(idSvc)
	sup.Register(journal)
	sup.Register(policyRuntime)
	sup.Register(healthSvc)
	sup.Register(presenceEngine)
	sup.Register(dnsServer)

	// Bind 10.10.0.254 on wg0 so the sinkhole can listen.
	// If the address is already bound (e.g. after a restart) the error is ignored.
	if err := sinkhole.EnsureSinkholeAddr(); err != nil {
		logger.Printf("[wiring] sinkhole addr: %v (continuing)", err)
	}
	if err := sinkhole.StartSinkhole(); err != nil {
		return nil, fmt.Errorf("start sinkhole: %w", err)
	}

	// UPnP — auto port mapping for WireGuard (home_node and lan_node only).
	// Non-fatal: if the router doesn't support UPnP the service exits cleanly
	// and the VPS relay handles WAN connectivity.
	if cfg.UPnPEnabled && (cfg.NodeType == "home_node" || cfg.NodeType == "lan_node") {
		upnpSvc := upnp.New(51820, logger)
		sup.Register(upnpSvc)
	}

	sup.Register(tunnelMgr)
	sup.Register(enforcer)
	sup.Register(controlSyncSvc)
	sup.Register(apiSvc)

	return sup, nil
}
