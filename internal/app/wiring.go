package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/api"
	"github.com/getsafeswitch/safeswitch-router/internal/commands"
	"github.com/getsafeswitch/safeswitch-router/internal/controlsync"
	"github.com/getsafeswitch/safeswitch-router/internal/dns"
	"github.com/getsafeswitch/safeswitch-router/internal/events"
	"github.com/getsafeswitch/safeswitch-router/internal/firewall"
	"github.com/getsafeswitch/safeswitch-router/internal/health"
	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/localclock"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	"github.com/getsafeswitch/safeswitch-router/internal/presence"
	"github.com/getsafeswitch/safeswitch-router/internal/relay"
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
	isRelay := cfg.NodeType == "vps_relay"
	devMode := cfg.Environment != "prod"

	// â”€â”€ DB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	db, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := store.RunMigrations(ctx, db); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	// â”€â”€ Identity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	idSvc, err := identity.NewService(cfg.DataDir, cfg.NodeName, logger)
	if err != nil {
		return nil, fmt.Errorf("init identity: %w", err)
	}

	// â”€â”€ Core services â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	journal := events.NewJournal(db, logger)
	policyRuntime := policy.NewRuntime(db, logger)
	healthSvc := health.NewService(db, logger, cfg.HeartbeatEvery)
	presenceEngine := presence.NewEngine(db, logger, journal, policyRuntime, 30*time.Second)
	routeProfileStore := commands.NewDBRouteProfileStore(db)

	// â”€â”€ DNS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	blocklist := dns.NewBlocklist()
	// NRD disabled 2026-05-01 — Postgres ingest was burning daily disk IO budget.
	// Re-enable via R2 distribution path. Resolver accepts nil and skips NRD check.
	var nrdBlocklist *dns.NRDBlocklist
	resolver := dns.NewResolver(blocklist, nrdBlocklist, policyRuntime, presenceEngine, logger)
	dnsServer := dns.NewServer(db, logger, resolver, blocklist, cfg.DNSListenAddr)

	// â”€â”€ Tunnel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	// WG private key file path comes from config (SS_ROUTER_WG_PRIVATE_KEY_FILE).
	// tunnel.Manager handles fallback to SQLite backfill if the file is absent.
	tunnelMgr := tunnel.NewManager(db, logger, journal, policyRuntime, cfg.WGPrivateKeyFile, devMode)

	// â”€â”€ Firewall â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	enforcer := firewall.NewEnforcer(db, routeProfileStore, devMode, logger)

	// â”€â”€ Hardening: restore iptables on boot â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	// Re-applies the SAFESWITCH chain, DNS lock, QUIC block, and per-device
	// rules after a node reboot. Without this, enforcement is absent until
	// the first bundle sync cycle (up to 60s window with no filtering).
	if !isRelay {
		if err := restoreIptablesOnBoot(db, "wg0"); err != nil {
			logger.Printf("[wiring] iptables restore warning: %v", err)
		}
	}

	// On every policy bundle swap: sync firewall rules + trigger immediate
	// WireGuard peer sync (so new enrollments appear without waiting 60s).
	policyRuntime.SetOnSwap(func(ctx context.Context) {
		if isRelay {
			return
		}
		if err := enforcer.SyncFromBundle(ctx); err != nil {
			logger.Printf("[wiring] firewall sync: %v", err)
		}
		if err := tunnelMgr.TriggerSync(ctx); err != nil {
			logger.Printf("[wiring] tunnel sync: %v", err)
		}
	})

	enforcer.SetBundleProvider(func() []firewall.Child {
		bundle, err := policyRuntime.ActiveBundle(context.Background())
		if err != nil || bundle == nil {
			return nil
		}
		children := make([]firewall.Child, 0, len(bundle.Children))
		for _, c := range bundle.Children {
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
				Paused:             c.LockEnabled || c.Mode == "paused",
				RouteMode:          routeMode,
			})
		}
		return children
	})

	// â”€â”€ Commands â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	executor := commands.NewExecutor(db, logger)
	commands.RegisterHandlers(executor, policyRuntime, dnsServer, tunnelMgr, enforcer, routeProfileStore, logger)

	controlSyncSvc := controlsync.NewService(
		db, logger,
		cfg.SyncBaseURL,
		cfg.NodeToken,
		cfg.AnonKey,
		cfg.SupabaseServiceRoleKey,
		cfg.CommandPollEvery,
		cfg.HeartbeatEvery,
		idSvc,
		journal,
		policyRuntime,
		executor,
		cfg.NodeType,
		cfg.PublicEndpoint,
		cfg.IsLANLocal,
	).WithTunnel(tunnelMgr).WithDNS(dnsServer) // NRD wiring removed 2026-05-01

	resolver.SetBlockSink(controlSyncSvc.NewActivityWriter(ctx))

	// â”€â”€ API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	apiSvc := api.NewService(
		cfg.HTTPListenAddr,
		db,
		logger,
		idSvc,
		policyRuntime,
		presenceEngine,
		controlSyncSvc,
		tunnelMgr,
	)

	// â”€â”€ MITM (optional â€” disabled gracefully if CA not present) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	if !isRelay {
		caDir := getenv("SS_ROUTER_CA_DIR", filepath.Join(cfg.DataDir, "ca"))
		ca, err := mitm.LoadCA(
			filepath.Join(caDir, "ca.crt"),
			filepath.Join(caDir, "ca.key"),
		)
		if err != nil {
			logger.Printf("[wiring] MITM disabled: %v", err)
		} else {
			apiSvc.SetCAProvider(ca)
			go func() {
				proxy := &mitm.Proxy{
					CA:        ca,
					Blocklist: blocklist,
					Port:      8080,
				}
				if err := proxy.ListenAndServe(); err != nil {
					logger.Printf("[mitm] proxy error: %v", err)
				}
			}()
		}
	}

	// â”€â”€ Supervisor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	sup := supervisor.New(logger)

	sup.Register(idSvc)
	sup.Register(journal)
	sup.Register(policyRuntime)
	sup.Register(healthSvc)
	sup.Register(presenceEngine)
	sup.Register(dnsServer)

	if !isRelay {
		if err := sinkhole.EnsureSinkholeAddr(); err != nil {
			logger.Printf("[wiring] sinkhole addr: %v", err)
		}
		if err := sinkhole.StartSinkhole(); err != nil {
			return nil, fmt.Errorf("start sinkhole: %w", err)
		}

		if err := sinkhole.StartSinkholeTLS(); err != nil {
			logger.Printf("[wiring] sinkhole tls: %v", err)
		}

		if cfg.UPnPEnabled && (cfg.NodeType == "home_node" || cfg.NodeType == "lan_node") {
			sup.Register(upnp.New(51820, logger))
		}

		sup.Register(tunnelMgr)
		sup.Register(enforcer)
	}

	sup.Register(controlSyncSvc)

	sup.Register(localclock.New(localclock.Config{
		SupabaseURL:      cfg.SyncBaseURL,
		AnonKey:          cfg.AnonKey,
		TickInterval:     1 * time.Second,
		LookBack:         2 * time.Minute,
		PerChildDebounce: 30 * time.Second,
	}, logger))

	// â”€â”€ Hardening: DDNS endpoint updater â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	// Detects public IP changes every 5 minutes and updates the nodes table
	// in Supabase so enrolled devices can pick up the new endpoint.
	// Only runs on home_node â€” the VPS relay has a static IP.
	if cfg.NodeType == "home_node" || cfg.NodeType == "lan_node" {
		nodeID := os.Getenv("SS_NODE_ID")
		if nodeID == "" {
			// Fall back to reading from identity service if env var not set
			nodeID = idSvc.Current().NodeID
		}
		if nodeID != "" {
			StartDDNSUpdater(ctx, nodeID, cfg.SyncBaseURL, cfg.AnonKey, cfg.PublicEndpoint, 51820)
		} else {
			logger.Printf("[wiring] DDNS updater skipped â€” node ID not available")
		}
	}

	// â”€â”€ Relay â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	switch cfg.NodeType {

	case "vps_relay":
		token := firstNonEmpty(cfg.RelayNodeToken, cfg.NodeToken)
		broker := relay.NewBroker()
		sup.Register(relay.NewBrokerServiceWithBroker(broker, cfg.RelayListenAddr, token))
		udpBridge := relay.NewUDPBridge(":51820", cfg.RelayFamilyID, broker)
		sup.Register(udpBridge)

	case "home_node", "lan_node":
		// RelayBrokerURL is optional â€” if unset, this node connects directly
		// (e.g. it has a public IP) and no relay client is started.
		if cfg.RelayBrokerURL != "" && cfg.RelayFamilyID != "" {
			token := firstNonEmpty(cfg.RelayNodeToken, cfg.NodeToken)
			sup.Register(relay.NewClientService(
				cfg.RelayBrokerURL,
				cfg.NodeName,
				cfg.RelayFamilyID,
				token,
				cfg.RelayWGAddr,
			))
		}
	}

	sup.Register(apiSvc)

	return sup, nil
}

// â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
