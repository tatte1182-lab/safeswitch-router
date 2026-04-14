package app

import (
	"context"
	"log"
	"os"

	"github.com/getsafeswitch/safeswitch-router/internal/commands"
	"github.com/getsafeswitch/safeswitch-router/internal/controlsync"
	"github.com/getsafeswitch/safeswitch-router/internal/dns"
	"github.com/getsafeswitch/safeswitch-router/internal/events"
	"github.com/getsafeswitch/safeswitch-router/internal/firewall"
	"github.com/getsafeswitch/safeswitch-router/internal/health"
	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	"github.com/getsafeswitch/safeswitch-router/internal/store"
	"github.com/getsafeswitch/safeswitch-router/internal/supervisor"
	"github.com/getsafeswitch/safeswitch-router/internal/relay"
	"github.com/getsafeswitch/safeswitch-router/internal/upnp"
)

func wire(ctx context.Context, cfg Config) (*supervisor.Supervisor, error) {
	logger := log.Default()

	// --- Store ---
	db, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return nil, err
	}
	if err := store.RunMigrations(ctx, db); err != nil {
		return nil, err
	}

	// --- Identity (Start() handles loadOrCreate internally) ---
	idSvc, err := identity.NewService(cfg.DataDir, cfg.NodeName, logger)
	if err != nil {
		return nil, err
	}

	// --- Core services ---
	journal := events.NewJournal(db, logger)
	policyRuntime := policy.NewRuntime(db, logger)
	executor := commands.NewExecutor(db, logger)

	// --- DNS ---
	blocklist := dns.NewBlocklist()
	resolver := dns.NewResolver(blocklist, nil, nil, logger)
	dnsServer := dns.NewServer(db, logger, resolver, blocklist, cfg.DNSListenAddr)

	// --- Firewall enforcer ---
	isRelay := cfg.NodeType == "vps_relay"
	wgIface := os.Getenv("SS_WG_INTERFACE")
	if wgIface == "" {
		wgIface = "wg0"
	}
	fwEnforcer := firewall.NewEnforcer(db, nil, false, logger)
	if !isRelay {
		restoreIptablesOnBoot(db, wgIface)
	}

	// --- Health ---
	healthSvc := health.NewService(db, logger, cfg.HeartbeatEvery)

	// --- Control sync ---
	controlSyncSvc := controlsync.NewService(
		db,
		logger,
		cfg.SyncBaseURL,
		cfg.NodeToken,
		cfg.AnonKey,
		cfg.CommandPollEvery,
		cfg.HeartbeatEvery,
		idSvc,
		journal,
		policyRuntime,
		executor,
		cfg.NodeType,
		cfg.PublicEndpoint,
		cfg.IsLANLocal,
	)

	// --- DDNS updater (home/lan nodes only) ---
	if !isRelay {
		nodeID := os.Getenv("SS_NODE_ID")
		if nodeID == "" {
			nodeID = idSvc.Current().NodeID
		}
		StartDDNSUpdater(ctx, nodeID, cfg.SyncBaseURL, cfg.AnonKey, cfg.PublicEndpoint, 51820)
	}

	// --- UPnP (optional, LAN nodes only) ---
	var upnpSvc *upnp.Service
	if cfg.UPnPEnabled && cfg.IsLANLocal {
		upnpSvc = upnp.New(51820, logger)
	}

	// --- Relay broker (VPS only) ---
	var relaySvc *relay.BrokerService
	if isRelay {
		relaySvc = relay.NewBrokerService(cfg.RelayListenAddr, cfg.RelayNodeToken)
	}

	// --- Supervisor ---
	sup := supervisor.New(logger)
	sup.Register(idSvc)
	sup.Register(dnsServer)
	sup.Register(fwEnforcer)
	sup.Register(healthSvc)
	sup.Register(controlSyncSvc)
	if upnpSvc != nil {
		sup.Register(upnpSvc)
	}

	if relaySvc != nil {
		sup.Register(relaySvc)
	}

	_ = journal
	_ = policyRuntime
	_ = executor

	return sup, nil
}
