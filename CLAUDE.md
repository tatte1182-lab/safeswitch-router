# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build
go build -o ss-router ./cmd/ss-router

# Run (configured via environment variables)
./ss-router

# Run tests
go test ./...

# Run a single test
go test ./internal/store -run TestMigrations
```

CGo is required (`mattn/go-sqlite3`). On Windows, a GCC toolchain (e.g. mingw-w64) must be available.

## Architecture

SafeSwitch Router is a parental-control router daemon that runs on home routers (OpenWrt) or a VPS. It enforces per-child device policies (DNS filtering, WireGuard tunnel routing, internet pausing) and syncs with a Supabase cloud backend.

### Supervisor pattern

`internal/supervisor` manages 10 services registered in `internal/app/app.go`. Each service implements `Start(ctx) error` and shuts down when the context is cancelled. Services are started in registration order and stopped in reverse. The supervisor coordinates graceful shutdown on SIGINT/SIGTERM.

### Service dependency flow

```
Identity → Store → PolicyRuntime → { HealthService, PresenceEngine, DNSServer, TunnelManager, FirewallEnforcer, ControlSyncService, LocalAPI }
```

- **PolicyRuntime** (`internal/policy`) loads policy bundles and fires swap callbacks that trigger firewall and tunnel re-syncs.
- **ControlSyncService** (`internal/controlsync`) runs three loops: heartbeat (posts health/presence, fetches bundles), command poll (5s), and enforcement sync (pushes firewall/tunnel state to cloud).
- **FirewallEnforcer** (`internal/firewall`) generates and applies iptables rule sets. In dev mode (`SS_ROUTER_ENV=dev`) it logs rules instead of executing them.
- **TunnelManager** (`internal/tunnel`) orchestrates WireGuard interfaces via `wg` and `ip` commands.
- **DNSServer** (`internal/dns`) serves DNS on UDP+TCP with per-device blocklist filtering; blocked domains resolve to 0.0.0.0.
- **PresenceEngine** (`internal/presence`) discovers LAN devices every 30s by reading ARP tables and DHCP leases.

### Cloud sync (Supabase)

`internal/controlsync/client.go` calls Supabase Edge Functions via REST RPCs. Auth uses two headers: `apikey` (anon key) and `Authorization: Bearer <node_token>`. Bundle versions are compared before downloading to avoid redundant policy swaps.

### Data layer

SQLite with WAL mode (`internal/store`). Schema migrations run on startup. Key tables: `active_policy_bundle`, `device_registry`, `dns_blocklist`, `command_ledger`, `event_journal`, `health_snapshots`.

### Contracts

`pkg/contract` defines shared data structures (policy bundles, commands, events, health snapshots) used across packages. Policy bundles contain children profiles with DNS and tunnel routing rules.

## Configuration

All config is via environment variables prefixed `SS_ROUTER_`. See `internal/config/config.go` for the full list and defaults. Key ones: `SS_ROUTER_ENV` (dev/prod), `SS_ROUTER_DATA_DIR`, `SS_ROUTER_SYNC_BASE_URL`, `SS_ROUTER_NODE_TOKEN`, `SS_ROUTER_ANON_KEY`.

## Platform considerations

The firewall (`iptables`), tunnel (`wg`, `ip`), and presence (ARP/DHCP) subsystems use Linux-specific tools. Dev mode gates destructive system calls so the codebase can be developed and tested on non-Linux platforms.
