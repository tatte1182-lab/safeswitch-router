package store

import (
	"context"
	"database/sql"
	"fmt"
)

// RunMigrations applies all schema migrations idempotently.
// Every statement uses CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
// so this is safe to run on every startup.
func RunMigrations(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		// ── Migration tracking ──────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		// ── Node-scoped key/value config store ──────────────────────────────
		// Single source of truth for: family_id, node_token, enrolled_at,
		// bundle_expires_at, failsafe_grace_seconds, wireguard_public_key.
		// tunnel/manager.go also mirrors the WireGuard private key here for
		// the sqlite-backfill path, but the canonical copy lives on disk.
		`CREATE TABLE IF NOT EXISTS tunnel_config (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);`,

		// ── WireGuard peer registry ──────────────────────────────────────────
		// Authoritative source for wg0.conf generation.
		// allowed_ip is UNIQUE so IP-stable re-key works correctly:
		//   ON CONFLICT(allowed_ip) DO UPDATE SET public_key = excluded.public_key
		`CREATE TABLE IF NOT EXISTS tunnel_peers (
			public_key TEXT PRIMARY KEY,
			allowed_ip TEXT NOT NULL UNIQUE,
			device_mac TEXT NOT NULL DEFAULT '',
			comment    TEXT NOT NULL DEFAULT '',
			added_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		// ── Policy bundle cache ──────────────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS active_policy_bundle (
			id           INTEGER PRIMARY KEY CHECK (id = 1),
			version      TEXT    NOT NULL,
			issued_at    TEXT    NOT NULL,
			expires_at   TEXT    NOT NULL,
			signature    TEXT    NOT NULL,
			payload_json TEXT    NOT NULL,
			updated_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		// ── Event journal (drained by controlsync to Supabase) ──────────────
		`CREATE TABLE IF NOT EXISTS event_journal (
			id           TEXT    PRIMARY KEY,
			event_type   TEXT    NOT NULL,
			severity     TEXT    NOT NULL,
			payload_json TEXT    NOT NULL,
			drained      INTEGER NOT NULL DEFAULT 0,
			created_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_event_journal_drained
			ON event_journal (drained, created_at);`,

		// ── Command ledger (commands received from cloud, tracked to completion)
		`CREATE TABLE IF NOT EXISTS command_ledger (
			id           TEXT    PRIMARY KEY,
			command_type TEXT    NOT NULL,
			status       TEXT    NOT NULL,
			payload_json TEXT    NOT NULL,
			result_json  TEXT    NOT NULL DEFAULT '{}',
			error_text   TEXT    NOT NULL DEFAULT '',
			updated_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
			created_at   TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		// ── Node health snapshots (written by health service, read by heartbeat)
		`CREATE TABLE IF NOT EXISTS health_snapshots (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			cpu_pct    REAL    NOT NULL,
			mem_pct    REAL    NOT NULL,
			disk_pct   REAL    NOT NULL,
			dns_ok     INTEGER NOT NULL DEFAULT 1,
			summary    TEXT    NOT NULL,
			created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		// ── ARP/presence device registry ────────────────────────────────────
		`CREATE TABLE IF NOT EXISTS device_registry (
			mac        TEXT    PRIMARY KEY,
			ip         TEXT    NOT NULL,
			hostname   TEXT    NOT NULL DEFAULT '',
			first_seen TEXT    NOT NULL,
			last_seen  TEXT    NOT NULL,
			enrolled   INTEGER NOT NULL DEFAULT 0
		);`,

		// ── Route profile intent (authoritative desired state per device) ────
		// Values: split_tunnel | full_tunnel | service_only
		// Written by guardian commands; read by firewall enforcer.
		`CREATE TABLE IF NOT EXISTS device_route_profiles (
			mac                   TEXT    PRIMARY KEY,
			route_profile         TEXT    NOT NULL DEFAULT 'split_tunnel',
			route_profile_source  TEXT    NOT NULL DEFAULT 'guardian',
			route_profile_version INTEGER NOT NULL DEFAULT 1,
			client_applied        INTEGER NOT NULL DEFAULT 0,
			client_applied_at     TEXT,
			updated_at            TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,

		// ── DNS blocklist (bulk-loaded from hagezi + Steven Black) ──────────
		`CREATE TABLE IF NOT EXISTS dns_blocklist (
			domain   TEXT PRIMARY KEY,
			category TEXT NOT NULL DEFAULT 'malware',
			source   TEXT NOT NULL DEFAULT 'safeswitch',
			added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	}

	for i, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration statement %d failed: %w\n\nSQL:\n%s", i+1, err, stmt)
		}
	}
	return nil
}
