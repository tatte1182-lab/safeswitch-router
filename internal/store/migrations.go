package store

import (
	"context"
	"database/sql"
	"fmt"
)

func RunMigrations(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE IF NOT EXISTS active_policy_bundle (id INTEGER PRIMARY KEY CHECK (id = 1), version TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, signature TEXT NOT NULL, payload_json TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE IF NOT EXISTS event_journal (id TEXT PRIMARY KEY, event_type TEXT NOT NULL, severity TEXT NOT NULL, payload_json TEXT NOT NULL, drained INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE IF NOT EXISTS command_ledger (id TEXT PRIMARY KEY, command_type TEXT NOT NULL, status TEXT NOT NULL, payload_json TEXT NOT NULL, result_json TEXT NOT NULL DEFAULT '{}', error_text TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE IF NOT EXISTS health_snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, cpu_pct REAL NOT NULL, mem_pct REAL NOT NULL, disk_pct REAL NOT NULL, summary TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE IF NOT EXISTS device_registry (
			mac        TEXT PRIMARY KEY,
			ip         TEXT NOT NULL,
			hostname   TEXT NOT NULL DEFAULT '',
			first_seen TEXT NOT NULL,
			last_seen  TEXT NOT NULL,
			enrolled   INTEGER NOT NULL DEFAULT 0
		);`,

		// Route profile intent store — one row per device MAC.
		// This is the authoritative desired state set by guardian commands.
		// Values: split_tunnel | full_tunnel | service_only
		// The firewall enforcer reads this to build per-device egress rules.
		// The command dispatcher reads this to push cooperative updates to clients.
		`CREATE TABLE IF NOT EXISTS device_route_profiles (
			mac                     TEXT PRIMARY KEY,
			route_profile           TEXT NOT NULL DEFAULT 'split_tunnel',
			route_profile_source    TEXT NOT NULL DEFAULT 'guardian',
			route_profile_version   INTEGER NOT NULL DEFAULT 1,
			client_applied          INTEGER NOT NULL DEFAULT 0,
			client_applied_at       TEXT,
			updated_at              TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
	}
	for i, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}
	return nil
}
