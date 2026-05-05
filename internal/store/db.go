package store

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Open opens the router's SQLite database with WAL mode, a 64MB WAL size cap,
// and a periodic checkpoint goroutine that prevents long-running readers from
// pinning the WAL indefinitely.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("sql open: %w", err)
	}

	pragmas := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA foreign_keys=ON;`,
		`PRAGMA wal_autocheckpoint=1000;`,
		`PRAGMA journal_size_limit=67108864;`, // 64MB cap on WAL
		`PRAGMA synchronous=NORMAL;`,
	}
	for _, p := range pragmas {
		if _, err := db.ExecContext(ctx, p); err != nil {
			return nil, fmt.Errorf("set pragma %q: %w", p, err)
		}
	}

	// Periodic WAL truncation. Without this, long-running readers can pin the
	// WAL and prevent auto-checkpoint from truncating it, causing the WAL file
	// to grow unbounded (we previously saw it reach 183MB in production).
	go runWALMaintenance(ctx, db)

	return db, nil
}

func runWALMaintenance(ctx context.Context, db *sql.DB) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var busy, walFrames, checkpointed int
			err := db.QueryRowContext(ctx,
				`PRAGMA wal_checkpoint(TRUNCATE);`,
			).Scan(&busy, &walFrames, &checkpointed)
			if err != nil {
				log.Printf("[store] wal_checkpoint failed: %v", err)
				continue
			}
			if busy != 0 || walFrames > 0 {
				log.Printf("[store] wal_checkpoint: busy=%d frames=%d checkpointed=%d",
					busy, walFrames, checkpointed)
			}
		}
	}
}
