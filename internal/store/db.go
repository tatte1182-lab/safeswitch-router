package store

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
)

func Open(ctx context.Context, path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil { return nil, fmt.Errorf("sql open: %w", err) }
	if _, err := db.ExecContext(ctx, `PRAGMA journal_mode=WAL;`); err != nil {
		return nil, fmt.Errorf("set WAL: %w", err)
	}
	if _, err := db.ExecContext(ctx, `PRAGMA foreign_keys=ON;`); err != nil {
		return nil, fmt.Errorf("set foreign keys: %w", err)
	}
	return db, nil
}
