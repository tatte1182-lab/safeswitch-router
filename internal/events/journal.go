package events

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"github.com/google/uuid"
	contract "github.com/getsafeswitch/safeswitch-router/pkg/contract/events"
)

type Logger interface { Printf(format string, v ...any) }

type Journal struct {
	db     *sql.DB
	logger Logger
	mu     sync.RWMutex
}

func NewJournal(db *sql.DB, logger Logger) *Journal { return &Journal{db: db, logger: logger} }
func (j *Journal) Name() string                     { return "events-journal" }
func (j *Journal) Start(ctx context.Context) error {
	j.logger.Printf("[events] journal ready")
	return nil
}
func (j *Journal) Stop(ctx context.Context) error   { return nil }
func (j *Journal) Health(ctx context.Context) error { return nil }

func (j *Journal) Append(ctx context.Context, evt contract.Event) error {
	if evt.ID == "" { evt.ID = uuid.NewString() }
	raw, err := json.Marshal(evt.Payload)
	if err != nil { return fmt.Errorf("marshal event payload: %w", err) }
	_, err = j.db.ExecContext(ctx,
		`INSERT INTO event_journal (id, event_type, severity, payload_json) VALUES (?, ?, ?, ?)`,
		evt.ID, evt.Type, evt.Severity, string(raw))
	if err != nil { return fmt.Errorf("insert event: %w", err) }
	return nil
}
