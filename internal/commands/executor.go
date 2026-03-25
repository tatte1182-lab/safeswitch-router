package commands

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/getsafeswitch/safeswitch-router/pkg/contract/commands"
)

// Logger is the minimal logging interface the executor needs.
type Logger interface {
	Printf(format string, v ...any)
}

// Handler is a typed command handler. It receives the decoded payload map
// and returns a result map (written to command_ledger.result_json) or an error.
type Handler func(ctx context.Context, payload map[string]any) (map[string]any, error)

// Executor dispatches incoming commands to registered handlers and maintains
// the full status lifecycle in command_ledger:
//
//	pending → acked → executing → done | failed
//
// All state transitions are written to SQLite so the cloud can read back
// the outcome on its next poll.
type Executor struct {
	db       *sql.DB
	logger   Logger
	handlers map[string]Handler
	mu       sync.RWMutex
}

// NewExecutor creates an Executor backed by db. Handlers are registered
// separately via Register so each package can wire itself in during startup.
func NewExecutor(db *sql.DB, logger Logger) *Executor {
	return &Executor{
		db:       db,
		logger:   logger,
		handlers: make(map[string]Handler),
	}
}

// Register adds a handler for the given command type.
// Panics if the same type is registered twice — catches wiring mistakes at startup.
func (e *Executor) Register(commandType string, h Handler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.handlers[commandType]; exists {
		panic(fmt.Sprintf("commands: handler already registered for %q", commandType))
	}
	e.handlers[commandType] = h
	e.logger.Printf("[executor] registered handler type=%s", commandType)
}

// Execute runs a single command through its full lifecycle.
// It is safe to call Execute concurrently for different commands.
// Calling Execute for a command that is already done or failed is a no-op
// (idempotency guard via command_ledger status check).
func (e *Executor) Execute(ctx context.Context, cmd commands.Command) {
	// Idempotency: skip if already terminal
	if e.isTerminal(ctx, cmd.ID) {
		e.logger.Printf("[executor] skip already-terminal command id=%s type=%s", cmd.ID, cmd.Type)
		return
	}

	e.logger.Printf("[executor] executing id=%s type=%s", cmd.ID, cmd.Type)

	// acked
	if err := e.setStatus(ctx, cmd.ID, commands.StatusAcked, nil, ""); err != nil {
		e.logger.Printf("[executor] ack failed id=%s: %v", cmd.ID, err)
		return
	}

	// executing
	if err := e.setStatus(ctx, cmd.ID, commands.StatusExecuting, nil, ""); err != nil {
		e.logger.Printf("[executor] executing status failed id=%s: %v", cmd.ID, err)
		return
	}

	e.mu.RLock()
	h, ok := e.handlers[cmd.Type]
	e.mu.RUnlock()

	if !ok {
		errText := fmt.Sprintf("no handler registered for command type %q", cmd.Type)
		e.logger.Printf("[executor] unhandled id=%s type=%s", cmd.ID, cmd.Type)
		_ = e.setStatus(ctx, cmd.ID, commands.StatusFailed, nil, errText)
		return
	}

	result, err := h(ctx, cmd.Payload)
	if err != nil {
		e.logger.Printf("[executor] handler failed id=%s type=%s: %v", cmd.ID, cmd.Type, err)
		_ = e.setStatus(ctx, cmd.ID, commands.StatusFailed, nil, err.Error())
		return
	}

	e.logger.Printf("[executor] done id=%s type=%s", cmd.ID, cmd.Type)
	_ = e.setStatus(ctx, cmd.ID, commands.StatusDone, result, "")
}

// Enqueue inserts a command into command_ledger with status=pending
// if it does not already exist. Used by controlsync when it receives
// commands from Supabase.
func (e *Executor) Enqueue(ctx context.Context, cmd commands.Command) error {
	payloadRaw, err := json.Marshal(cmd.Payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	_, err = e.db.ExecContext(ctx, `
		INSERT INTO command_ledger (id, command_type, status, payload_json, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING
	`, cmd.ID, cmd.Type, commands.StatusPending, string(payloadRaw),
		time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("enqueue command: %w", err)
	}
	return nil
}

// PendingCommands returns all commands in the ledger with status=pending,
// ordered oldest-first so commands execute in the order they were received.
func (e *Executor) PendingCommands(ctx context.Context) ([]commands.Command, error) {
	rows, err := e.db.QueryContext(ctx, `
		SELECT id, command_type, payload_json
		FROM command_ledger
		WHERE status = ?
		ORDER BY created_at ASC
	`, commands.StatusPending)
	if err != nil {
		return nil, fmt.Errorf("query pending commands: %w", err)
	}
	defer rows.Close()

	var cmds []commands.Command
	for rows.Next() {
		var c commands.Command
		var payloadRaw string
		if err := rows.Scan(&c.ID, &c.Type, &payloadRaw); err != nil {
			return nil, fmt.Errorf("scan command row: %w", err)
		}
		if err := json.Unmarshal([]byte(payloadRaw), &c.Payload); err != nil {
			return nil, fmt.Errorf("unmarshal payload id=%s: %w", c.ID, err)
		}
		cmds = append(cmds, c)
	}
	return cmds, rows.Err()
}

// isTerminal returns true if the command already has a terminal status
// (done, failed, expired) — used for idempotency.
func (e *Executor) isTerminal(ctx context.Context, id string) bool {
	var status string
	err := e.db.QueryRowContext(ctx,
		`SELECT status FROM command_ledger WHERE id = ?`, id,
	).Scan(&status)
	if err != nil {
		return false
	}
	s := commands.Status(status)
	return s == commands.StatusDone || s == commands.StatusFailed || s == commands.StatusExpired
}

// setStatus updates command_ledger status, optional result JSON, and error text.
func (e *Executor) setStatus(ctx context.Context, id string, status commands.Status, result map[string]any, errText string) error {
	resultRaw := []byte("{}")
	if result != nil {
		var err error
		resultRaw, err = json.Marshal(result)
		if err != nil {
			return fmt.Errorf("marshal result: %w", err)
		}
	}

	_, err := e.db.ExecContext(ctx, `
		UPDATE command_ledger
		SET status = ?, result_json = ?, error_text = ?, updated_at = ?
		WHERE id = ?
	`, status, string(resultRaw), errText,
		time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return fmt.Errorf("update command status: %w", err)
	}
	return nil
}
