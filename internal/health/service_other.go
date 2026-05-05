//go:build !linux

// Non-Linux stub for the health package. The real implementation
// in service.go uses Linux-specific syscalls (Statfs) for disk
// usage stats. On dev machines (Windows, macOS) we provide a
// degenerate Service that satisfies the supervisor contract but
// reports zero disk metrics — the prod build (always Linux) uses
// the real one.
//
// If you find yourself adding logic here beyond stubs, that's a
// signal the health package should grow proper cross-platform
// abstractions instead of two divergent files.

package health

import (
	"context"
	"database/sql"
	"time"
)

// Service is the dev-stub form. Same exported surface as the Linux
// build so callers (wiring, supervisor) link cleanly.
type Service struct{}

// Logger matches the interface NewService expected. Kept here so
// the dev build doesn't import telemetry just for the type.
type Logger interface {
	Printf(format string, args ...any)
}

func NewService(_ *sql.DB, _ Logger, _ time.Duration) *Service {
	return &Service{}
}

func (s *Service) Name() string                      { return "health-stub" }
func (s *Service) Start(_ context.Context) error     { return nil }
func (s *Service) Stop(_ context.Context) error      { return nil }
func (s *Service) Health(_ context.Context) error    { return nil }