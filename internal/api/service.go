package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	"github.com/getsafeswitch/safeswitch-router/internal/presence"
)

type Logger interface { Printf(format string, v ...any) }

type PresenceReader interface {
	Devices(ctx context.Context) ([]presence.Device, error)
}

type Service struct {
	addr           string
	db             *sql.DB
	logger         Logger
	identity       *identity.Service
	policyRuntime  *policy.Runtime
	presenceEngine PresenceReader
	server         *http.Server
	wg             sync.WaitGroup
}

func NewService(addr string, db *sql.DB, logger Logger, identity *identity.Service, policyRuntime *policy.Runtime, presenceEngine PresenceReader) *Service {
	return &Service{addr: addr, db: db, logger: logger, identity: identity, policyRuntime: policyRuntime, presenceEngine: presenceEngine}
}

func (s *Service) Name() string               { return "local-api" }
func (s *Service) Health(ctx context.Context) error { return nil }

func (s *Service) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/node", s.handleNode)
	mux.HandleFunc("/v1/policy", s.handlePolicy)
	mux.HandleFunc("/v1/devices", s.handleDevices)
	s.server = &http.Server{Addr: s.addr, Handler: mux}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.logger.Printf("[api] listening on %s", s.addr)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Printf("[api] server error: %v", err)
		}
	}()
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.server != nil {
		if err := s.server.Shutdown(ctx); err != nil { return err }
	}
	s.wg.Wait()
	return nil
}

func (s *Service) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
func (s *Service) handleNode(w http.ResponseWriter, r *http.Request) {
	id := s.identity.Current()
	writeJSON(w, http.StatusOK, map[string]any{"node_id": id.NodeID, "node_name": id.NodeName, "public_key": id.PublicKey})
}
func (s *Service) handlePolicy(w http.ResponseWriter, r *http.Request) {
	b, err := s.policyRuntime.ActiveBundle(r.Context())
	if err != nil { writeJSON(w, http.StatusNotFound, map[string]any{"error": "no active bundle"}); return }
	writeJSON(w, http.StatusOK, b)
}
func (s *Service) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.presenceEngine.Devices(r.Context())
	if err != nil {
		s.logger.Printf("[api] devices query failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	if devices == nil { devices = []presence.Device{} }
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices, "count": len(devices)})
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
