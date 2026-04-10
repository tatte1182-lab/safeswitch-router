package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/google/uuid"

	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	"github.com/getsafeswitch/safeswitch-router/internal/presence"
	"github.com/getsafeswitch/safeswitch-router/internal/tunnel"
	contractcmds "github.com/getsafeswitch/safeswitch-router/pkg/contract/commands"
)

type Logger interface{ Printf(format string, v ...any) }

type PresenceReader interface {
	Devices(ctx context.Context) ([]presence.Device, error)
}

// CommandEnqueuer is the subset of controlsync.Service the API needs.
type CommandEnqueuer interface {
	EnqueueCommand(ctx context.Context, cmd contractcmds.Command) error
}

// CAProvider is satisfied by *mitm.CA — kept as an interface so the api
// package does not import the mitm package directly.
type CAProvider interface {
	RawCert() []byte
	Subject() string
	NotAfter() string
}

type Service struct {
	addr           string
	db             *sql.DB
	logger         Logger
	identity       *identity.Service
	policyRuntime  *policy.Runtime
	presenceEngine PresenceReader
	cmdEnqueuer    CommandEnqueuer
	tunnelHealth   tunnel.TunnelHealth
	caProvider     CAProvider // nil if MITM not configured
	server         *http.Server
	wg             sync.WaitGroup
}

func NewService(
	addr string,
	db *sql.DB,
	logger Logger,
	identity *identity.Service,
	policyRuntime *policy.Runtime,
	presenceEngine PresenceReader,
	cmdEnqueuer CommandEnqueuer,
	tunnelHealth tunnel.TunnelHealth,
) *Service {
	return &Service{
		addr:           addr,
		db:             db,
		logger:         logger,
		identity:       identity,
		policyRuntime:  policyRuntime,
		presenceEngine: presenceEngine,
		cmdEnqueuer:    cmdEnqueuer,
		tunnelHealth:   tunnelHealth,
	}
}

// SetCAProvider wires the MITM CA into the API so it can serve /ca/cert and /ca/info.
// Call this from wiring.go after loading the CA, before Start().
func (s *Service) SetCAProvider(ca CAProvider) {
	s.caProvider = ca
}

func (s *Service) Name() string                { return "local-api" }
func (s *Service) Health(ctx context.Context) error { return nil }

func (s *Service) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/node", s.handleNode)
	mux.HandleFunc("/v1/policy", s.handlePolicy)
	mux.HandleFunc("/v1/devices", s.handleDevices)
	mux.HandleFunc("/v1/commands", s.handleCommands)
	mux.HandleFunc("/v1/tunnel", s.handleTunnel)

	// CA endpoints — registered only when MITM is configured
	if s.caProvider != nil {
		mux.HandleFunc("/ca/cert", s.handleCACert)
		mux.HandleFunc("/ca/info", s.handleCAInfo)
		log.Println("[api] CA endpoints registered at /ca/cert and /ca/info")
	}

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
		if err := s.server.Shutdown(ctx); err != nil {
			return err
		}
	}
	s.wg.Wait()
	return nil
}

func (s *Service) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.logger.Printf("[api] CA cert requested from %s", r.RemoteAddr)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="safeswitch-ca.pem"`)
	w.Write(s.caProvider.RawCert())
}

func (s *Service) handleCAInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"subject":%q,"not_after":%q}`,
		s.caProvider.Subject(),
		s.caProvider.NotAfter(),
	)
}

func (s *Service) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleNode(w http.ResponseWriter, r *http.Request) {
	id := s.identity.Current()
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":    id.NodeID,
		"node_name":  id.NodeName,
		"public_key": id.PublicKey,
	})
}

func (s *Service) handlePolicy(w http.ResponseWriter, r *http.Request) {
	b, err := s.policyRuntime.ActiveBundle(r.Context())
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no active bundle"})
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Service) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.presenceEngine.Devices(r.Context())
	if err != nil {
		s.logger.Printf("[api] devices query failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}
	if devices == nil {
		devices = []presence.Device{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices, "count": len(devices)})
}

func (s *Service) handleCommands(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST only"})
		return
	}

	var body struct {
		Type    string         `json:"type"`
		Payload map[string]any `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if body.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "type is required"})
		return
	}
	if body.Payload == nil {
		body.Payload = map[string]any{}
	}

	cmd := contractcmds.Command{
		ID:      uuid.NewString(),
		Type:    body.Type,
		Payload: body.Payload,
	}

	if err := s.cmdEnqueuer.EnqueueCommand(r.Context(), cmd); err != nil {
		s.logger.Printf("[api] enqueue failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "enqueue failed"})
		return
	}

	s.logger.Printf("[api] command enqueued id=%s type=%s", cmd.ID, cmd.Type)
	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":     cmd.ID,
		"type":   cmd.Type,
		"status": "pending",
	})
}

func (s *Service) handleTunnel(w http.ResponseWriter, r *http.Request) {
	snap := s.tunnelHealth.LatestHealth(r.Context())
	writeJSON(w, http.StatusOK, snap.ToMap())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
