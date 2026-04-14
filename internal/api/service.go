package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	"github.com/getsafeswitch/safeswitch-router/internal/presence"
	"github.com/getsafeswitch/safeswitch-router/internal/tunnel"
	contractcmds "github.com/getsafeswitch/safeswitch-router/pkg/contract/commands"
)

type Logger interface {
	Printf(format string, v ...any)
}

type PresenceReader interface {
	Devices(ctx context.Context) ([]presence.Device, error)
}

type CommandEnqueuer interface {
	EnqueueCommand(ctx context.Context, cmd contractcmds.Command) error
}

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
	caProvider     CAProvider
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

func (s *Service) SetCAProvider(ca CAProvider) {
	s.caProvider = ca
}

func (s *Service) Name() string {
	return "local-api"
}

func (s *Service) Health(ctx context.Context) error {
	switch {
	case s.logger == nil:
		return errors.New("logger not configured")
	case s.identity == nil:
		return errors.New("identity service not configured")
	case s.policyRuntime == nil:
		return errors.New("policy runtime not configured")
	case s.presenceEngine == nil:
		return errors.New("presence engine not configured")
	case s.cmdEnqueuer == nil:
		return errors.New("command enqueuer not configured")
	case s.tunnelHealth == nil:
		return errors.New("tunnel health not configured")
	default:
		return nil
	}
}

func (s *Service) Start(ctx context.Context) error {
	if err := s.Health(ctx); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/node", s.handleNode)
	mux.HandleFunc("/v1/policy", s.handlePolicy)
	mux.HandleFunc("/v1/devices", s.handleDevices)
	mux.HandleFunc("/v1/commands", s.handleCommands)
	mux.HandleFunc("/v1/tunnel", s.handleTunnel)

	if s.caProvider != nil {
		mux.HandleFunc("/ca/cert", s.handleCACert)
		mux.HandleFunc("/ca/info", s.handleCAInfo)
		s.logger.Printf("[api] CA endpoints enabled")
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("api bind failed on %s: %w", s.addr, err)
	}

	s.server = &http.Server{
		Handler:           s.withMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.logger.Printf("[api] listening on %s", s.addr)
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

func (s *Service) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCommonHeaders(w)

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}

		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "forbidden"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Service) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	if err := s.Health(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleNode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	id := s.identity.Current()
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":    id.NodeID,
		"node_name":  id.NodeName,
		"public_key": id.PublicKey,
	})
}

func (s *Service) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	b, err := s.policyRuntime.ActiveBundle(r.Context())
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no active bundle"})
		return
	}

	writeJSON(w, http.StatusOK, b)
}

func (s *Service) handleDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	devices, err := s.presenceEngine.Devices(r.Context())
	if err != nil {
		s.logger.Printf("[api] devices query failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
		return
	}

	if devices == nil {
		devices = []presence.Device{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"devices": devices,
		"count":   len(devices),
	})
}

func (s *Service) handleCommands(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST required"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer r.Body.Close()

	var body struct {
		Type    string         `json:"type"`
		Payload map[string]any `json:"payload"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	var extra any
	if err := dec.Decode(&extra); err != nil && !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	if extra != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}

	if body.Type == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "type is required"})
		return
	}

	if !isValidCommandType(body.Type) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid command type"})
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
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	snap := s.tunnelHealth.LatestHealth(r.Context())
	writeJSON(w, http.StatusOK, snap.ToMap())
}

func (s *Service) handleCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="safeswitch-ca.pem"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.caProvider.RawCert())
}

func (s *Service) handleCAInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"subject":   s.caProvider.Subject(),
		"not_after": s.caProvider.NotAfter(),
	})
}

func isValidCommandType(t string) bool {
	switch t {
	case "LOCK",
		"UNLOCK",
		"REFRESH_POLICY",
		"PAUSE",
		"RESUME":
		return true
	default:
		return false
	}
}

func setCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}