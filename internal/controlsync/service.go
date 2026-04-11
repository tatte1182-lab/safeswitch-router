package controlsync

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/commands"
	"github.com/getsafeswitch/safeswitch-router/internal/events"
	"github.com/getsafeswitch/safeswitch-router/internal/identity"
	"github.com/getsafeswitch/safeswitch-router/internal/policy"
	contractcmds "github.com/getsafeswitch/safeswitch-router/pkg/contract/commands"
)

type Logger interface {
Printf(format string, v ...any)
}

type Service struct {
	db               *sql.DB
	logger           Logger
	client           *client
	commandPollEvery time.Duration
	heartbeatEvery   time.Duration
	identity         *identity.Service
	journal          *events.Journal
	policyRuntime    *policy.Runtime
	executor         *commands.Executor
	// Mesh identity
	nodeType       string // home_node | lan_node | vps_relay
	publicEndpoint string // host or host:port advertised to the mesh
	isLANLocal     bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewService(
	db *sql.DB,
	logger Logger,
	baseURL string,
	nodeToken string,
	anonKey string,
	commandPollEvery time.Duration,
	heartbeatEvery time.Duration,
	identity *identity.Service,
	journal *events.Journal,
	policyRuntime *policy.Runtime,
	executor *commands.Executor,
	nodeType string,
	publicEndpoint string,
	isLANLocal bool,
) *Service {
	if nodeType == "" {
		nodeType = "home_node"
	}
	return &Service{
		db:               db,
		logger:           logger,
		client:           newClient(baseURL, nodeToken, anonKey, logger),
		commandPollEvery: commandPollEvery,
		heartbeatEvery:   heartbeatEvery,
		identity:         identity,
		journal:          journal,
		policyRuntime:    policyRuntime,
		executor:         executor,
		nodeType:         nodeType,
		publicEndpoint:   publicEndpoint,
		isLANLocal:       isLANLocal,
	}
}

func (s *Service) Name() string { return "control-sync" }

func (s *Service) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	// Register as lan_node on first start if configured.
	// home_node registration is handled by the existing node claiming flow.
	// lan_node and vps_relay need to self-register via RPC.
	if s.nodeType == "lan_node" || s.nodeType == "vps_relay" {
		if err := s.registerNodeType(ctx); err != nil {
			s.logger.Printf("[controlsync] node type registration warning: %v (will retry on heartbeat)", err)
		}
	}

	s.wg.Add(3)
	go s.runHeartbeat(runCtx)
	go s.runCommandPoll(runCtx)
	go s.runEnforcementSync(runCtx)
	s.logger.Printf("[controlsync] started node_type=%s lan=%v (heartbeat=%s commandPoll=%s)",
		s.nodeType, s.isLANLocal, s.heartbeatEvery, s.commandPollEvery)
	return nil
}

// registerNodeType calls the appropriate Supabase RPC to register this node
// in the mesh with its capabilities. Idempotent — safe to call on every restart.
func (s *Service) registerNodeType(ctx context.Context) error {
	id := s.identity.Current()
	familyID := s.loadFamilyID(ctx)
	if familyID == "" {
		return nil // not yet claimed — will retry
	}

	wgPubKey := s.loadWGPublicKey(ctx)

	payload := map[string]any{
		"p_family_id":          familyID,
		"p_node_token":         "", // token already validated at claim time
		"p_display_name":       id.NodeName,
		"p_os_platform":        "linux",
		"p_wireguard_pub_key":  wgPubKey,
		"p_wireguard_endpoint": s.publicEndpoint,
	}

	rpc := "register_lan_node"
	if s.nodeType == "vps_relay" {
		// vps_relay uses same RPC but different node_type — handled server-side
		// by checking the existing node record
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, status, err := s.client.postREST(ctx, "/rest/v1/rpc/"+rpc, raw)
	if err != nil {
		return err
	}
	if status >= 400 {
		s.logger.Printf("[controlsync] %s RPC status=%d", rpc, status)
		return nil // non-fatal
	}

	s.logger.Printf("[controlsync] registered as %s endpoint=%s", s.nodeType, s.publicEndpoint)
	return nil
}

func (s *Service) loadWGPublicKey(ctx context.Context) string {
	var key string
	_ = s.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'public_key'`,
	).Scan(&key)
	return key
}

func (s *Service) Stop(ctx context.Context) error {
if s.cancel != nil {
s.cancel()
}
s.wg.Wait()
return nil
}

func (s *Service) Health(ctx context.Context) error { return nil }

func (s *Service) EnqueueCommand(ctx context.Context, cmd contractcmds.Command) error {
return s.executor.Enqueue(ctx, cmd)
}
