package controlsync

import (
"context"
"database/sql"
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

cancel context.CancelFunc
wg     sync.WaitGroup
}

func NewService(
db *sql.DB,
logger Logger,
baseURL string,
nodeToken string,
commandPollEvery time.Duration,
heartbeatEvery time.Duration,
identity *identity.Service,
journal *events.Journal,
policyRuntime *policy.Runtime,
executor *commands.Executor,
) *Service {
return &Service{
db:               db,
logger:           logger,
client:           newClient(baseURL, nodeToken, logger),
commandPollEvery: commandPollEvery,
heartbeatEvery:   heartbeatEvery,
identity:         identity,
journal:          journal,
policyRuntime:    policyRuntime,
executor:         executor,
}
}

func (s *Service) Name() string { return "control-sync" }

func (s *Service) Start(ctx context.Context) error {
runCtx, cancel := context.WithCancel(ctx)
s.cancel = cancel
s.wg.Add(2)
go s.runHeartbeat(runCtx)
go s.runCommandPoll(runCtx)
s.logger.Printf("[controlsync] started")
return nil
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
