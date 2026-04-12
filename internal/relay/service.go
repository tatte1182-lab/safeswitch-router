// Package relay implements the SafeSwitch relay broker (VPS side) and relay
// client (home node side). The broker runs on the VPS and stitches together
// WebSocket connections from home nodes and child devices. The client runs on
// the home node and maintains a persistent outbound connection to the broker.
package relay

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// BrokerService is a supervisor.Service that runs the relay broker on the VPS.
// It listens on :443 (or cfg port) and accepts WebSocket connections from:
//   - Home nodes: GET /relay/node?node_id=&family_id=&token=
//   - Child devices: GET /relay/device?family_id=&device_id=&token=
type BrokerService struct {
	listenAddr string
	nodeToken  string
	server     *http.Server
}

func NewBrokerService(listenAddr, nodeToken string) *BrokerService {
	return &BrokerService{
		listenAddr: listenAddr,
		nodeToken:  nodeToken,
	}
}

func (s *BrokerService) Name() string { return "relay-broker" }

func (s *BrokerService) Start(ctx context.Context) error {
	broker := NewBroker()
	handler := NewHandler(broker, s.nodeToken)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	s.server = &http.Server{
		Addr:        s.listenAddr,
		Handler:     mux,
		ReadTimeout: 0, // WebSocket — long-lived
		IdleTimeout: 120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shutCtx)
	}()

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Non-fatal — log only. Port 443 may be in use by derper.
			// In that case, set SS_ROUTER_RELAY_ADDR to a different port e.g. :8443
			fmt.Printf("[relay-broker] listen error: %v\n", err)
		}
	}()

	fmt.Printf("[relay-broker] listening on %s\n", s.listenAddr)
	return nil
}

func (s *BrokerService) Stop(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

func (s *BrokerService) Health(ctx context.Context) error { return nil }
