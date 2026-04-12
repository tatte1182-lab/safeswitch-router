package relay

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// BrokerService is a supervisor.Service that runs the relay broker on the VPS.
type BrokerService struct {
	listenAddr string
	nodeToken  string
	broker     *Broker
	server     *http.Server
}

// NewBrokerService creates a broker service with an internally managed broker.
func NewBrokerService(listenAddr, nodeToken string) *BrokerService {
	return NewBrokerServiceWithBroker(NewBroker(), listenAddr, nodeToken)
}

// NewBrokerServiceWithBroker creates a broker service using a pre-created broker.
// Use this when you need to share the broker with other components (e.g. UDPBridge).
func NewBrokerServiceWithBroker(broker *Broker, listenAddr, nodeToken string) *BrokerService {
	return &BrokerService{
		listenAddr: listenAddr,
		nodeToken:  nodeToken,
		broker:     broker,
	}
}

func (s *BrokerService) Name() string { return "relay-broker" }

func (s *BrokerService) Start(ctx context.Context) error {
	handler := NewHandler(s.broker, s.nodeToken)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	s.server = &http.Server{
		Addr:        s.listenAddr,
		Handler:     mux,
		ReadTimeout: 0,
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
