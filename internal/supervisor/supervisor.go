package supervisor

import (
	"context"
	"fmt"
	"log"
	"sync"
)

type Logger interface { Printf(format string, v ...any) }

type Supervisor struct {
	logger   Logger
	services []Service
}

func New(logger Logger) *Supervisor {
	if logger == nil { logger = log.Default() }
	return &Supervisor{logger: logger}
}

func (s *Supervisor) Register(svc Service) { s.services = append(s.services, svc) }

func (s *Supervisor) Start(ctx context.Context) error {
	for _, svc := range s.services {
		s.logger.Printf("[supervisor] starting %s", svc.Name())
		if err := svc.Start(ctx); err != nil {
			return fmt.Errorf("start %s: %w", svc.Name(), err)
		}
	}
	return nil
}

func (s *Supervisor) Stop(ctx context.Context) error {
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var allErrs []error
	for i := len(s.services) - 1; i >= 0; i-- {
		svc := s.services[i]
		wg.Add(1)
		go func(svc Service) {
			defer wg.Done()
			s.logger.Printf("[supervisor] stopping %s", svc.Name())
			if err := svc.Stop(ctx); err != nil {
				errMu.Lock()
				allErrs = append(allErrs, fmt.Errorf("stop %s: %w", svc.Name(), err))
				errMu.Unlock()
			}
		}(svc)
	}
	wg.Wait()
	if len(allErrs) > 0 { return fmt.Errorf("shutdown errors: %v", allErrs) }
	return nil
}
