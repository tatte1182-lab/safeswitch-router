package health

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Logger interface {
	Printf(format string, v ...any)
}

type Service struct {
	db       *sql.DB
	logger   Logger
	interval time.Duration

	cancel context.CancelFunc
	wg     sync.WaitGroup

	// FIX: track previous CPU sample for delta calculation
	prevCPUIdle  uint64
	prevCPUTotal uint64
}

func NewService(db *sql.DB, logger Logger, interval time.Duration) *Service {
	return &Service{
		db:       db,
		logger:   logger,
		interval: interval,
	}
}

func (s *Service) Name() string { return "health" }

func (s *Service) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	// Prime the CPU baseline so the first real sample has a delta to compare
	if idle, total, err := readCPUSample(); err == nil {
		s.prevCPUIdle = idle
		s.prevCPUTotal = total
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		s.record(runCtx)

		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				s.record(runCtx)
			}
		}
	}()

	s.logger.Printf("[health] started interval=%s", s.interval)
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

func (s *Service) record(ctx context.Context) {
	// FIX: real system metrics — no more hardcoded stubs
	cpu  := s.cpuPercent()
	mem  := memPercent()
	disk := diskPercent("/")

	summary := "healthy"
	if cpu > 80 || mem > 85 || disk > 90 {
		summary = "degraded"
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO health_snapshots (cpu_pct, mem_pct, disk_pct, summary) VALUES (?, ?, ?, ?)`,
		cpu, mem, disk, summary,
	)
	if err != nil {
		s.logger.Printf("[health] record failed: %v", err)
		return
	}

	s.logger.Printf("[health] snapshot cpu=%.1f mem=%.1f disk=%.1f summary=%s", cpu, mem, disk, summary)
}

// cpuPercent returns CPU usage as a percentage since the last call.
// Reads /proc/stat and computes delta between idle and total jiffies.
func (s *Service) cpuPercent() float64 {
	idle, total, err := readCPUSample()
	if err != nil {
		s.logger.Printf("[health] cpu read failed: %v", err)
		return 0
	}

	deltaIdle  := idle - s.prevCPUIdle
	deltaTotal := total - s.prevCPUTotal

	s.prevCPUIdle  = idle
	s.prevCPUTotal = total

	if deltaTotal == 0 {
		return 0
	}
	used := deltaTotal - deltaIdle
	return float64(used) / float64(deltaTotal) * 100
}

// readCPUSample reads the first "cpu" line from /proc/stat and returns
// (idle jiffies, total jiffies). Called twice to compute a delta.
func readCPUSample() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, fmt.Errorf("open /proc/stat: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		// fields: cpu user nice system idle iowait irq softirq steal guest guest_nice
		if len(fields) < 5 {
			return 0, 0, fmt.Errorf("unexpected /proc/stat format")
		}
		var vals [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			vals[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
			total += vals[i-1]
		}
		idle = vals[3] // index 4 in fields = index 3 in vals
		return idle, total, nil
	}
	return 0, 0, fmt.Errorf("cpu line not found in /proc/stat")
}

// memPercent reads /proc/meminfo and returns used memory as a percentage.
func memPercent() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	vals := make(map[string]uint64)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		vals[key] = v
	}

	total     := vals["MemTotal"]
	available := vals["MemAvailable"]
	if total == 0 {
		return 0
	}
	used := total - available
	return float64(used) / float64(total) * 100
}

// diskPercent returns used disk space as a percentage for the given path.
// Uses syscall.Statfs — works on Linux and OpenWrt without cgo.
func diskPercent(path string) float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free  := stat.Bfree  * uint64(stat.Bsize)
	if total == 0 {
		return 0
	}
	used := total - free
	return float64(used) / float64(total) * 100
}
