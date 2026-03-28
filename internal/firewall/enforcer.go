package firewall

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

// RouteProfileReader returns stored route profiles per device.
type RouteProfileReader interface {
	RouteProfileForMAC(ctx context.Context, mac string) string
	RouteProfileForKey(ctx context.Context, publicKey string) string
}

// Child is one entry from a policy bundle.
type Child struct {
	DeviceID           string
	ChildID            string
	DeviceMAC          string
	WireguardPublicKey string
	WireguardIP        string
	DisplayName        string
	Paused             bool
	RouteMode          string
}

type Enforcer struct {
	db             *sql.DB
	routeProfile   RouteProfileReader
	devMode        bool
	logger         *log.Logger
	bundleProvider func() []Child
}

func NewEnforcer(db *sql.DB, rp RouteProfileReader, devMode bool, logger *log.Logger) *Enforcer {
	return &Enforcer{db: db, routeProfile: rp, devMode: devMode, logger: logger}
}

func (e *Enforcer) Sync(ctx context.Context, children []Child) error {
	if e.devMode {
		e.logger.Printf("[firewall] devMode sync children=%d", len(children))
		return nil
	}
	exec.Command("iptables", "-N", SSChain).Run()
	for _, checkArgs := range EnsureForwardJump() {
		if err := exec.Command("iptables", checkArgs...).Run(); err != nil {
			insertArgs := InsertForwardJump(checkArgs)
			exec.Command("iptables", insertArgs...).Run()
		}
	}
	if err := e.runIPTables(ChainFlushArgs()); err != nil {
		return fmt.Errorf("flush chain: %w", err)
	}
	applied := 0
	for _, child := range children {
		ip := e.resolveIP(ctx, child)
		if ip == "" {
			e.logger.Printf("[firewall] skip %s — no tunnel IP", child.DisplayName)
			continue
		}
		state := e.resolveState(ctx, child)
		rs := BuildRules(ip, state)
		for _, rule := range rs.Rules {
			if err := e.runIPTables(rule.Args); err != nil {
				e.logger.Printf("[firewall] rule error ip=%s: %v", ip, err)
			}
		}
		applied++
		e.logger.Printf("[firewall] applied ip=%s state=%s device=%s", ip, state, child.DisplayName)
	}
	e.logger.Printf("[firewall] sync complete children=%d applied=%d", len(children), applied)
	return nil
}

// resolveIP: prefer bundle WireguardIP if in tunnel subnet, else look up tunnel_peers by public key.
func (e *Enforcer) resolveIP(ctx context.Context, child Child) string {
	if child.WireguardIP != "" && strings.HasPrefix(child.WireguardIP, "10.10.0.") {
		return child.WireguardIP
	}
	if child.WireguardPublicKey != "" {
		var ip string
		if err := e.db.QueryRowContext(ctx,
			`SELECT replace(allowed_ip, '/32', '') FROM tunnel_peers WHERE public_key = ?`,
			child.WireguardPublicKey,
		).Scan(&ip); err == nil && ip != "" {
			return ip
		}
	}
	return ""
}

// resolveState: explicit route profile > bundle pause > bundle route_mode.
func (e *Enforcer) resolveState(ctx context.Context, child Child) string {
	if e.routeProfile != nil {
		if p := e.routeProfile.RouteProfileForKey(ctx, child.WireguardPublicKey); p != "" {
			switch p {
			case "full_tunnel":
				return StateFullTunnel
			case "service_only":
				return StateServiceOnly
			case "blocked":
				return StatePaused
			}
		}
		if p := e.routeProfile.RouteProfileForMAC(ctx, child.DeviceMAC); p != "" {
			switch p {
			case "full_tunnel":
				return StateFullTunnel
			case "service_only":
				return StateServiceOnly
			case "blocked":
				return StatePaused
			}
		}
	}
	if child.Paused {
		return StatePaused
	}
	switch child.RouteMode {
	case "full_tunnel":
		return StateFullTunnel
	case "service_only":
		return StateServiceOnly
	}
	return StateFullAccess
}

func (e *Enforcer) runIPTables(args []string) error {
	cmd := exec.Command("iptables", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables %v: %w (output: %s)", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// bundleProvider is set by wiring after construction.
var bundleProvider func() []Child

func (e *Enforcer) SetBundleProvider(fn func() []Child) { e.bundleProvider = fn }

func (e *Enforcer) Name() string { return "firewall-enforcer" }
func (e *Enforcer) Stop(_ context.Context) error { return nil }
func (e *Enforcer) Health(_ context.Context) error { return nil }

func (e *Enforcer) Start(ctx context.Context) error {
	e.logger.Printf("[firewall] enforcer started devMode=%v", e.devMode)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		children := []Child{}
		if e.bundleProvider != nil {
			children = e.bundleProvider()
		}
		_ = e.Sync(ctx, children)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if e.bundleProvider != nil {
					_ = e.Sync(ctx, e.bundleProvider())
				}
			}
		}
	}()
	return nil
}

// SyncFromBundle is called by wiring after a policy bundle swap.
func (e *Enforcer) SyncFromBundle(ctx context.Context) error {
	children := []Child{}
	if e.bundleProvider != nil {
		children = e.bundleProvider()
	}
	return e.Sync(ctx, children)
}

// PauseDevice blocks all traffic from a device MAC immediately.
func (e *Enforcer) PauseDevice(ctx context.Context, mac string) error {
	if e.devMode {
		e.logger.Printf("[firewall] devMode PauseDevice mac=%s", mac)
		return nil
	}
	for _, args := range ChainEnsureArgs() {
		exec.Command("iptables", args...).Run()
	}
	rs := BuildRules(mac, StatePaused)
	for _, rule := range rs.Rules {
		if err := e.runIPTables(rule.Args); err != nil {
			e.logger.Printf("[firewall] PauseDevice rule error: %v", err)
		}
	}
	return nil
}

// UnpauseDevice removes pause rules for a device MAC.
func (e *Enforcer) UnpauseDevice(ctx context.Context, mac string) error {
	if e.devMode {
		e.logger.Printf("[firewall] devMode UnpauseDevice mac=%s", mac)
		return nil
	}
	// Full resync restores correct state without leaving stale rules.
	return e.SyncFromBundle(ctx)
}
