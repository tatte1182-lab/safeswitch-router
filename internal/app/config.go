package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds every runtime knob for the router process.
// All values are loaded from environment variables; nothing is hardcoded.
type Config struct {
	NodeName         string
	Environment      string
	DataDir          string
	DBPath           string
	LogLevel         string
	HTTPListenAddr   string
	DNSListenAddr    string
	SyncBaseURL      string
	NodeToken        string
	AnonKey          string
	NotifyURL        string
	ShutdownTimeout  time.Duration
	HeartbeatEvery   time.Duration
	CommandPollEvery time.Duration

	// Mesh / node topology
	NodeType       string // home_node | lan_node | vps_relay
	PublicEndpoint string // host:port or host — included in heartbeats for peer discovery
	IsLANLocal     bool
	UPnPEnabled    bool

	// WireGuard
	// Canonical private key lives at SS_ROUTER_WG_PRIVATE_KEY_FILE.
	// If unset, falls back to /etc/safeswitch/wireguard/privatekey.
	// tunnel/manager.go also backfills from SQLite tunnel_config.private_key
	// if the file is missing on first boot.
	WGPrivateKeyFile string

	// NAT interface — the upstream interface that wg0 traffic is masqueraded onto.
	// Defaults to eth0 (correct for VPS / most Linux servers).
	// Override with SS_ROUTER_NAT_IFACE for Acer Swift (wlp0s12f0), RPi (wlan0), etc.
	NATIface string

	// Relay
	RelayListenAddr string
	RelayBrokerURL  string // required only for home_node / lan_node that connect to a relay
	RelayNodeToken  string
	RelayFamilyID   string
	RelayWGAddr     string // local WG endpoint for the relay bridge, e.g. 127.0.0.1:51820
}

func LoadConfigFromEnv() (Config, error) {
	nodeType := strings.ToLower(getenv("SS_ROUTER_NODE_TYPE", "home_node"))

	switch nodeType {
	case "home_node", "lan_node", "vps_relay":
	default:
		return Config{}, fmt.Errorf("invalid SS_ROUTER_NODE_TYPE %q — must be home_node, lan_node, or vps_relay", nodeType)
	}

	cfg := Config{
		NodeName:         getenv("SS_ROUTER_NODE_NAME", "safeswitch-router"),
		Environment:      getenv("SS_ROUTER_ENV", "dev"),
		DataDir:          getenv("SS_ROUTER_DATA_DIR", "./data"),
		DBPath:           getenv("SS_ROUTER_DB_PATH", "./data/router.db"),
		LogLevel:         strings.ToLower(getenv("SS_ROUTER_LOG_LEVEL", "info")),
		HTTPListenAddr:   getenv("SS_ROUTER_HTTP_ADDR", "127.0.0.1:8099"),
		DNSListenAddr:    getenv("SS_ROUTER_DNS_ADDR", "127.0.0.1:5353"),
		SyncBaseURL:      getenv("SS_ROUTER_SYNC_BASE_URL", ""),
		NodeToken:        getenv("SS_ROUTER_NODE_TOKEN", ""),
		AnonKey:          getenv("SS_ROUTER_ANON_KEY", ""),
		NotifyURL:        getenv("SS_ROUTER_NOTIFY_URL", ""),

		ShutdownTimeout:  durationFromEnv("SS_ROUTER_SHUTDOWN_TIMEOUT_SEC", 10),
		HeartbeatEvery:   durationFromEnv("SS_ROUTER_HEARTBEAT_SEC", 30),
		CommandPollEvery: durationFromEnv("SS_ROUTER_COMMAND_POLL_SEC", 5),

		NodeType:       nodeType,
		PublicEndpoint: getenv("SS_ROUTER_PUBLIC_ENDPOINT", ""),
		IsLANLocal:     nodeType == "lan_node",
		UPnPEnabled:    parseBool(getenv("SS_ROUTER_UPNP", "true")),

		// WireGuard private key file path — used by tunnel/manager.go
		WGPrivateKeyFile: getenv("SS_ROUTER_WG_PRIVATE_KEY_FILE", "/etc/safeswitch/wireguard/privatekey"),

		// NAT interface — default eth0 is correct for VPS / DigitalOcean / Hetzner.
		// Acer Swift home node: set SS_ROUTER_NAT_IFACE=wlp0s12f0
		NATIface: getenv("SS_ROUTER_NAT_IFACE", "eth0"),

		RelayListenAddr: getenv("SS_ROUTER_RELAY_ADDR", ":8443"),
		RelayBrokerURL:  getenv("SS_ROUTER_RELAY_BROKER_URL", ""),
		RelayNodeToken:  getenv("SS_ROUTER_RELAY_TOKEN", ""),
		RelayFamilyID:   getenv("SS_ROUTER_RELAY_FAMILY_ID", ""),
		RelayWGAddr:     getenv("SS_ROUTER_RELAY_WG_ADDR", "127.0.0.1:51820"),
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.DataDir == "" {
		return errors.New("SS_ROUTER_DATA_DIR cannot be empty")
	}
	if c.DBPath == "" {
		return errors.New("SS_ROUTER_DB_PATH cannot be empty")
	}

	// DBPath must resolve inside DataDir (prevents path traversal)
	dataDirAbs, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("invalid SS_ROUTER_DATA_DIR: %w", err)
	}
	dbPathAbs, err := filepath.Abs(c.DBPath)
	if err != nil {
		return fmt.Errorf("invalid SS_ROUTER_DB_PATH: %w", err)
	}
	if !strings.HasPrefix(dbPathAbs, dataDirAbs) {
		return fmt.Errorf("SS_ROUTER_DB_PATH must be inside SS_ROUTER_DATA_DIR")
	}

	// Listen address validation
	if err := validateAddr(c.HTTPListenAddr); err != nil {
		return fmt.Errorf("invalid SS_ROUTER_HTTP_ADDR: %w", err)
	}
	if err := validateAddr(c.DNSListenAddr); err != nil {
		return fmt.Errorf("invalid SS_ROUTER_DNS_ADDR: %w", err)
	}

	// In prod the HTTP API must only bind on loopback
	if c.Environment == "prod" {
		host, _, _ := net.SplitHostPort(c.HTTPListenAddr)
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("SS_ROUTER_HTTP_ADDR must bind to loopback in prod (got %s)", c.HTTPListenAddr)
		}
	}

	// PublicEndpoint is optional but must be valid when set
	if c.PublicEndpoint != "" {
		if _, _, err := net.SplitHostPort(c.PublicEndpoint); err != nil {
			if net.ParseIP(c.PublicEndpoint) == nil {
				return fmt.Errorf("invalid SS_ROUTER_PUBLIC_ENDPOINT %q — must be host:port or IP", c.PublicEndpoint)
			}
		}
	}

	// vps_relay must have a relay listen address
	if c.NodeType == "vps_relay" {
		if c.RelayListenAddr == "" {
			return fmt.Errorf("SS_ROUTER_RELAY_ADDR is required for vps_relay")
		}
	}

	// home_node / lan_node relay broker URL is OPTIONAL — not every deployment
	// uses a relay broker (e.g. a home node with a public IP or a standalone VPS).
	// If RelayBrokerURL is empty the relay client service simply is not started
	// (see wiring.go switch case home_node/lan_node).

	// Sanity limits
	if c.CommandPollEvery < 1*time.Second {
		return fmt.Errorf("SS_ROUTER_COMMAND_POLL_SEC must be >= 1 (got %s)", c.CommandPollEvery)
	}
	if c.HeartbeatEvery < 5*time.Second {
		return fmt.Errorf("SS_ROUTER_HEARTBEAT_SEC must be >= 5 (got %s)", c.HeartbeatEvery)
	}

	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func validateAddr(addr string) error {
	if addr == "" {
		return errors.New("empty address")
	}
	_, _, err := net.SplitHostPort(addr)
	return err
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func durationFromEnv(key string, fallback int) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return time.Duration(fallback) * time.Second
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return time.Duration(fallback) * time.Second
	}
	return time.Duration(n) * time.Second
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}
