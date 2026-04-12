package app

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// NodeType controls how this router registers itself in the family mesh.
// Valid values: "home_node" (default), "lan_node", "vps_relay"
//   home_node  — primary dedicated hardware or Ubuntu server (default)
//   lan_node   — any always-on LAN device: Pi, NAS, old laptop
//   vps_relay  — cloud relay node, lowest election priority
//
// Set via SS_ROUTER_NODE_TYPE env var.
// PublicEndpoint is the WireGuard endpoint advertised to child devices,
// e.g. "192.168.1.10" for a LAN node or "203.0.113.5" for a VPS.
// Port defaults to 51820. Set via SS_ROUTER_PUBLIC_ENDPOINT.

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
	// Mesh identity
	NodeType       string // home_node | lan_node | vps_relay
	PublicEndpoint string // host or host:port advertised to peers
	IsLANLocal     bool   // derived from NodeType
	UPnPEnabled    bool   // auto port mapping — set SS_ROUTER_UPNP=false to disable
	// Relay
	RelayListenAddr string // vps_relay only: addr for relay broker e.g. ":8443"
	RelayBrokerURL  string // home_node/lan_node: ws URL of VPS relay broker
	RelayNodeToken  string // shared secret for relay auth
	RelayFamilyID   string // home_node/lan_node: family this node serves
	RelayWGAddr     string // home_node/lan_node: local wg UDP addr e.g. "127.0.0.1:51820"
}

func LoadConfigFromEnv() (Config, error) {
	nodeType := getenv("SS_ROUTER_NODE_TYPE", "home_node")
	// Validate node type
	switch nodeType {
	case "home_node", "lan_node", "vps_relay":
		// valid
	default:
		nodeType = "home_node"
	}

	cfg := Config{
		NodeName:         getenv("SS_ROUTER_NODE_NAME", "safeswitch-router"),
		Environment:      getenv("SS_ROUTER_ENV", "dev"),
		DataDir:          getenv("SS_ROUTER_DATA_DIR", "./data"),
		DBPath:           getenv("SS_ROUTER_DB_PATH", "./data/router.db"),
		LogLevel:         getenv("SS_ROUTER_LOG_LEVEL", "info"),
		HTTPListenAddr:   getenv("SS_ROUTER_HTTP_ADDR", "127.0.0.1:8099"),
		DNSListenAddr:    getenv("SS_ROUTER_DNS_ADDR", "127.0.0.1:5353"),
		SyncBaseURL:      getenv("SS_ROUTER_SYNC_BASE_URL", "http://127.0.0.1:54321"),
		NodeToken:        getenv("SS_ROUTER_NODE_TOKEN", ""),
		AnonKey:          getenv("SS_ROUTER_ANON_KEY", ""),
		NotifyURL:        getenv("SS_ROUTER_NOTIFY_URL", ""),
		ShutdownTimeout:  time.Duration(getenvInt("SS_ROUTER_SHUTDOWN_TIMEOUT_SEC", 10)) * time.Second,
		HeartbeatEvery:   time.Duration(getenvInt("SS_ROUTER_HEARTBEAT_SEC", 30)) * time.Second,
		CommandPollEvery: time.Duration(getenvInt("SS_ROUTER_COMMAND_POLL_SEC", 5)) * time.Second,
		NodeType:         nodeType,
		PublicEndpoint:   getenv("SS_ROUTER_PUBLIC_ENDPOINT", ""),
		IsLANLocal:       nodeType == "lan_node",
		UPnPEnabled:      getenv("SS_ROUTER_UPNP", "true") != "false",
		// Relay
		RelayListenAddr: getenv("SS_ROUTER_RELAY_ADDR", ":8443"),
		RelayBrokerURL:  getenv("SS_ROUTER_RELAY_BROKER_URL", ""),
		RelayNodeToken:  getenv("SS_ROUTER_RELAY_TOKEN", ""),
		RelayFamilyID:   getenv("SS_ROUTER_RELAY_FAMILY_ID", ""),
		RelayWGAddr:     getenv("SS_ROUTER_RELAY_WG_ADDR", "127.0.0.1:51820"),
	}
	if cfg.DataDir == "" { return Config{}, fmt.Errorf("data dir cannot be empty") }
	if cfg.DBPath == ""  { return Config{}, fmt.Errorf("db path cannot be empty") }
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" { return v }
	return fallback
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" { return fallback }
	n, err := strconv.Atoi(v)
	if err != nil { return fallback }
	return n
}
