package app

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

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
}

func LoadConfigFromEnv() (Config, error) {
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
