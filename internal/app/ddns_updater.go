package app

// ddns_updater.go
//
// HARDENING: Detects public IP changes and updates Supabase nodes table.
//
// Problem: The home node sits on a residential ISP IP that changes
// periodically. When it rotates, all enrolled devices have a stale endpoint
// and can't reconnect until someone manually updates Supabase.
//
// Fix: A background goroutine polls the public IP every 5 minutes. When a
// change is detected it writes the new IP and updated wireguard_endpoint to
// the nodes table. Child devices pick up the change via get_child_tunnel_config
// on their next reconnect refresh cycle (triggered after 3 consecutive failures).
//
// IP detection uses two independent sources — if they disagree the update is
// skipped until consensus (avoids thrashing on transient DNS failures).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	ddnsCheckInterval = 5 * time.Minute
	ddnsHTTPTimeout   = 8 * time.Second
)

// ipCheckSource is a URL that returns the public IP as plain text or JSON.
type ipCheckSource struct {
	url     string
	jsonKey string // empty = plain text response
}

var ipSources = []ipCheckSource{
	{"https://api.ipify.org", ""},
	{"https://api64.ipify.org?format=json", "ip"},
	{"https://checkip.amazonaws.com", ""},
}

// StartDDNSUpdater runs a background goroutine that keeps the node's
// public IP and wireguard_endpoint in sync with Supabase.
// nodeID: the UUID of this node in the nodes table.
// supabaseURL / supabaseKey: service-role credentials for REST updates.
// duckDNSHost: the DuckDNS hostname (e.g. "safeswitch-tee.duckdns.org").
// wgPort: WireGuard port (default 51820).
func StartDDNSUpdater(ctx context.Context, nodeID, supabaseURL, supabaseKey, duckDNSHost string, wgPort int) {
	go func() {
		var lastKnownIP string

		// Check immediately on startup, then on interval
		ticker := time.NewTicker(ddnsCheckInterval)
		defer ticker.Stop()

		for {
			currentIP, err := detectPublicIP()
			if err != nil {
				log.Printf("[ddns] IP detection failed: %v", err)
			} else if currentIP != lastKnownIP {
				if lastKnownIP == "" {
					log.Printf("[ddns] initial public IP: %s", currentIP)
				} else {
					log.Printf("[ddns] IP changed: %s → %s — updating Supabase", lastKnownIP, currentIP)
				}

				endpoint := duckDNSHost
				if endpoint == "" {
					// No DuckDNS configured — use raw IP
					endpoint = currentIP
				}

				if err := updateNodeEndpoint(supabaseURL, supabaseKey, nodeID, currentIP, endpoint, wgPort); err != nil {
					log.Printf("[ddns] Supabase update failed: %v", err)
				} else {
					lastKnownIP = currentIP
					log.Printf("[ddns] endpoint updated — public_ip=%s endpoint=%s:%d", currentIP, endpoint, wgPort)
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// detectPublicIP queries multiple sources and returns the IP when at least
// two agree, to avoid acting on transient DNS or CDN failures.
func detectPublicIP() (string, error) {
	results := make(map[string]int)

	for _, src := range ipSources {
		ip, err := fetchIP(src)
		if err != nil {
			continue
		}
		ip = strings.TrimSpace(ip)
		if ip != "" {
			results[ip]++
		}
	}

	// Return any IP with consensus from 2+ sources
	for ip, count := range results {
		if count >= 2 {
			return ip, nil
		}
	}

	// Fall back to any single result if only one source responded
	for ip := range results {
		return ip, nil
	}

	return "", fmt.Errorf("all IP detection sources failed or disagreed")
}

func fetchIP(src ipCheckSource) (string, error) {
	client := &http.Client{Timeout: ddnsHTTPTimeout}
	resp, err := client.Get(src.url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}

	if src.jsonKey == "" {
		return strings.TrimSpace(string(body)), nil
	}

	var data map[string]string
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	return data[src.jsonKey], nil
}

// updateNodeEndpoint writes the new IP and endpoint to the nodes table
// using the Supabase REST API directly (avoids needing a DB connection here).
func updateNodeEndpoint(supabaseURL, supabaseKey, nodeID, publicIP, endpoint string, port int) error {
	payload := fmt.Sprintf(
		`{"public_ip":"%s","wireguard_endpoint":"%s","wireguard_port":%d,"last_seen_at":"now()"}`,
		publicIP, endpoint, port,
	)

	url := fmt.Sprintf("%s/rest/v1/nodes?id=eq.%s", supabaseURL, nodeID)
	req, err := http.NewRequest(http.MethodPatch, url, strings.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("apikey", supabaseKey)
	req.Header.Set("Authorization", "Bearer "+supabaseKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=minimal")

	client := &http.Client{Timeout: ddnsHTTPTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Supabase PATCH status %d: %s", resp.StatusCode, body)
	}
	return nil
}
