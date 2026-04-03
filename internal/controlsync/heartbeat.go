package controlsync

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	contractevents "github.com/getsafeswitch/safeswitch-router/pkg/contract/events"
	"github.com/getsafeswitch/safeswitch-router/pkg/version"
)

// heartbeatPayload is the existing node-heartbeat Edge Function payload.
// Unchanged — do not remove.
type heartbeatPayload struct {
	NodeID              string  `json:"node_id"`
	NodeName            string  `json:"node_name"`
	Version             string  `json:"version"`
	UptimeSeconds       int64   `json:"uptime_seconds"`
	CPUPct              float64 `json:"cpu_pct"`
	MemPct              float64 `json:"mem_pct"`
	DiskPct             float64 `json:"disk_pct"`
	TunnelPeerCount     int     `json:"tunnel_peer_count"`
	ActiveBundleVersion string  `json:"active_bundle_version"`
	DeviceCount         int     `json:"device_count"`
}

// electionHeartbeat is the new format consumed by the election orchestrator.
type electionHeartbeat struct {
	SchemaVersion     int            `json:"schema_version"`
	FamilyID          string         `json:"family_id"`
	NodeID            string         `json:"node_id"`
	NodeEpoch         int64          `json:"node_epoch"`
	SentAt            string         `json:"sent_at"`
	AgentVersion      string         `json:"agent_version"`
	CapabilityHash    string         `json:"capability_hash"`
	RegistrationState string         `json:"registration_state"`
	Connectivity      ehConnectivity `json:"connectivity"`
	Health            ehHealth       `json:"health"`
	Power             ehPower        `json:"power"`
	RoleMetrics       ehRoleMetrics  `json:"role_metrics"`
	Observations      ehObservations `json:"observations"`
}

type ehConnectivity struct {
	CloudConnected bool    `json:"cloud_connected"`
	LANOK          bool    `json:"lan_ok"`
	InternetOK     bool    `json:"internet_ok"`
	RTTToCloudMS   int     `json:"rtt_to_cloud_ms"`
	PacketLossPct  float64 `json:"packet_loss_pct"`
}

type ehHealth struct {
	HealthScore   int     `json:"health_score"`
	CPUPct        float64 `json:"cpu_pct"`
	MemoryPct     float64 `json:"memory_pct"`
	DiskPct       float64 `json:"disk_pct"`
	ProcessOK     bool    `json:"process_ok"`
	DNSServiceOK  bool    `json:"dns_service_ok"`
	WireGuardOK   bool    `json:"wireguard_ok"`
	PolicyCacheOK bool    `json:"policy_cache_ok"`
	UptimeSeconds int64   `json:"uptime_seconds"`
}

type ehPower struct {
	PowerClass string `json:"power_class"`
	OnACPower  bool   `json:"on_ac_power"`
}

type ehRoleMetrics struct {
	DNS    ehDNSMetrics    `json:"dns"`
	Exit   ehExitMetrics   `json:"exit"`
	Policy ehPolicyMetrics `json:"policy"`
}

type ehDNSMetrics struct {
	Eligible     bool    `json:"eligible"`
	BindOK       bool    `json:"bind_ok"`
	LatencyMSP50 int     `json:"latency_ms_p50"`
	ErrorRatePct float64 `json:"error_rate_pct"`
}

type ehExitMetrics struct {
	Eligible bool `json:"eligible"`
	WGPeers  int  `json:"wg_peers"`
}

type ehPolicyMetrics struct {
	Eligible      bool   `json:"eligible"`
	CommandBusOK  bool   `json:"command_bus_ok"`
	PolicyVersion string `json:"policy_version"`
}

type ehObservations struct {
	PresenceDevicesSeen int `json:"presence_devices_seen"`
}

// upsertNodeHeartbeatRPC matches the upsert_node_heartbeat RPC signature.
type upsertNodeHeartbeatRPC struct {
	FamilyID       string            `json:"p_family_id"`
	NodeID         string            `json:"p_node_id"`
	SentAt         string            `json:"p_sent_at"`
	Heartbeat      electionHeartbeat `json:"p_heartbeat"`
	HealthScore    int               `json:"p_health_score"`
	CloudConnected bool              `json:"p_cloud_connected"`
	LANOK          bool              `json:"p_lan_ok"`
	InternetOK     bool              `json:"p_internet_ok"`
}

func (s *Service) runHeartbeat(ctx context.Context) {
	defer s.wg.Done()
	startedAt := time.Now()
	ticker := time.NewTicker(s.heartbeatEvery)
	defer ticker.Stop()
	s.sendHeartbeat(ctx, startedAt)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendHeartbeat(ctx, startedAt)
		}
	}
}

func (s *Service) sendHeartbeat(ctx context.Context, startedAt time.Time) {
	id := s.identity.Current()
	cpu, mem, disk := s.latestHealth(ctx)
	bundleVersion := "none"
	if b, err := s.policyRuntime.ActiveBundle(ctx); err == nil && b != nil {
		bundleVersion = b.Version
	}
	tunnelPeers := s.tunnelPeerCount(ctx)
	deviceCount := s.deviceCount(ctx)
	uptimeSeconds := int64(time.Since(startedAt).Seconds())

	// --- existing heartbeat (node-heartbeat Edge Function) — unchanged ---
	payload := heartbeatPayload{
		NodeID:              id.NodeID,
		NodeName:            id.NodeName,
		Version:             version.Version,
		UptimeSeconds:       uptimeSeconds,
		CPUPct:              cpu,
		MemPct:              mem,
		DiskPct:             disk,
		TunnelPeerCount:     tunnelPeers,
		ActiveBundleVersion: bundleVersion,
		DeviceCount:         deviceCount,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		s.logger.Printf("[controlsync] heartbeat marshal failed: %v", err)
		return
	}
	_, status, err := s.client.post(ctx, "/functions/v1/node-heartbeat", raw)
	if err != nil {
		s.logger.Printf("[controlsync] heartbeat failed status=%d: %v", status, err)
	} else {
		s.logger.Printf("[controlsync] heartbeat sent node_id=%s uptime=%ds bundle=%s peers=%d devices=%d",
			id.NodeID, uptimeSeconds, bundleVersion, tunnelPeers, deviceCount)
	}

	// --- election heartbeat (upsert_node_heartbeat RPC) ---
	s.sendElectionHeartbeat(ctx, id.NodeID, uptimeSeconds, cpu, mem, disk,
		tunnelPeers, deviceCount, bundleVersion)

	// --- sync WireGuard peer stats to device_tunnel_stats ---
	s.syncTunnelStats(ctx)

	_ = s.journal.Append(ctx, contractevents.Event{
		Type:     "node.heartbeat.sent",
		Severity: "info",
		Payload: map[string]any{
			"node_id": id.NodeID,
			"uptime":  uptimeSeconds,
			"bundle":  bundleVersion,
		},
	})
}

func (s *Service) sendElectionHeartbeat(
	ctx context.Context,
	nodeID string,
	uptimeSeconds int64,
	cpu, mem, disk float64,
	tunnelPeers, deviceCount int,
	bundleVersion string,
) {
	familyID := s.loadFamilyID(ctx)
	if familyID == "" {
		return
	}

	now := time.Now().UTC()

	healthScore := 100
	if cpu > 85 {
		healthScore -= 20
	} else if cpu > 70 {
		healthScore -= 10
	}
	if mem > 80 {
		healthScore -= 10
	}
	if disk > 90 {
		healthScore -= 10
	}
	if healthScore < 0 {
		healthScore = 0
	}

	dnsOK := s.isDNSAlive(ctx)
	wgOK := tunnelPeers >= 0
	policyOK := bundleVersion != "none" && bundleVersion != ""

	hb := electionHeartbeat{
		SchemaVersion:     1,
		FamilyID:          familyID,
		NodeID:            nodeID,
		NodeEpoch:         1,
		SentAt:            now.Format(time.RFC3339Nano),
		AgentVersion:      version.Version,
		CapabilityHash:    capabilityHash(nodeID),
		RegistrationState: "active",
		Connectivity: ehConnectivity{
			CloudConnected: true,
			LANOK:          true,
			InternetOK:     true,
			RTTToCloudMS:   0,
			PacketLossPct:  0,
		},
		Health: ehHealth{
			HealthScore:   healthScore,
			CPUPct:        cpu,
			MemoryPct:     mem,
			DiskPct:       disk,
			ProcessOK:     true,
			DNSServiceOK:  dnsOK,
			WireGuardOK:   wgOK,
			PolicyCacheOK: policyOK,
			UptimeSeconds: uptimeSeconds,
		},
		Power: ehPower{
			PowerClass: "mains",
			OnACPower:  true,
		},
		RoleMetrics: ehRoleMetrics{
			DNS: ehDNSMetrics{
				Eligible:     dnsOK,
				BindOK:       dnsOK,
				LatencyMSP50: 3,
				ErrorRatePct: 0,
			},
			Exit: ehExitMetrics{
				Eligible: wgOK,
				WGPeers:  tunnelPeers,
			},
			Policy: ehPolicyMetrics{
				Eligible:      policyOK,
				CommandBusOK:  true,
				PolicyVersion: bundleVersion,
			},
		},
		Observations: ehObservations{
			PresenceDevicesSeen: deviceCount,
		},
	}

	rpcPayload := upsertNodeHeartbeatRPC{
		FamilyID:       familyID,
		NodeID:         nodeID,
		SentAt:         now.Format(time.RFC3339Nano),
		Heartbeat:      hb,
		HealthScore:    healthScore,
		CloudConnected: true,
		LANOK:          true,
		InternetOK:     true,
	}

	raw, err := json.Marshal(rpcPayload)
	if err != nil {
		s.logger.Printf("[controlsync] election heartbeat marshal failed: %v", err)
		return
	}

	_, statusCode, err := s.client.postREST(ctx, "/rest/v1/rpc/upsert_node_heartbeat", raw)
	if err != nil || statusCode >= 400 {
		s.logger.Printf("[controlsync] election heartbeat RPC failed status=%d: %v", statusCode, err)
	} else {
		s.logger.Printf("[controlsync] election heartbeat ok node_id=%s health=%d dns=%v wg=%v",
			nodeID, healthScore, dnsOK, wgOK)
	}
}

func (s *Service) loadFamilyID(ctx context.Context) string {
	var familyID string
	_ = s.db.QueryRowContext(ctx,
		`SELECT value FROM tunnel_config WHERE key = 'family_id'`,
	).Scan(&familyID)
	return familyID
}

func capabilityHash(nodeID string) string {
	h := sha256.New()
	fmt.Fprintf(h, "nas:mains:ethernet:home_lan:v1:%s", nodeID)
	return fmt.Sprintf("sha256:%x", h.Sum(nil))[:24]
}

func (s *Service) isDNSAlive(ctx context.Context) bool {
	var ok int
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(dns_ok, 1) FROM health_snapshots ORDER BY id DESC LIMIT 1`,
	).Scan(&ok)
	if err != nil {
		return true
	}
	return ok == 1
}

func (s *Service) latestHealth(ctx context.Context) (cpu, mem, disk float64) {
	_ = s.db.QueryRowContext(ctx,
		`SELECT cpu_pct, mem_pct, disk_pct FROM health_snapshots ORDER BY id DESC LIMIT 1`,
	).Scan(&cpu, &mem, &disk)
	return
}

func (s *Service) tunnelPeerCount(ctx context.Context) int {
	var count int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM tunnel_peers`).Scan(&count)
	return count
}

func (s *Service) deviceCount(ctx context.Context) int {
	var count int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_registry`).Scan(&count)
	return count
}
