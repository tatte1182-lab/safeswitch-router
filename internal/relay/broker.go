package relay

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// SessionKey uniquely identifies a relay session
type SessionKey struct {
	FamilyID string
	DeviceID string
}

// Session holds the two sides of a relay connection. Used only for
// the legacy WebSocket device path (parent app long-lived sockets).
// Child WireGuard traffic uses the UDP bridge + NodeRegistry path
// instead.
type Session struct {
	Key       SessionKey
	NodeConn  *Conn
	DevConn   *Conn
	CreatedAt time.Time
	mu        sync.Mutex
}

// Conn wraps a WebSocket connection with a send channel
type Conn struct {
	Send   chan []byte
	nodeID string
}

// CloudNotifier is the (optional) hook the broker calls to tell the
// cloud that a family has entered or exited fallback. The relay
// service injects an implementation that posts to a Supabase edge
// function. In tests / dev we leave it nil.
type CloudNotifier interface {
	NotifyFamilyFallback(ctx context.Context, familyID string, inFallback bool)
}

// Broker manages relay state on the VPS. It tracks:
//
//   - Long-lived WebSocket pubsub sessions (legacy device path)
//   - The NodeRegistry of connected home nodes (with health)
//   - The FallbackResolver for degraded-mode routing
//
// The UDP bridge holds a reference to the broker for the registry
// and fallback lookups, plus to fire one-shot cloud notifications
// when a family transitions in/out of fallback.
type Broker struct {
	mu sync.RWMutex

	// nodeConns is the WS-level node table. Kept around for the
	// existing UnregisterNode behaviour (closing Send channels on
	// disconnect). The authoritative health-aware view lives in
	// Registry.
	nodeConns map[string]*nodeEntry

	// sessions are legacy pubsub device sessions (parent app, etc).
	sessions map[SessionKey]*Session

	// Registry is the new health-aware index used by the UDP bridge.
	// Exposed (lowercase field, public-ish via accessor) so the
	// bridge can call PickHealthyNode directly without going through
	// the broker mutex.
	Registry *NodeRegistry

	// Fallback handles degraded-mode routing decisions and metrics.
	Fallback *FallbackResolver

	// notifier (optional) escalates fallback transitions to cloud.
	notifier CloudNotifier

	// udpBridge for delivering UDP relay replies back to child devices.
	udpBridge *UDPBridge
	udpMu     sync.RWMutex

	// cancelJanitor stops the staleness sweep goroutine on shutdown.
	cancelJanitor context.CancelFunc
}

type nodeEntry struct {
	NodeID   string
	FamilyID string
	Conn     *Conn
}

// NewBroker constructs a broker with default registry and a
// disabled-fallback resolver. Call SetFallbackEndpoint and
// SetCloudNotifier from the wiring layer before Start to enable
// the full degraded-mode behaviour.
func NewBroker() *Broker {
	b := &Broker{
		nodeConns: make(map[string]*nodeEntry),
		sessions:  make(map[SessionKey]*Session),
		Registry:  NewNodeRegistry(),
		Fallback:  NewFallbackResolver(""), // disabled until configured
	}
	b.startJanitor()
	go b.cleanup()
	return b
}

// SetFallbackEndpoint configures the local UDP terminator addr.
// Call from wiring before any traffic flows. Empty endpoint
// disables fallback (silent-drop, original behaviour).
func (b *Broker) SetFallbackEndpoint(endpoint string) {
	b.Fallback = NewFallbackResolver(endpoint)
}

// SetCloudNotifier wires the cloud-side notification hook. Optional.
func (b *Broker) SetCloudNotifier(n CloudNotifier) {
	b.mu.Lock()
	b.notifier = n
	b.mu.Unlock()
}

// SetUDPBridge registers the UDP bridge for delivering replies.
func (b *Broker) SetUDPBridge(bridge *UDPBridge) {
	b.udpMu.Lock()
	b.udpBridge = bridge
	b.udpMu.Unlock()
}

// notifyFallback fires a cloud event for a fallback transition.
// Called by the UDP bridge. Best-effort; failures are logged not
// returned because the data path doesn't care about cloud state.
func (b *Broker) notifyFallback(familyID string, inFallback bool) {
	b.mu.RLock()
	n := b.notifier
	b.mu.RUnlock()
	if n == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n.NotifyFamilyFallback(ctx, familyID, inFallback)
}

// RegisterNode is called when a home node connects via WebSocket.
// Adds to both the legacy nodeConns map (for compat) and the
// health-aware Registry (for routing).
func (b *Broker) RegisterNode(nodeID, familyID string, conn *Conn) {
	b.mu.Lock()
	b.nodeConns[nodeID] = &nodeEntry{
		NodeID:   nodeID,
		FamilyID: familyID,
		Conn:     conn,
	}
	b.mu.Unlock()

	// TODO: load preference from cloud-pushed routing config. Until
	// then assume primary; secondary nodes get demoted via SetPreference
	// once we wire up the cloud channel.
	b.Registry.Add(&NodeHealth{
		NodeID:   nodeID,
		FamilyID: familyID,
		Conn:     conn,
		Pref:     PrefPrimary,
	})

	log.Printf("[relay] node registered: %s (family %s)", nodeID, familyID)
}

// UnregisterNode is called when a home node disconnects.
// Removes from both indexes and tears down any pubsub sessions
// rooted on this node.
func (b *Broker) UnregisterNode(nodeID string) {
	b.Registry.Remove(nodeID)

	b.mu.Lock()
	delete(b.nodeConns, nodeID)
	for key, sess := range b.sessions {
		if sess.NodeConn != nil && sess.NodeConn.nodeID == nodeID {
			close(sess.NodeConn.Send)
			if sess.DevConn != nil {
				close(sess.DevConn.Send)
			}
			delete(b.sessions, key)
		}
	}
	b.mu.Unlock()
	log.Printf("[relay] node unregistered: %s", nodeID)
}

// TouchNode bumps the LastSeen timestamp for a node. Called by the
// handler on every received frame (data or pong).
func (b *Broker) TouchNode(nodeID string) {
	b.Registry.Touch(nodeID)
}

// RegisterDevice is unchanged from the original: legacy WebSocket
// device path. Child WG traffic does not go through this.
func (b *Broker) RegisterDevice(familyID, deviceID string, devConn *Conn) (*Session, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var entry *nodeEntry
	for _, e := range b.nodeConns {
		if e.FamilyID == familyID {
			entry = e
			break
		}
	}
	if entry == nil {
		return nil, fmt.Errorf("no home node online for family %s", familyID)
	}

	key := SessionKey{FamilyID: familyID, DeviceID: deviceID}
	sess := &Session{
		Key:       key,
		NodeConn:  entry.Conn,
		DevConn:   devConn,
		CreatedAt: time.Now(),
	}
	b.sessions[key] = sess

	log.Printf("[relay] session created: device=%s family=%s node=%s", deviceID, familyID, entry.NodeID)
	return sess, nil
}

// UnregisterDevice tears down a legacy device session.
func (b *Broker) UnregisterDevice(familyID, deviceID string) {
	b.mu.Lock()
	key := SessionKey{FamilyID: familyID, DeviceID: deviceID}
	if sess, ok := b.sessions[key]; ok {
		sess.mu.Lock()
		if sess.DevConn != nil {
			close(sess.DevConn.Send)
			sess.DevConn = nil
		}
		sess.mu.Unlock()
		delete(b.sessions, key)
	}
	b.mu.Unlock()
	log.Printf("[relay] device unregistered: %s (family %s)", deviceID, familyID)
}

// ForwardToNode sends a packet from device → node (legacy pubsub).
func (b *Broker) ForwardToNode(familyID, deviceID string, pkt []byte) {
	b.mu.RLock()
	key := SessionKey{FamilyID: familyID, DeviceID: deviceID}
	sess, ok := b.sessions[key]
	b.mu.RUnlock()
	if !ok || sess.NodeConn == nil {
		return
	}
	select {
	case sess.NodeConn.Send <- pkt:
	default:
		log.Printf("[relay] node send buffer full, dropping packet for device %s", deviceID)
	}
}

// ForwardToDevice sends a packet from node → device. Tries the
// legacy WS pubsub session first, then routes through the UDP
// bridge for WireGuard relay clients.
//
// Unchanged from the original — the home-node-happy path was already
// working. The bridge handles fallback replies on its own loop.
func (b *Broker) ForwardToDevice(familyID, deviceID string, pkt []byte) {
	b.mu.RLock()
	key := SessionKey{FamilyID: familyID, DeviceID: deviceID}
	sess, ok := b.sessions[key]
	b.mu.RUnlock()

	if ok && sess.DevConn != nil {
		select {
		case sess.DevConn.Send <- pkt:
		default:
			log.Printf("[relay] device send buffer full for %s", deviceID)
		}
		return
	}

	b.udpMu.RLock()
	bridge := b.udpBridge
	b.udpMu.RUnlock()

	if bridge != nil && len(pkt) >= 3 {
		devIDLen := int((uint16(pkt[1]) << 8) | uint16(pkt[2]))
		if len(pkt) >= 3+devIDLen {
			payload := pkt[3+devIDLen:]
			bridge.DeliverToClient(deviceID, payload)
		}
	}
}

// startJanitor runs a background sweep that fires fallback for
// families whose nodes have all gone stale, even if no traffic is
// flowing. Without this, a family with no active children would
// stay marked "healthy" forever after their home node silently dies.
func (b *Broker) startJanitor() {
	ctx, cancel := context.WithCancel(context.Background())
	b.cancelJanitor = cancel

	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.sweepStaleFamilies()
			}
		}
	}()
}

// sweepStaleFamilies walks every family with at least one node and
// updates fallback state. Called from the janitor; safe to call
// concurrently with the bridge's hot path because all state is in
// the registry/fallback (their own locks).
func (b *Broker) sweepStaleFamilies() {
	// Collect family IDs from current node table. Snapshot under
	// read lock then release before calling into registry/fallback
	// to avoid lock ordering issues.
	b.mu.RLock()
	families := make(map[string]struct{}, len(b.nodeConns))
	for _, e := range b.nodeConns {
		families[e.FamilyID] = struct{}{}
	}
	b.mu.RUnlock()

	for fam := range families {
		status := b.Registry.Status(fam)
		if status.HealthyCount == 0 && status.HasFallback {
			if b.Fallback.EnterFallback(fam) {
				log.Printf("[relay] janitor: family %s entering fallback (sweep)", fam)
				go b.notifyFallback(fam, true)
			}
		}
		if status.HealthyCount > 0 {
			if b.Fallback.ExitFallback(fam) {
				log.Printf("[relay] janitor: family %s recovered (sweep)", fam)
				go b.notifyFallback(fam, false)
			}
		}
	}
}

// cleanup periodically removes stale legacy sessions.
// Unchanged from the original.
func (b *Broker) cleanup() {
	ticker := time.NewTicker(2 * time.Minute)
	for range ticker.C {
		b.mu.Lock()
		for key, sess := range b.sessions {
			if time.Since(sess.CreatedAt) > 10*time.Minute && sess.DevConn == nil {
				delete(b.sessions, key)
			}
		}
		b.mu.Unlock()
	}
}

// Shutdown stops the janitor goroutine. Optional — process exit
// would clean up anyway, but tests like a clean teardown.
func (b *Broker) Shutdown() {
	if b.cancelJanitor != nil {
		b.cancelJanitor()
	}
}