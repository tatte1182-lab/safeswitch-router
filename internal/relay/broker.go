package relay

import (
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

// Session holds the two sides of a relay connection
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

// Broker manages all relay sessions
type Broker struct {
	mu sync.RWMutex

	// nodeConns: nodeID -> Conn (home nodes waiting for devices)
	nodeConns map[string]*nodeEntry

	// pending device sessions waiting for a node
	sessions map[SessionKey]*Session

	// udpBridge for delivering UDP relay replies back to child devices
	udpBridge *UDPBridge
	udpMu     sync.RWMutex
}

type nodeEntry struct {
	NodeID   string
	FamilyID string
	Conn     *Conn
}

func NewBroker() *Broker {
	b := &Broker{
		nodeConns: make(map[string]*nodeEntry),
		sessions:  make(map[SessionKey]*Session),
	}
	go b.cleanup()
	return b
}

// SetUDPBridge registers the UDP bridge for delivering replies to child devices.
func (b *Broker) SetUDPBridge(bridge *UDPBridge) {
	b.udpMu.Lock()
	b.udpBridge = bridge
	b.udpMu.Unlock()
}

// RegisterNode called when a home node connects via WebSocket
func (b *Broker) RegisterNode(nodeID, familyID string, conn *Conn) {
	b.mu.Lock()
	b.nodeConns[nodeID] = &nodeEntry{
		NodeID:   nodeID,
		FamilyID: familyID,
		Conn:     conn,
	}
	b.mu.Unlock()
	log.Printf("[relay] node registered: %s (family %s)", nodeID, familyID)
}

// UnregisterNode called when a home node disconnects
func (b *Broker) UnregisterNode(nodeID string) {
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

// RegisterDevice called when a child device connects via WebSocket
func (b *Broker) RegisterDevice(familyID, deviceID string, devConn *Conn) (*Session, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var nodeEntry *nodeEntry
	for _, entry := range b.nodeConns {
		if entry.FamilyID == familyID {
			nodeEntry = entry
			break
		}
	}
	if nodeEntry == nil {
		return nil, fmt.Errorf("no home node online for family %s", familyID)
	}

	key := SessionKey{FamilyID: familyID, DeviceID: deviceID}
	sess := &Session{
		Key:       key,
		NodeConn:  nodeEntry.Conn,
		DevConn:   devConn,
		CreatedAt: time.Now(),
	}
	b.sessions[key] = sess

	log.Printf("[relay] session created: device=%s family=%s node=%s", deviceID, familyID, nodeEntry.NodeID)
	return sess, nil
}

// UnregisterDevice tears down a device session
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

// ForwardToNode sends a packet from device → node
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

// ForwardToDevice sends a packet from node → device (WebSocket device sessions).
// Also routes to UDP bridge for WireGuard UDP relay clients.
func (b *Broker) ForwardToDevice(familyID, deviceID string, pkt []byte) {
	// Try WebSocket device session first
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

	// No WebSocket session — try UDP bridge (WireGuard relay path)
	// deviceID in this context is the client UDP addr string e.g. "1.2.3.4:12345"
	b.udpMu.RLock()
	bridge := b.udpBridge
	b.udpMu.RUnlock()

	if bridge != nil {
		// Extract payload from frame (strip header)
		if len(pkt) >= 3 {
			devIDLen := int((uint16(pkt[1]) << 8) | uint16(pkt[2]))
			if len(pkt) >= 3+devIDLen {
				payload := pkt[3+devIDLen:]
				bridge.DeliverToClient(deviceID, payload)
			}
		}
	}
}

// cleanup periodically removes stale sessions
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
