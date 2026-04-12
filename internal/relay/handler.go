package relay

import (
	"encoding/binary"
	"io"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/websocket"
)

const (
	// Frame header: [1 byte type][2 byte deviceID len][deviceID][payload]
	frameTypeData = 0x01
	frameTypePing = 0x02
	frameTypePong = 0x03

	sendBufSize  = 256
	maxFrameSize = 65536
	pingInterval = 15 * time.Second
	pingTimeout  = 10 * time.Second
)

// Handler holds HTTP handlers for relay endpoints
type Handler struct {
	broker    *Broker
	nodeToken string // shared secret nodes authenticate with
}

func NewHandler(broker *Broker, nodeToken string) *Handler {
	return &Handler{broker: broker, nodeToken: nodeToken}
}

// RegisterRoutes wires relay endpoints onto an existing mux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("/relay/node", websocket.Handler(h.handleNodeConn))
	mux.Handle("/relay/device", websocket.Handler(h.handleDeviceConn))
	mux.HandleFunc("/relay/status", h.handleStatus)
}

// handleNodeConn upgrades a home node connection
// Query params: node_id, family_id, token
func (h *Handler) handleNodeConn(ws *websocket.Conn) {
	q := ws.Request().URL.Query()
	nodeID := q.Get("node_id")
	familyID := q.Get("family_id")
	token := q.Get("token")

	if nodeID == "" || familyID == "" {
		ws.Close()
		return
	}
	if token != h.nodeToken {
		log.Printf("[relay] node auth failed: %s", nodeID)
		ws.Close()
		return
	}

	conn := &Conn{
		Send:   make(chan []byte, sendBufSize),
		nodeID: nodeID,
	}
	h.broker.RegisterNode(nodeID, familyID, conn)
	defer h.broker.UnregisterNode(nodeID)

	log.Printf("[relay] node connected: %s", nodeID)
	runRelayLoop(ws, conn, func(pkt []byte) {
		// Packet from node → decode deviceID header → forward to device
		if len(pkt) < 3 {
			return
		}
		devIDLen := int(binary.BigEndian.Uint16(pkt[1:3]))
		if len(pkt) < 3+devIDLen {
			return
		}
		deviceID := string(pkt[3 : 3+devIDLen])
		payload := pkt[3+devIDLen:]
		h.broker.ForwardToDevice(familyID, deviceID, wrapFrame(deviceID, payload))
	})
}

// handleDeviceConn upgrades a child device relay connection
// Query params: family_id, device_id, token (node token reused for now — swap for device JWT later)
func (h *Handler) handleDeviceConn(ws *websocket.Conn) {
	q := ws.Request().URL.Query()
	familyID := q.Get("family_id")
	deviceID := q.Get("device_id")
	token := q.Get("token")

	if familyID == "" || deviceID == "" || token == "" {
		ws.Close()
		return
	}
	// TODO: validate device JWT against Supabase — for now accept node token for testing
	if token != h.nodeToken {
		log.Printf("[relay] device auth failed: %s", deviceID)
		ws.Close()
		return
	}

	conn := &Conn{
		Send: make(chan []byte, sendBufSize),
	}
	sess, err := h.broker.RegisterDevice(familyID, deviceID, conn)
	if err != nil {
		log.Printf("[relay] no node for device %s: %v", deviceID, err)
		ws.Close()
		return
	}
	defer h.broker.UnregisterDevice(familyID, deviceID)
	_ = sess

	log.Printf("[relay] device connected: %s", deviceID)
	runRelayLoop(ws, conn, func(pkt []byte) {
		// Packet from device → strip frame header → forward to node with device tag
		if len(pkt) < 3 {
			return
		}
		devIDLen := int(binary.BigEndian.Uint16(pkt[1:3]))
		if len(pkt) < 3+devIDLen {
			return
		}
		payload := pkt[3+devIDLen:]
		h.broker.ForwardToNode(familyID, deviceID, wrapFrame(deviceID, payload))
	})
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","service":"safeswitch-relay"}`))
}

// runRelayLoop reads from ws, calls onRecv for each packet, and drains conn.Send back to ws
func runRelayLoop(ws *websocket.Conn, conn *Conn, onRecv func([]byte)) {
	ws.MaxPayloadBytes = maxFrameSize

	done := make(chan struct{})

	// Writer goroutine — drains Send channel to WebSocket
	go func() {
		defer close(done)
		for pkt := range conn.Send {
			ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := websocket.Message.Send(ws, pkt); err != nil {
				log.Printf("[relay] ws write error: %v", err)
				return
			}
		}
	}()

	// Ping goroutine
	go func() {
		ticker := time.NewTicker(pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				ping := []byte{frameTypePing, 0, 0}
				select {
				case conn.Send <- ping:
				default:
				}
			}
		}
	}()

	// Reader loop
	for {
		var pkt []byte
		ws.SetReadDeadline(time.Now().Add(pingInterval + pingTimeout))
		if err := websocket.Message.Receive(ws, &pkt); err != nil {
			if err != io.EOF {
				log.Printf("[relay] ws read error: %v", err)
			}
			break
		}
		if len(pkt) == 0 {
			continue
		}
		switch pkt[0] {
		case frameTypePing:
			pong := []byte{frameTypePong, 0, 0}
			select {
			case conn.Send <- pong:
			default:
			}
		case frameTypePong:
			// reset deadline handled by SetReadDeadline above
		case frameTypeData:
			onRecv(pkt)
		}
	}
	ws.Close()
}

// wrapFrame builds [type=0x01][2-byte devID len][devID][payload]
func wrapFrame(deviceID string, payload []byte) []byte {
	idBytes := []byte(deviceID)
	frame := make([]byte, 1+2+len(idBytes)+len(payload))
	frame[0] = frameTypeData
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(idBytes)))
	copy(frame[3:], idBytes)
	copy(frame[3+len(idBytes):], payload)
	return frame
}
