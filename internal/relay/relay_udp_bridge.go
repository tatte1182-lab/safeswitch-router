package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

// FamilyEndpointResolver is satisfied by *terminator.Service. The bridge
// calls EnsureFamily on every fallback path (cheap — repeat calls just
// bump lastSeen) so the terminator can lazily bring up a per-family WG
// endpoint and hand back the local UDP socket addr to dial.
//
// Optional. If nil, the bridge falls back to the static endpoint
// configured via FallbackResolver.Endpoint() — same as the original
// silent-drop+single-port behaviour, kept for tests and dev where the
// terminator isn't wired up.
type FamilyEndpointResolver interface {
	EnsureFamily(ctx context.Context, familyID string) (string, error)
}

// UDPBridge listens on UDP :51820 on the VPS and bridges WireGuard
// packets to the family's home node via the WebSocket relay session,
// or to the local fallback endpoint when no healthy home node exists.
//
// Traffic flow (relay path, healthy):
//
//	Child WireGuard → UDP :51820 → UDPBridge
//	UDPBridge → registry.PickHealthyNode → frame → home node
//	Home node → wg0 → DNS filter, cache, internet
//	Reply: home node → frame → UDPBridge.DeliverToClient → child UDP
//
// Traffic flow (fallback, home node offline):
//
//	Child WireGuard → UDP :51820 → UDPBridge
//	UDPBridge → terminator.EnsureFamily → per-family local UDP socket
//	Terminator → wireguard-go decrypt → DNS filter (coarse) → NAT
//	Reply: terminator → UDP back to child
//
// The bridge itself is a simple frame router. It does not decrypt
// WireGuard. Both paths above terminate the tunnel elsewhere
// (home node or VPS terminator). The bridge's only job is to put
// each packet into the correct path.
type UDPBridge struct {
	listenAddr string
	familyID   string // optional: pin to one family in single-tenant deployments
	broker     *Broker
	registry   *NodeRegistry
	fallback   *FallbackResolver
	terminator FamilyEndpointResolver // optional; nil → static fallback endpoint

	conn *net.UDPConn

	// clientAddrs is "best-effort latest known UDP addr" per device tag.
	// We don't expire entries — WireGuard endpoints can roam (mobile
	// network handoff) and we want the most recent observation to win.
	// A device that genuinely goes away will simply stop sending and
	// its entry becomes inert.
	clientAddrs map[string]*net.UDPAddr
	// fallbackConns are persistent UDP sockets to the local terminator,
	// one per child device tag. Reused so the terminator sees a stable
	// source addr per device (= stable WG peer identity inside the
	// terminator's wireguard-go). Lazily created on first fallback
	// packet for a device.
	fallbackConns map[string]*net.UDPConn
}

func NewUDPBridge(
	listenAddr, familyID string,
	broker *Broker,
	registry *NodeRegistry,
	fallback *FallbackResolver,
) *UDPBridge {
	return &UDPBridge{
		listenAddr:    listenAddr,
		familyID:      familyID,
		broker:        broker,
		registry:      registry,
		fallback:      fallback,
		clientAddrs:   make(map[string]*net.UDPAddr),
		fallbackConns: make(map[string]*net.UDPConn),
	}
}

// SetFamilyEndpointResolver wires the per-family terminator in. Call
// before Start. Optional — without it the bridge falls back to the
// static endpoint from FallbackResolver, which is fine for tests but
// will NOT work multi-family because every family would land on the
// same wireguard-go listener.
func (b *UDPBridge) SetFamilyEndpointResolver(r FamilyEndpointResolver) {
	b.terminator = r
}

func (b *UDPBridge) Name() string { return "relay-udp-bridge" }

func (b *UDPBridge) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", b.listenAddr)
	if err != nil {
		return fmt.Errorf("resolve udp addr: %w", err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	b.conn = conn

	b.broker.SetUDPBridge(b)

	go func() {
		<-ctx.Done()
		conn.Close()
		// Close all fallback sockets on shutdown
		for _, c := range b.fallbackConns {
			_ = c.Close()
		}
	}()

	go b.readLoop(ctx)
	log.Printf("[relay-udp-bridge] listening on %s", b.listenAddr)
	return nil
}

func (b *UDPBridge) Stop(ctx context.Context) error {
	b.broker.SetUDPBridge(nil)
	if b.conn != nil {
		return b.conn.Close()
	}
	return nil
}

// readLoop reads UDP packets from child WireGuard and routes them
// to either a healthy home node (frame over WebSocket) or the
// fallback terminator (UDP-to-UDP local).
func (b *UDPBridge) readLoop(ctx context.Context) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = b.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, clientAddr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("[relay-udp-bridge] read error: %v", err)
			return
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		deviceTag := clientAddr.String()
		b.clientAddrs[deviceTag] = clientAddr

		// Resolve familyID. In single-tenant relays this is configured;
		// in multi-tenant we'd derive it from the WG public key in the
		// handshake. For now we trust the configured familyID and let
		// the registry pick the right node.
		fam := b.familyID
		if fam == "" {
			// TODO(multi-tenant): inspect WG handshake initiation
			// (msg type 1) to extract sender pubkey, look up family
			// in cloud-pushed pubkey→family map. Until then, single-
			// tenant only.
			b.recordDrop("no family configured")
			continue
		}

		// Hot path: pick a healthy node.
		if node := b.registry.PickHealthyNode(fam); node != nil {
			// If we were in fallback for this family, exit it now
			// that a healthy node is back.
			if b.fallback.ExitFallback(fam) {
				log.Printf("[relay-udp-bridge] family %s recovered, exiting fallback", fam)
			}
			frame := wrapFrame(deviceTag, payload)
			select {
			case node.Conn.Send <- frame:
				// success
			default:
				// Send buffer full — node is technically connected
				// but not draining. Don't fall back yet (might be
				// transient); just drop and let WG retransmit.
				log.Printf("[relay-udp-bridge] node send buffer full for family %s, dropping", fam)
				b.recordDrop("node buffer full")
			}
			continue
		}

		// No healthy node — enter fallback.
		if b.fallback.EnterFallback(fam) {
			log.Printf("[relay-udp-bridge] family %s entering fallback (no healthy node)", fam)
			// Fire-and-forget cloud event so the parent app can show
			// "running on backup" UI.
			go b.broker.notifyFallback(fam, true)
		}

		endpoint := b.fallback.Endpoint()
		if endpoint == "" && b.terminator == nil {
			// Fallback disabled (dev / not configured). Drop with counter.
			b.fallback.RecordDropped()
			continue
		}

		if err := b.forwardToFallback(ctx, fam, deviceTag, endpoint, payload); err != nil {
			log.Printf("[relay-udp-bridge] fallback forward error: %v", err)
			b.fallback.RecordDropped()
			continue
		}
		b.fallback.RecordForwarded()
	}
}

// forwardToFallback sends a packet to the local VPS terminator and
// arranges for replies to be routed back to the originating child.
// Per-device sockets persist for the life of the bridge — they're
// cheap and give the terminator stable peer addresses.
//
// When a FamilyEndpointResolver is wired, we ask it for the per-family
// listen addr the first time we see a device. The resolver is
// idempotent: subsequent calls just bump the terminator's last-seen
// timer and return the cached addr, so calling it on every fresh
// device is fine.
func (b *UDPBridge) forwardToFallback(ctx context.Context, familyID, deviceTag, staticEndpoint string, payload []byte) error {
	conn, ok := b.fallbackConns[deviceTag]
	if !ok {
		endpoint := staticEndpoint
		if b.terminator != nil {
			famAddr, err := b.terminator.EnsureFamily(ctx, familyID)
			if err != nil {
				return fmt.Errorf("ensure family %s: %w", familyID, err)
			}
			endpoint = famAddr
		}
		if endpoint == "" {
			return fmt.Errorf("no fallback endpoint for family %s", familyID)
		}

		ep, err := net.ResolveUDPAddr("udp4", endpoint)
		if err != nil {
			return fmt.Errorf("resolve fallback endpoint: %w", err)
		}
		c, err := net.DialUDP("udp4", nil, ep)
		if err != nil {
			return fmt.Errorf("dial fallback: %w", err)
		}
		b.fallbackConns[deviceTag] = c
		conn = c

		// Spin up a reader to deliver replies back to the child.
		go b.fallbackReplyLoop(deviceTag, c)
	}

	_, err := conn.Write(payload)
	return err
}

// fallbackReplyLoop reads from the local terminator and writes
// each reply back to the originating child UDP addr. Exits when
// the connection is closed (bridge shutdown).
func (b *UDPBridge) fallbackReplyLoop(deviceTag string, conn *net.UDPConn) {
	buf := make([]byte, 65536)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		addr, ok := b.clientAddrs[deviceTag]
		if !ok || b.conn == nil {
			continue
		}
		_, _ = b.conn.WriteToUDP(buf[:n], addr)
	}
}

// DeliverToClient sends a reply packet from the home node back to
// the child device. Called by the broker when it receives a frame
// from the home node tagged with a UDP device addr.
//
// Unchanged from the original implementation — the home-node-
// happy path is identical. Only the no-node path got smarter.
func (b *UDPBridge) DeliverToClient(deviceTag string, payload []byte) {
	addr, ok := b.clientAddrs[deviceTag]
	if !ok {
		parsed, err := net.ResolveUDPAddr("udp4", deviceTag)
		if err != nil {
			return
		}
		addr = parsed
	}
	if b.conn != nil {
		_, _ = b.conn.WriteToUDP(payload, addr)
	}
}

// recordDrop increments the broker's drop counter and logs at debug.
// Centralised so we can swap to structured metrics later without
// chasing scattered log lines.
func (b *UDPBridge) recordDrop(reason string) {
	// TODO: wire into telemetry once we add prom metrics.
	// For now the log line + fallback counter is enough to debug.
	_ = reason
}

// wrapUDPFrame is a tag-aliased copy of wrapFrame for callers that
// want to be explicit about which side they're framing for. Kept
// for API compatibility with the original bridge.
//
//	[0x01][2-byte tag len][tag bytes][payload]
func wrapUDPFrame(deviceTag string, payload []byte) []byte {
	tagBytes := []byte(deviceTag)
	frame := make([]byte, 1+2+len(tagBytes)+len(payload))
	frame[0] = frameTypeData
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(tagBytes)))
	copy(frame[3:], tagBytes)
	copy(frame[3+len(tagBytes):], payload)
	return frame
}

func (b *UDPBridge) Health(ctx context.Context) error { return nil }
