package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// UDPBridge listens on UDP :51820 on the VPS and bridges WireGuard packets
// to/from the home node via the existing WebSocket relay session.
//
// Traffic flow (relay path):
//   Child WireGuard → UDP 51820 → VPS UDPBridge
//   UDPBridge → WebSocket frame → Home node relay client
//   Home node relay client → UDP → wg0 (127.0.0.1:51820)
//   Response: wg0 → relay client → WebSocket → UDPBridge → Child UDP
type UDPBridge struct {
	listenAddr string
	familyID   string
	broker     *Broker

	conn *net.UDPConn
	// clientAddrs maps device tag → UDP addr for sending replies back
	clientAddrs map[string]*net.UDPAddr
}

func NewUDPBridge(listenAddr, familyID string, broker *Broker) *UDPBridge {
	return &UDPBridge{
		listenAddr:  listenAddr,
		familyID:    familyID,
		broker:      broker,
		clientAddrs: make(map[string]*net.UDPAddr),
	}
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

	// Register this bridge with the broker so the home node relay client
	// can deliver reply packets back to child devices.
	b.broker.SetUDPBridge(b)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	go b.readLoop(ctx)
	fmt.Printf("[relay-udp-bridge] listening on %s\n", b.listenAddr)
	return nil
}

func (b *UDPBridge) Stop(ctx context.Context) error {
	b.broker.SetUDPBridge(nil)
	if b.conn != nil {
		return b.conn.Close()
	}
	return nil
}

// readLoop reads UDP packets from child WireGuard and forwards to home node via WebSocket.
func (b *UDPBridge) readLoop(ctx context.Context) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		b.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, clientAddr, err := b.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("[relay-udp-bridge] read error: %v\n", err)
			return
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		deviceTag := clientAddr.String()
		b.clientAddrs[deviceTag] = clientAddr

		// Find home node conn for this family
		b.broker.mu.RLock()
		var nodeConn *Conn
		for _, entry := range b.broker.nodeConns {
			if entry.FamilyID == b.familyID {
				nodeConn = entry.Conn
				break
			}
		}
		b.broker.mu.RUnlock()

		if nodeConn == nil {
			// No home node connected — silently drop
			continue
		}

		// Wrap and forward to home node over WebSocket
		frame := wrapFrame(deviceTag, payload)
		select {
		case nodeConn.Send <- frame:
		default:
			fmt.Printf("[relay-udp-bridge] node send buffer full, dropping packet\n")
		}
	}
}

// DeliverToClient sends a reply packet from the home node back to the child device.
// Called by the broker when it receives a frame from the home node tagged with a UDP device addr.
func (b *UDPBridge) DeliverToClient(deviceTag string, payload []byte) {
	addr, ok := b.clientAddrs[deviceTag]
	if !ok {
		// Try parsing the tag as a UDP addr directly
		parsed, err := net.ResolveUDPAddr("udp4", deviceTag)
		if err != nil {
			return
		}
		addr = parsed
	}
	if b.conn != nil {
		b.conn.WriteToUDP(payload, addr)
	}
}

// wrapUDPFrame is an alias — uses the same frame format as the WebSocket relay.
// [0x01][2-byte tag len][tag bytes][payload]
func wrapUDPFrame(deviceTag string, payload []byte) []byte {
	tagBytes := []byte(deviceTag)
	frame := make([]byte, 1+2+len(tagBytes)+len(payload))
	frame[0] = frameTypeData
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(tagBytes)))
	copy(frame[3:], tagBytes)
	copy(frame[3+len(tagBytes):], payload)
	return frame
}
