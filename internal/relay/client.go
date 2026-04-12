package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/websocket"
)

const (
	clientReconnectBase = 5 * time.Second
	clientReconnectMax  = 30 * time.Second
	clientPingInterval  = 15 * time.Second
	clientReadTimeout   = 40 * time.Second
)

// ClientService is a supervisor.Service that runs the relay client on the home node.
// It maintains a persistent outbound WebSocket connection to the VPS relay broker,
// bridging WireGuard UDP packets through when the direct path is unavailable.
type ClientService struct {
	brokerURL string // e.g. ws://209.38.30.90:8443/relay/node
	nodeID    string
	familyID  string
	token     string
	wgAddr    string // local WireGuard UDP addr e.g. "127.0.0.1:51820"

	cancel context.CancelFunc
}

func NewClientService(brokerURL, nodeID, familyID, token, wgAddr string) *ClientService {
	return &ClientService{
		brokerURL: brokerURL,
		nodeID:    nodeID,
		familyID:  familyID,
		token:     token,
		wgAddr:    wgAddr,
	}
}

func (s *ClientService) Name() string { return "relay-client" }

func (s *ClientService) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	go s.connectLoop(runCtx)
	fmt.Printf("[relay-client] started, broker=%s\n", s.brokerURL)
	return nil
}

func (s *ClientService) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *ClientService) Health(ctx context.Context) error { return nil }

func (s *ClientService) connectLoop(ctx context.Context) {
	delay := clientReconnectBase
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		err := s.runSession(ctx)
		if err != nil && ctx.Err() == nil {
			fmt.Printf("[relay-client] session ended (%v), reconnecting in %s\n", err, delay)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay *= 2
		if delay > clientReconnectMax {
			delay = clientReconnectMax
		}
	}
}

func (s *ClientService) runSession(ctx context.Context) error {
	url := fmt.Sprintf("%s?node_id=%s&family_id=%s&token=%s",
		s.brokerURL, s.nodeID, s.familyID, s.token)

	ws, err := websocket.Dial(url, "", "https://safeswitch-node")
	if err != nil {
		return fmt.Errorf("dial broker: %w", err)
	}
	defer ws.Close()
	fmt.Printf("[relay-client] connected to VPS broker\n")

	// Dial local WireGuard UDP socket
	wgAddr, err := net.ResolveUDPAddr("udp4", s.wgAddr)
	if err != nil {
		return fmt.Errorf("resolve wg addr: %w", err)
	}
	wgConn, err := net.DialUDP("udp4", nil, wgAddr)
	if err != nil {
		return fmt.Errorf("dial wg: %w", err)
	}
	defer wgConn.Close()

	send := make(chan []byte, 256)
	errCh := make(chan error, 2)

	// WireGuard → broker: read UDP packets from wg0, tag with source addr, forward
	go func() {
		buf := make([]byte, 65536)
		for {
			n, srcAddr, err := wgConn.ReadFromUDP(buf)
			if err != nil {
				errCh <- fmt.Errorf("wg read: %w", err)
				return
			}
			deviceTag := srcAddr.String()
			frame := wrapClientFrame(deviceTag, buf[:n])
			select {
			case send <- frame:
			default:
				fmt.Printf("[relay-client] send buffer full, dropping wg→broker packet\n")
			}
		}
	}()

	// Broker → WireGuard: read relay frames from WS, strip header, inject into wg0
	go func() {
		for {
			var pkt []byte
			ws.SetReadDeadline(time.Now().Add(clientReadTimeout))
			if err := websocket.Message.Receive(ws, &pkt); err != nil {
				errCh <- fmt.Errorf("ws read: %w", err)
				return
			}
			if len(pkt) == 0 {
				continue
			}
			switch pkt[0] {
			case frameTypePing:
				select {
				case send <- []byte{frameTypePong, 0, 0}:
				default:
				}
			case frameTypeData:
				if len(pkt) < 3 {
					continue
				}
				devIDLen := int(binary.BigEndian.Uint16(pkt[1:3]))
				if len(pkt) < 3+devIDLen {
					continue
				}
				payload := pkt[3+devIDLen:]
				if _, err := wgConn.Write(payload); err != nil {
					fmt.Printf("[relay-client] wg write error: %v\n", err)
				}
			}
		}
	}()

	// Writer + ping + context cancellation
	pingTicker := time.NewTicker(clientPingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		case <-pingTicker.C:
			select {
			case send <- []byte{frameTypePing, 0, 0}:
			default:
			}
		case frame := <-send:
			ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := websocket.Message.Send(ws, frame); err != nil {
				return fmt.Errorf("ws write: %w", err)
			}
		}
	}
}

func wrapClientFrame(deviceID string, payload []byte) []byte {
	idBytes := []byte(deviceID)
	frame := make([]byte, 1+2+len(idBytes)+len(payload))
	frame[0] = frameTypeData
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(idBytes)))
	copy(frame[3:], idBytes)
	copy(frame[3+len(idBytes):], payload)
	return frame
}
