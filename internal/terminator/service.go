// Package terminator runs the VPS-side WireGuard endpoint used by
// the fallback path. When a family's home node is unreachable, the
// UDP bridge forwards their child WireGuard traffic here instead
// of silently dropping it.
//
// The terminator is intentionally a degraded mirror of the home
// node's data path:
//
//   - It terminates WireGuard via wireguard-go (userspace impl, no
//     kernel module needed — VPS portability matters more than the
//     ~5% throughput hit).
//   - DNS queries are intercepted and run through a family-level
//     blocklist mirrored from Supabase (the same blocklist the
//     home node would have applied locally).
//   - Non-DNS traffic is NAT'd straight out via the VPS's egress
//     interface. No caching, no compression, no per-child filter
//     granularity. That's the deal: customers stay online but lose
//     the home-node features until the home node comes back.
//
// One terminator process serves all families. Each family has its
// own wireguard-go device (cheap — they're userspace), keyed by
// family ID. Peers are loaded from the cloud heartbeat path on
// first fallback for that family and torn down when the family
// exits fallback for >5 minutes.
package terminator

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/dns"
)

// FamilyConfig is what the terminator needs to bring up a family's
// fallback WG endpoint. Pulled from Supabase via the cloud client
// when a family first enters fallback.
type FamilyConfig struct {
	FamilyID    string
	PrivateKey  string  // VPS-side terminator's WG private key for this family
	ListenPort  int     // bound port on 127.0.0.1 — bridge dials here
	Peers       []Peer  // child devices belonging to this family
	BlockedCats []string // categories the family blocks (adult, gambling, …)
}

// Peer is one child device known to the family. The bridge sees
// only WG packets, so the only identity that matters here is the
// public key + assigned tunnel IP.
type Peer struct {
	PublicKey  string // child's WG pubkey (base64)
	AllowedIPs []string // typically a single /32 in 10.99.x.y/32
}

// ConfigSource is how the terminator gets per-family configs from
// the cloud. The relay's controlsync client implements this.
type ConfigSource interface {
	FetchFamilyConfig(ctx context.Context, familyID string) (*FamilyConfig, error)
}

// Service is the supervised terminator. One per VPS process.
type Service struct {
	cfg          ConfigSource
	listenAddr   string // typically 127.0.0.1:51821
	blocklist    *dns.Blocklist
	egressIface  string // VPS public iface, e.g. "eth0" — used for NAT

	mu       sync.RWMutex
	families map[string]*familyEndpoint

	// idleTeardown closes a family's endpoint after this long with
	// no fallback traffic. 5 min is a balance between memory churn
	// (terminator endpoints are ~50KB each) and avoiding repeated
	// cold-start stalls when a flaky home node flaps.
	idleTeardown time.Duration

	cancel context.CancelFunc
}

// familyEndpoint is one running per-family terminator.
type familyEndpoint struct {
	cfg      *FamilyConfig
	device   *wgDevice         // wireguard-go wrapper, see wg_device.go
	conn     *net.UDPConn      // bridge ↔ terminator socket
	lastSeen time.Time
	cancel   context.CancelFunc
}

func NewService(cfg ConfigSource, listenAddr string, blocklist *dns.Blocklist, egressIface string) *Service {
	return &Service{
		cfg:          cfg,
		listenAddr:   listenAddr,
		blocklist:    blocklist,
		egressIface:  egressIface,
		families:     make(map[string]*familyEndpoint),
		idleTeardown: 5 * time.Minute,
	}
}

func (s *Service) Name() string { return "relay-terminator" }

// Start brings up the terminator's accept loop. The accept loop
// itself is trivial — it just demultiplexes incoming UDP packets
// to the right family endpoint based on destination port. The
// real work happens in each per-family goroutine.
func (s *Service) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	go s.idleSweeper(runCtx)

	log.Printf("[terminator] ready, listen base=%s", s.listenAddr)
	return nil
}

func (s *Service) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for fam, ep := range s.families {
		ep.cancel()
		_ = ep.conn.Close()
		_ = ep.device.Close()
		delete(s.families, fam)
	}
	return nil
}

func (s *Service) Health(ctx context.Context) error { return nil }

// EnsureFamily is called by the bridge (indirectly, via the broker)
// when a family enters fallback. It's idempotent — repeat calls for
// an already-running family are no-ops apart from bumping lastSeen.
//
// First call for a family fetches the config from the cloud, brings
// up a wireguard-go device, binds a UDP socket on the bridge-facing
// port, and starts the read loop. Subsequent fallback packets land
// on the existing endpoint without going through this function.
func (s *Service) EnsureFamily(ctx context.Context, familyID string) (string, error) {
	s.mu.Lock()
	if ep, ok := s.families[familyID]; ok {
		ep.lastSeen = time.Now()
		addr := ep.conn.LocalAddr().String()
		s.mu.Unlock()
		return addr, nil
	}
	s.mu.Unlock()

	cfg, err := s.cfg.FetchFamilyConfig(ctx, familyID)
	if err != nil {
		return "", fmt.Errorf("fetch family config: %w", err)
	}

	ep, err := s.bringUpFamily(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("bring up family %s: %w", familyID, err)
	}

	s.mu.Lock()
	// Race check — another goroutine may have brought up the same
	// family while we were fetching. If so, tear ours down and use
	// theirs.
	if existing, ok := s.families[familyID]; ok {
		s.mu.Unlock()
		ep.cancel()
		_ = ep.conn.Close()
		_ = ep.device.Close()
		return existing.conn.LocalAddr().String(), nil
	}
	s.families[familyID] = ep
	s.mu.Unlock()

	log.Printf("[terminator] family %s up on %s (%d peers)", familyID, ep.conn.LocalAddr(), len(cfg.Peers))
	return ep.conn.LocalAddr().String(), nil
}

func (s *Service) bringUpFamily(ctx context.Context, cfg *FamilyConfig) (*familyEndpoint, error) {
	// Bind the bridge-facing UDP socket. Port 0 = let the kernel
	// pick. We hand the actual addr back to the bridge so it knows
	// where to dial. cfg.ListenPort is advisory — we honour it if
	// non-zero, fall back to ephemeral otherwise.
	bindAddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: cfg.ListenPort,
	}
	conn, err := net.ListenUDP("udp4", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("bind bridge socket: %w", err)
	}

	dev, err := newWGDevice(cfg, s.blocklist, s.egressIface)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("init wg device: %w", err)
	}

	famCtx, cancel := context.WithCancel(ctx)
	ep := &familyEndpoint{
		cfg:      cfg,
		device:   dev,
		conn:     conn,
		lastSeen: time.Now(),
		cancel:   cancel,
	}

	// Bridge-side read loop: bridge → terminator
	go ep.readBridgeLoop(famCtx, dev)

	// Device-side read loop: terminator → bridge (replies)
	go ep.readDeviceLoop(famCtx, conn)

	return ep, nil
}

// readBridgeLoop pumps UDP packets from the bridge into the
// wireguard-go device. The device decrypts (or runs handshake),
// then either routes to the DNS filter (if it's a DNS query) or
// out to the internet via NAT.
func (ep *familyEndpoint) readBridgeLoop(ctx context.Context, dev *wgDevice) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = ep.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, src, err := ep.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("[terminator] bridge read err family=%s: %v", ep.cfg.FamilyID, err)
			return
		}

		ep.lastSeen = time.Now()

		// The src addr is the bridge's per-device socket. We track
		// it so the device-side read loop knows where to send replies.
		dev.RegisterClientAddr(src)

		// Hand the packet to wireguard-go for processing.
		if err := dev.HandleInbound(buf[:n]); err != nil {
			// Decrypt failures are normal during peer rekeys — log
			// at debug, not error. A flood of these would indicate
			// a bigger problem (e.g. wrong family config loaded).
			continue
		}
	}
}

// readDeviceLoop drains outbound packets from wireguard-go (replies
// the device wants to send back to the child) and writes them to
// the bridge socket. The bridge then forwards to the actual child
// UDP addr.
func (ep *familyEndpoint) readDeviceLoop(ctx context.Context, conn *net.UDPConn) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-ep.device.Outbound():
			addr := ep.device.LastClientAddr()
			if addr == nil {
				continue
			}
			_, _ = conn.WriteToUDP(pkt, addr)
		}
	}
}

// idleSweeper tears down family endpoints that haven't seen
// fallback traffic in idleTeardown. Cheap to recreate so we'd
// rather reclaim memory than keep stale endpoints around.
func (s *Service) idleSweeper(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for fam, ep := range s.families {
				if now.Sub(ep.lastSeen) > s.idleTeardown {
					ep.cancel()
					_ = ep.conn.Close()
					_ = ep.device.Close()
					delete(s.families, fam)
					log.Printf("[terminator] family %s torn down (idle)", fam)
				}
			}
			s.mu.Unlock()
		}
	}
}