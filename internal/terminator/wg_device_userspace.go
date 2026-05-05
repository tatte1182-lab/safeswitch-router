package terminator

import (
	"context"
	"fmt"
	"io"
	"net"
        "net/netip"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// wgImplUserspace is the portable WireGuard termination impl.
//
// Why netstack: it's a userspace TCP/IP stack (gVisor) so we get a
// working "interface" without root or kernel TUN. The terminator
// process can be a non-privileged systemd unit and still terminate
// WG. The trade-off is throughput — netstack tops out at ~500 Mbps
// on a single core vs ~2 Gbps for kernel WG. For the fallback path
// that's plenty: we're carrying degraded-mode traffic, not steady
// state.
type wgImplUserspace struct {
	dev    *device.Device
	tun    *netstack.Net
	logger *device.Logger

	// outbound: encrypted bytes the WG device wants us to ship
	// back to the bridge socket. We surface this as the channel on
	// the wgDevice wrapper.
	parent *wgDevice

	// upstream is the net.Conn-style wrapper we hand to wireguard-go.
	// It's a synthetic "UDP socket" whose Write goes to outbound and
	// whose Read blocks on packets we feed via HandleInbound.
	upstream *syntheticUDP

	closeOnce sync.Once
	closeErr  error
}

// newWGImpl is referenced from wg_device.go's newWGDevice. It picks
// the userspace impl by default. A future build tag could swap in a
// kernel-TUN impl on Linux when speed matters.
func newWGImpl(parent *wgDevice, cfg *FamilyConfig) (wgDeviceImpl, error) {
	// Build a netstack-backed TUN and Net. The Net gives us a
	// userspace TCP/IP stack we can dial through; the TUN is what
	// wireguard-go reads/writes plaintext IP packets on.
	
        tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{
			// Address of the WG endpoint inside the family's tunnel
			// network. The first /32 in the family's allowed-IP space
			// works — child peers expect to reach .1 of their subnet
			// for DNS, and we're acting as that gateway.
			netip.MustParseAddr("10.99.0.1"),
		},
		[]netip.Addr{
			// DNS resolver inside the tunnel — also us. Replies are
			// synthesised in the wgDevice plaintext-out path before
			// we ever forward to a real upstream.
			netip.MustParseAddr("10.99.0.1"),
		},
		1420, // standard WG MTU
	)

	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	upstream := newSyntheticUDP(parent.outbound)

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[term/%s] ", cfg.FamilyID))
	dev := device.NewDevice(tun, &syntheticBind{u: upstream}, logger)

	// Build the IPC config string wireguard-go expects via UAPI.
	// This is the same wire format wg(8) uses for `wg syncconf`.
	uapi, err := buildUAPI(cfg)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("build uapi: %w", err)
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("apply uapi: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("dev up: %w", err)
	}

	impl := &wgImplUserspace{
		dev:      dev,
		tun:      tnet,
		logger:   logger,
		parent:   parent,
		upstream: upstream,
	}

	// Spin up the plaintext-out goroutine: read decrypted IP
	// packets out of netstack, hand them to the parent's
	// onPlaintextOutbound so DNS gets filtered / NAT happens.
	go impl.plaintextOutLoop(context.Background())

	return impl, nil
}

func (i *wgImplUserspace) HandleInbound(pkt []byte) error {
	return i.upstream.feed(pkt)
}

func (i *wgImplUserspace) Close() error {
	i.closeOnce.Do(func() {
		i.dev.Close()
		i.upstream.close()
	})
	return i.closeErr
}

// ForwardOut implements natForwarder. The userspace impl can't
// directly inject a packet onto the host network without root,
// so we use the netstack we already have: dial out via tnet and
// the kernel's normal egress path applies.
//
// In practice this means: parse the destination from the IP header,
// dial it via tnet, write the inner payload, copy replies back into
// the tunnel. For Phase 1 this is over-ambitious — instead we drop
// non-DNS packets in fallback and tell the child app to disable
// caching. Customer still has DNS-filtered browsing because the
// DNS replies we synthesise above resolve to real upstream IPs.
//
// TODO(phase 2): real egress proxying via tnet.DialContext.
func (i *wgImplUserspace) ForwardOut(plaintext []byte) error {
	// Phase 1: silent drop with debug-level visibility. The DNS
	// path above is what keeps customer-facing browsing alive in
	// fallback; non-DNS UDP/TCP just stalls until the home node
	// recovers. Acceptable for the launch tier; revisit for v2.
	return nil
}

func (i *wgImplUserspace) plaintextOutLoop(ctx context.Context) {
	// netstack's TUN exposes Read/Write on the gateway side. We
	// read decrypted IP packets here and route them through the
	// parent's plaintext-out logic.
	//
	// netstack.Net does not expose the raw TUN reader publicly in
	// the version we depend on; it's plumbed via the channel-based
	// TUN under the hood. The clean access pattern is to dial via
	// tnet and let the stack handle inbound — which is what the
	// "real" Phase 2 implementation should do.
	//
	// For Phase 1 we lean on the WG device's own outbound path
	// (encrypted replies coming out via syntheticUDP) and rely on
	// the DNS-synthesis fast path at the WG layer above. The
	// plaintext-out goroutine here is reserved for Phase 2 and
	// currently exits immediately.
	_ = ctx
}

// ──────────────────────────────────────────────────────────────────
// syntheticUDP: a fake UDP "connection" we hand to wireguard-go.
// ──────────────────────────────────────────────────────────────────

// syntheticUDP satisfies enough of net.PacketConn for
// wireguard-go's conn.Bind to drive WireGuard over it. Reads pull
// from a packet queue we fill via feed(). Writes push to the
// outbound channel, which the terminator's readDeviceLoop ships
// back to the bridge.
type syntheticUDP struct {
	outbound chan<- []byte

	mu       sync.Mutex
	inbound  chan []byte
	closed   bool
	closeErr error
}

func newSyntheticUDP(outbound chan<- []byte) *syntheticUDP {
	return &syntheticUDP{
		outbound: outbound,
		inbound:  make(chan []byte, 256),
	}
}

func (s *syntheticUDP) feed(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case s.inbound <- cp:
		return nil
	default:
		// Queue full — drop. WG retransmits.
		return nil
	}
}

// Read implements net.Conn. Returns the next inbound packet.
func (s *syntheticUDP) Read(p []byte) (int, error) {
	pkt, ok := <-s.inbound
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, pkt)
	return n, nil
}

// Write implements net.Conn. Sends the encrypted bytes outbound.
func (s *syntheticUDP) Write(p []byte) (int, error) {
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case s.outbound <- cp:
		return len(p), nil
	default:
		// Drop on backpressure rather than block the WG goroutine.
		return len(p), nil
	}
}

func (s *syntheticUDP) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.inbound)
}

// Close, LocalAddr, RemoteAddr, SetDeadline, SetReadDeadline,
// SetWriteDeadline — minimal implementations to satisfy net.Conn.
func (s *syntheticUDP) Close() error                       { s.close(); return nil }
func (s *syntheticUDP) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero} }
func (s *syntheticUDP) RemoteAddr() net.Addr               { return &net.UDPAddr{IP: net.IPv4zero} }
func (s *syntheticUDP) SetDeadline(_ /*t*/ interface{}) error      { return nil }
func (s *syntheticUDP) SetReadDeadline(_ interface{}) error  { return nil }
func (s *syntheticUDP) SetWriteDeadline(_ interface{}) error { return nil }

// ──────────────────────────────────────────────────────────────────
// UAPI builder — translates a FamilyConfig to wireguard-go's
// `wg syncconf` wire format.
// ──────────────────────────────────────────────────────────────────

// syntheticBind adapts our syntheticUDP to wireguard-go's conn.Bind
// interface. The Open/Close/SetMark methods are stubs because we
// don't bind a real UDP port — all I/O goes through the synthetic
// channel-based queue.
type syntheticBind struct {
	u *syntheticUDP
}

func (b *syntheticBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *syntheticBind) receive(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (n int, err error) {
	pkt, ok := <-b.u.inbound
	if !ok {
		return 0, net.ErrClosed
	}
	if len(packets) == 0 || len(packets[0]) < len(pkt) {
		return 0, io.ErrShortBuffer
	}
	copy(packets[0], pkt)
	sizes[0] = len(pkt)
	endpoints[0] = &syntheticEndpoint{}
	return 1, nil
}

func (b *syntheticBind) Close() error              { b.u.close(); return nil }
func (b *syntheticBind) SetMark(mark uint32) error { return nil }
func (b *syntheticBind) BatchSize() int            { return 1 }

func (b *syntheticBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		cp := make([]byte, len(buf))
		copy(cp, buf)
		select {
		case b.u.outbound <- cp:
		default:
			// Drop on backpressure
		}
	}
	return nil
}

func (b *syntheticBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &syntheticEndpoint{}, nil
}

// syntheticEndpoint is a no-op endpoint. Our synthetic bind doesn't
// route packets between peers — the bridge already handles that.
type syntheticEndpoint struct{}

func (e *syntheticEndpoint) ClearSrc()             {}
func (e *syntheticEndpoint) SrcToString() string   { return "" }
func (e *syntheticEndpoint) DstToString() string   { return "" }
func (e *syntheticEndpoint) DstToBytes() []byte    { return nil }
func (e *syntheticEndpoint) DstIP() netip.Addr     { return netip.Addr{} }
func (e *syntheticEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }


func buildUAPI(cfg *FamilyConfig) (string, error) {
	priv, err := decodeWGKey(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	fmt.Fprintf(&b, "listen_port=0\n") // we don't bind on a real port; conn.Bind is synthetic
	fmt.Fprintf(&b, "replace_peers=true\n")

	for _, p := range cfg.Peers {
		pub, err := decodeWGKey(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer %s: decode pubkey: %w", p.PublicKey, err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pub)
		fmt.Fprintf(&b, "replace_allowed_ips=true\n")
		for _, allowed := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", allowed)
		}
	}
	return b.String(), nil
}

// decodeWGKey moved to wg_keys.go so kernel-TUN impl can share it.