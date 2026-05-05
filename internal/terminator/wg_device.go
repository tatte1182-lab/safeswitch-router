package terminator

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/getsafeswitch/safeswitch-router/internal/dns"
)

// wgDevice wraps a wireguard-go userspace device for one family.
//
// Why a wrapper at all: the public wireguard-go API is geared for
// "I have a TUN device, plumb it together with WG." For the
// terminator we want something subtler — the decrypted plaintext
// packets need to go through our DNS filter and NAT path, not into
// a TUN. So we feed wireguard-go a fake TUN that routes plaintext
// packets through user code instead of into the kernel.
//
// This file is the abstraction boundary. Real implementation in
// wg_device_linux.go (kernel TUN) and wg_device_userspace.go
// (gVisor netstack) — pick at build time. The userspace path is
// the default; the linux/TUN path is an optimisation for high-
// throughput VPSes.
type wgDevice struct {
	familyID  string
	blocklist *dns.Blocklist
	categories []string
	egressIface string

	// outbound is plaintext packets the device wants to send back
	// to the client (responses from internet, DNS replies, …).
	// Encrypted by the device first, then dropped on this channel
	// for the readDeviceLoop to ship over the bridge.
	outbound chan []byte

	mu             sync.Mutex
	lastClientAddr *net.UDPAddr

	// closed guards Close idempotency. Calling Close twice on a
	// wireguard-go device panics, which is unfortunate.
	closed bool

	impl wgDeviceImpl // platform-specific implementation
}

// wgDeviceImpl is what the platform layer fills in.
//
// HandleInbound: encrypted bytes from the bridge → device
//   decrypts → emits plaintext packets via the outbound channel
//   (for replies) or forwards via NAT (for outbound child traffic).
//
// Close: tears down the wireguard-go device, the fake TUN, and
//   any goroutines the impl started.
type wgDeviceImpl interface {
	HandleInbound(pkt []byte) error
	Close() error
}

func newWGDevice(cfg *FamilyConfig, bl *dns.Blocklist, egressIface string) (*wgDevice, error) {
	if cfg.PrivateKey == "" {
		return nil, errors.New("terminator: family config missing private key")
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("terminator: family config has zero peers")
	}

	dev := &wgDevice{
		familyID:    cfg.FamilyID,
		blocklist:   bl,
		categories:  cfg.BlockedCats,
		egressIface: egressIface,
		outbound:    make(chan []byte, 256),
	}

	impl, err := newWGImpl(dev, cfg)
	if err != nil {
		return nil, fmt.Errorf("init wg impl: %w", err)
	}
	dev.impl = impl

	return dev, nil
}

func (d *wgDevice) HandleInbound(pkt []byte) error {
	if d.closed {
		return errors.New("terminator: device closed")
	}
	return d.impl.HandleInbound(pkt)
}

// Outbound returns the channel that yields encrypted packets the
// device wants to send back to the client. The terminator's
// readDeviceLoop drains this and writes to the bridge socket.
func (d *wgDevice) Outbound() <-chan []byte { return d.outbound }

// RegisterClientAddr remembers the bridge's per-device socket addr
// so we know where to send replies. WG roams, so the latest
// observation wins. Cheap; no locking needed for atomic-ish
// pointer updates on amd64/arm64, but we lock for portability.
func (d *wgDevice) RegisterClientAddr(addr *net.UDPAddr) {
	d.mu.Lock()
	d.lastClientAddr = addr
	d.mu.Unlock()
}

func (d *wgDevice) LastClientAddr() *net.UDPAddr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastClientAddr
}

func (d *wgDevice) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()

	if d.impl != nil {
		return d.impl.Close()
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────
// Plaintext packet handling — called by the impl after decryption.
// ──────────────────────────────────────────────────────────────────

// onPlaintextOutbound is called by the impl when the device has
// decrypted a packet from the child that wants to go to the
// internet. We:
//   1. Inspect — if it's a DNS query (UDP/53), run it through
//      the blocklist and synthesise a reply if blocked.
//   2. Otherwise, forward via the NAT path on the egress iface.
//
// Returning a non-nil byte slice means "send this back to the
// client as a reply" (e.g. the synthesised DNS NXDOMAIN). Nil
// means "forwarded normally, no reply yet."
func (d *wgDevice) onPlaintextOutbound(plaintext []byte) ([]byte, error) {
	// Cheap protocol probe: IPv4 + UDP + dst port 53?
	if isDNSQuery(plaintext) {
		domain, err := extractDNSQName(plaintext)
		if err == nil && domain != "" {
			normalized := strings.TrimSuffix(strings.ToLower(domain), ".")
			if d.blocklist.IsBlockedForCategories(normalized, d.categories) {
				// Synthesise an NXDOMAIN reply. The impl will encrypt
				// this and emit on outbound for us.
				reply, err := buildBlockedDNSReply(plaintext)
				if err != nil {
					return nil, err
				}
				return reply, nil
			}
		}
	}

	// Not a DNS query, or DNS query that's allowed. Forward via NAT.
	return nil, d.forwardViaNAT(plaintext)
}

// forwardViaNAT is the egress path. For Phase 1 we lean on the
// kernel: the terminator process runs as a normal Linux user and
// the OS rewrites the source addr via a SNAT rule installed at
// startup (see deploy/terminator-nat.sh).
//
// We don't reimplement NAT here; we just write the packet to a
// raw socket bound to the egress iface and let the kernel handle
// the rest. If we wanted full per-family egress accounting we'd
// need our own NAT table, but Phase 1 ships without that.
func (d *wgDevice) forwardViaNAT(plaintext []byte) error {
	// Implementation lives in wg_device_linux.go because raw
	// sockets are platform-specific. Stub here for tests.
	return d.impl.(natForwarder).ForwardOut(plaintext)
}

type natForwarder interface {
	ForwardOut(plaintext []byte) error
}

// ──────────────────────────────────────────────────────────────────
// DNS protocol probes — kept tiny to stay on the hot path.
// ──────────────────────────────────────────────────────────────────

// isDNSQuery returns true iff the packet looks like an outbound
// IPv4 UDP/53 DNS query. Cheap heuristic — false positives just
// cost us a wasted blocklist lookup, false negatives mean the
// query goes through to the upstream resolver unchecked, which
// is the existing behaviour.
func isDNSQuery(pkt []byte) bool {
	if len(pkt) < 28 {
		return false
	}
	// IPv4?
	if pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return false
	}
	// UDP?
	if pkt[9] != 17 {
		return false
	}
	// Dst port 53?
	dstPort := int(pkt[ihl+2])<<8 | int(pkt[ihl+3])
	return dstPort == 53
}

// extractDNSQName pulls the QNAME out of the first question of a
// DNS query packet. Returns ("", err) on malformed input.
func extractDNSQName(pkt []byte) (string, error) {
	if len(pkt) < 28 {
		return "", errors.New("packet too short")
	}
	ihl := int(pkt[0]&0x0f) * 4
	dnsStart := ihl + 8 // skip UDP header
	if len(pkt) < dnsStart+12 {
		return "", errors.New("dns header truncated")
	}
	// DNS header is 12 bytes; question starts at dnsStart+12.
	pos := dnsStart + 12
	var labels []string
	for pos < len(pkt) {
		l := int(pkt[pos])
		if l == 0 {
			break
		}
		if l&0xc0 != 0 {
			// Compression pointer in a query — unusual but legal;
			// we don't bother resolving it for filter purposes.
			return "", errors.New("compressed qname")
		}
		pos++
		if pos+l > len(pkt) {
			return "", errors.New("label runs off end")
		}
		labels = append(labels, string(pkt[pos:pos+l]))
		pos += l
		if len(labels) > 127 {
			return "", errors.New("too many labels")
		}
	}
	return strings.Join(labels, "."), nil
}

// buildBlockedDNSReply takes a full IPv4+UDP+DNS query packet (as it
// came out of the family's tunnel via netstack) and returns a full
// IPv4+UDP+DNS reply pointing the queried name at the home node's
// sinkhole IP. Reply matches what dns.BuildBlockedResponse would have
// produced on the home node, so block-page UX is identical in
// fallback.
//
// We swap src/dst at both the IP and UDP layers, copy the DNS reply
// payload from the shared internal/dns helper, and recompute both
// checksums. Returns ErrNotDNSQuery if the packet doesn't look like
// IPv4/UDP/53 — caller's already filtered that via isDNSQuery so this
// shouldn't fire in practice but it's cheap insurance.
func buildBlockedDNSReply(query []byte) ([]byte, error) {
	if len(query) < 28 {
		return nil, errors.New("query too short")
	}
	if query[0]>>4 != 4 {
		return nil, errors.New("not ipv4")
	}
	ihl := int(query[0]&0x0f) * 4
	if ihl < 20 || len(query) < ihl+8 {
		return nil, errors.New("bad ipv4 header")
	}
	if query[9] != 17 {
		return nil, errors.New("not udp")
	}

	udpStart := ihl
	udpLen := int(binary.BigEndian.Uint16(query[udpStart+4 : udpStart+6]))
	if udpLen < 8 || udpStart+udpLen > len(query) {
		return nil, errors.New("bad udp length")
	}
	dnsPayload := query[udpStart+8 : udpStart+udpLen]

	// Build the DNS reply bytes via the shared helper. This guarantees
	// the same answer shape (sinkhole A 10.10.0.2, TTL 5s) the home
	// node would have produced.
	dnsReply := dns.BuildSinkholeAFromBytes(dnsPayload)
	if len(dnsReply) == 0 {
		return nil, errors.New("dns reply build failed")
	}

	// Compose IPv4 + UDP + DNS reply.
	const (
		ipv4HeaderLen = 20
		udpHeaderLen  = 8
	)
	totalUDPLen := udpHeaderLen + len(dnsReply)
	totalIPLen := ipv4HeaderLen + totalUDPLen

	out := make([]byte, totalIPLen)

	// IPv4 header: copy the request's then patch length, ttl, swap
	// addrs, zero checksum, recompute. We rebuild a fresh 20-byte
	// header (ignoring options) — the request might have used IHL>5
	// but for fallback replies we always emit a plain header.
	out[0] = 0x45 // IPv4, IHL=5
	out[1] = query[1] // copy DSCP/ECN
	binary.BigEndian.PutUint16(out[2:4], uint16(totalIPLen))
	// Identification: 0 is fine for unfragmented short replies.
	binary.BigEndian.PutUint16(out[4:6], 0)
	binary.BigEndian.PutUint16(out[6:8], 0x4000) // DF, no fragment offset
	out[8] = 64                                  // TTL
	out[9] = 17                                  // UDP
	// Swap src/dst IP addrs. Source/dest live at fixed offsets in the
	// IPv4 header regardless of IHL (options come after), so use 12:16
	// and 16:20 directly rather than computing from ihl.
	copy(out[12:16], query[16:20]) // their dst (us) → our src
	copy(out[16:20], query[12:16]) // their src (child) → our dst
	// IP checksum at [10:12]. make() zeroed the buffer so the field
	// is already zero when ipChecksum runs.
	ipChecksum(out[:ipv4HeaderLen])

	// UDP header.
	udpOut := out[ipv4HeaderLen:]
	// Swap src/dst ports.
	copy(udpOut[0:2], query[udpStart+2:udpStart+4]) // their dst (53) → our src
	copy(udpOut[2:4], query[udpStart+0:udpStart+2]) // their src → our dst
	binary.BigEndian.PutUint16(udpOut[4:6], uint16(totalUDPLen))
	// UDP checksum: optional in IPv4 (0 = unchecked). Compute it
	// anyway — netstack/clients are happier with checksummed UDP.
	binary.BigEndian.PutUint16(udpOut[6:8], 0) // zero before compute
	copy(udpOut[8:], dnsReply)
	udpChecksum(out[:ipv4HeaderLen], udpOut)

	return out, nil
}

// ipChecksum computes the IPv4 header checksum over the first 20
// bytes of hdr (assumes IHL=5; we always emit plain headers above).
// Sets hdr[10:12] in place. The checksum field must be zero on entry.
func ipChecksum(hdr []byte) {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(hdr[10:12], ^uint16(sum))
}

// udpChecksum computes the UDP checksum using the IPv4 pseudo-header
// (src IP, dst IP, zero, protocol, UDP length). Sets udp[6:8] in place.
// udp[6:8] must be zero on entry. ipHdr is the IPv4 header (20 bytes).
func udpChecksum(ipHdr, udp []byte) {
	var sum uint32
	// Pseudo-header: src + dst (8 bytes) + zero + proto (2 bytes) + udp len (2 bytes).
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ipHdr[i : i+2]))
	}
	sum += uint32(ipHdr[9])                                  // protocol
	sum += uint32(binary.BigEndian.Uint16(udp[4:6]))          // udp length
	// UDP itself.
	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)&1 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		// RFC 768: a transmitted zero checksum means "no checksum".
		// If our computed checksum is zero, send all-ones instead.
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], csum)
}