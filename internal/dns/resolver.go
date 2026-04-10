package dns

import (
	"context"
	"net"
	"time"
)

type PolicyReader interface {
	DNSProfileForMAC(mac string) string
	// InternetPausedForIP returns true when the policy engine has blocked
	// internet for the device with the given tunnel IP.
	InternetPausedForIP(ip string) bool
	// BlockedCategoriesForIP returns the list of blocked DNS categories for
	// the child device with the given tunnel IP. Returns nil when no extra
	// category blocking applies.
	BlockedCategoriesForIP(ip string) []string
}

type PresenceReader interface {
	MACForIP(ip string) (string, bool)
}

type Logger interface {
	Printf(format string, v ...any)
}

// sinkholeIP is bound to wg0. All sinkholed A queries return this address
// so the browser reaches the block page HTTP server on the same host.
const qTypeA uint16 = 1

var sinkholeIP = [4]byte{10, 10, 0, 254}

type Resolver struct {
	blocklist *Blocklist
	policy    PolicyReader
	presence  PresenceReader
	logger    Logger
	sink      BlockSink
	upstreams []string
}

func NewResolver(bl *Blocklist, policy PolicyReader, presence PresenceReader, logger Logger) *Resolver {
	return &Resolver{
		blocklist: bl,
		policy:    policy,
		presence:  presence,
		logger:    logger,
		sink:      NoopBlockSink{},
		upstreams: []string{"1.1.1.1:53", "8.8.8.8:53"},
	}
}

// SetBlockSink wires a BlockSink. Call before Start.
func (r *Resolver) SetBlockSink(s BlockSink) {
	r.sink = s
}

func (r *Resolver) Resolve(ctx context.Context, query []byte, srcIP string) []byte {
	m, err := parseQuery(query)
	if err != nil {
		return buildServFail(query)
	}
	if len(m.questions) == 0 {
		return buildServFail(query)
	}
	domain := m.questions[0].name
	isAQuery := m.questions[0].qtype == qTypeA

	// ── Priority 1: internet_paused — sinkhole ALL domains ──────────────────
	if r.policy != nil && r.policy.InternetPausedForIP(srcIP) {
		if isAQuery {
			r.logger.Printf("[dns] paused sinkhole domain=%s src=%s", domain, srcIP)
			return buildSinkholeA(query, sinkholeIP)
		}
		return buildNXDomain(query)
	}

	// ── Priority 2: blocklist — global malware + per-child categories ────────
	//
	// 2a. Global malware/phishing blocklist — applies to every device.
	if r.blocklist.IsBlocked(domain) {
		r.logger.Printf("[dns] blocked (malware) domain=%s src=%s", domain, srcIP)
		r.sink.RecordBlock(BlockEvent{Domain: domain, SrcIP: srcIP})
		if isAQuery {
			return buildSinkholeA(query, sinkholeIP)
		}
		return buildNXDomain(query)
	}

	// 2b. Per-child category blocking — only when the policy bundle carries
	// a non-empty BlockedCategories list for this device's tunnel IP.
	if r.policy != nil {
		if cats := r.policy.BlockedCategoriesForIP(srcIP); len(cats) > 0 {
			if r.blocklist.IsBlockedForCategories(domain, cats) {
				r.logger.Printf("[dns] blocked (category) domain=%s src=%s cats=%v", domain, srcIP, cats)
				r.sink.RecordBlock(BlockEvent{Domain: domain, SrcIP: srcIP})
				if isAQuery {
					return buildSinkholeA(query, sinkholeIP)
				}
				return buildNXDomain(query)
			}
		}
	}

	// ── Priority 3: forward to upstream ─────────────────────────────────────
	resp, err := r.forward(ctx, query)
	if err != nil {
		r.logger.Printf("[dns] upstream failed domain=%s: %v", domain, err)
		return buildServFail(query)
	}
	return resp
}

func (r *Resolver) forward(ctx context.Context, query []byte) ([]byte, error) {
	timeout := 3 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	var lastErr error
	for _, upstream := range r.upstreams {
		resp, err := r.forwardOnce(upstream, query, timeout)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (r *Resolver) forwardOnce(upstream string, query []byte, timeout time.Duration) ([]byte, error) {
	dialer := &net.Dialer{
		Timeout:   timeout,
		LocalAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 0},
	}
	conn, err := dialer.Dial("udp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
