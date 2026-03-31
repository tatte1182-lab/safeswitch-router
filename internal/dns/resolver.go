package dns

import (
	"context"
	"io"
	"net"
	"time"
)

type PolicyReader interface {
	DNSProfileForMAC(mac string) string
}

type PresenceReader interface {
	MACForIP(ip string) (string, bool)
}

type Logger interface {
	Printf(format string, v ...any)
}

// sinkholeIP is the IP the block-page HTTP server listens on (bound to wg0).
// Blocked A queries return this address; browsers follow and get the block page.
const qTypeA uint16 = 1

var sinkholeIP = [4]byte{10, 10, 0, 2}

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
		upstreams: []string{"185.228.168.168:53", "185.228.169.168:53", "1.1.1.3:53"},
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
	if r.blocklist.IsBlocked(domain) {
		r.logger.Printf("[dns] blocked domain=%s src=%s", domain, srcIP)
		r.sink.RecordBlock(BlockEvent{Domain: domain, SrcIP: srcIP})
		// For A queries return the sinkhole IP so the browser reaches the
		// block page. For everything else (AAAA, MX, TXT…) NXDOMAIN is correct.
		if m.questions[0].qtype == qTypeA {
			return buildSinkholeA(query, sinkholeIP)
		}
		return buildNXDomain(query)
	}
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
	conn, err := net.DialTimeout("tcp", upstream, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	msg := make([]byte, 2+len(query))
	msg[0] = byte(len(query) >> 8)
	msg[1] = byte(len(query))
	copy(msg[2:], query)
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, err
	}
	respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	buf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
