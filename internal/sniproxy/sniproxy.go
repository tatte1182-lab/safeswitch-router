// Package sniproxy is a transparent TLS SNI inspector for closing the
// DNS-bypass gap where modern CDN-fronted content (Cloudflare, CloudFront,
// Fastly) can be reached via cached anycast connections without a fresh
// DNS lookup. The phone reuses a long-lived TCP socket to e.g.
// 104.18.38.10:443 and selects the destination site purely via the TLS
// ClientHello SNI extension. DNS-only filtering never sees the lookup
// and therefore cannot block.
//
// Enforcement model mirrors internal/dns/resolver.go exactly so DNS and
// SNI never drift:
//
//   1. Pause check        - InternetPausedForIP - global block-everything
//   2a. Global blocklist  - IsBlocked(sni)      - malware/phishing baseline
//   2c. Per-child filter  - IsBlockedForCategories(sni, cats) - adult/etc.
//   3. Pass-through       - splice both directions
//
// Unknown source IPs (devices on wg0 with no row in the policy bundle):
//   - Protective categories (malware/phishing/scam/etc.) still blocked.
//   - Policy categories (adult/gambling/social/etc.) pass through.
package sniproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/getsafeswitch/safeswitch-router/internal/dns"
)

type Blocklist interface {
	IsBlocked(domain string) bool
	IsBlockedForCategories(domain string, cats []string) bool
	CategoryFor(domain string) string
}

type PolicyReader interface {
	InternetPausedForIP(ip string) bool
	BlockedCategoriesForIP(ip string) []string
}

type BlockSink interface {
	RecordBlock(evt dns.BlockEvent)
}

type Logger interface {
	Printf(format string, args ...interface{})
}

var protectiveCategories = map[string]struct{}{
	"phishing":         {},
	"malware":          {},
	"scam":             {},
	"ransomware":       {},
	"cryptojacking":    {},
	"newly_registered": {},
}

func isProtective(category string) bool {
	_, ok := protectiveCategories[strings.ToLower(category)]
	return ok
}

type Server struct {
	addr        string
	blocklist   Blocklist
	policy      PolicyReader
	sink        BlockSink
	logger      Logger
	peekTimeout time.Duration
	dialTimeout time.Duration
}

func NewServer(addr string, bl Blocklist, policy PolicyReader, sink BlockSink, logger Logger) *Server {
	if sink == nil {
		sink = dns.NoopBlockSink{}
	}
	return &Server{
		addr:        addr,
		blocklist:   bl,
		policy:      policy,
		sink:        sink,
		logger:      logger,
		peekTimeout: 5 * time.Second,
		dialTimeout: 10 * time.Second,
	}
}

func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("sniproxy listen %s: %w", s.addr, err)
	}
	s.logger.Printf("[sniproxy] started addr=%s", s.addr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					time.Sleep(10 * time.Millisecond)
					continue
				}
			}
			go s.handle(ctx, conn)
		}
	}()
	return nil
}

func (s *Server) Stop(_ context.Context) error   { return nil }
func (s *Server) Name() string                   { return "sniproxy" }
func (s *Server) Health(_ context.Context) error { return nil }

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	br := bufio.NewReaderSize(conn, 16384)
	wrapped := &peekedConn{Conn: conn, r: br}

	conn.SetReadDeadline(time.Now().Add(s.peekTimeout))
	hdr, err := br.Peek(5)
	if err != nil || len(hdr) < 5 {
		conn.SetReadDeadline(time.Time{})
		return
	}

	if hdr[0] != 0x16 {
		conn.SetReadDeadline(time.Time{})
		s.passThroughWrapped(wrapped)
		return
	}

	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 16384 {
		conn.SetReadDeadline(time.Time{})
		return
	}

	full, err := br.Peek(5 + recLen)
	conn.SetReadDeadline(time.Time{})
	if err != nil || len(full) < 5+recLen {
		s.passThroughWrapped(wrapped)
		return
	}

	sni := extractSNI(full)

	if sni == "" {
		s.passThroughWrapped(wrapped)
		return
	}

	sni = strings.ToLower(sni)

	if s.policy != nil && s.policy.InternetPausedForIP(srcIP) {
		s.logger.Printf("[sniproxy] paused sinkhole sni=%s src=%s", sni, srcIP)
		s.recordBlock(sni, srcIP, "paused")
		s.sendTLSAlertAndRST(conn)
		return
	}

	if s.blocklist.IsBlocked(sni) {
		cat := s.blocklist.CategoryFor(sni)

		known := s.policy != nil && len(s.policy.BlockedCategoriesForIP(srcIP)) > 0
		if !known && !isProtective(cat) {
			s.passThroughWrapped(wrapped)
			return
		}

		s.logger.Printf("[sniproxy] blocked (%s) sni=%s src=%s", cat, sni, srcIP)
		s.recordBlock(sni, srcIP, cat)
		s.sendTLSAlertAndRST(conn)
		return
	}

	if s.policy != nil {
		if cats := s.policy.BlockedCategoriesForIP(srcIP); len(cats) > 0 {
			if s.blocklist.IsBlockedForCategories(sni, cats) {
				cat := s.blocklist.CategoryFor(sni)
				s.logger.Printf("[sniproxy] blocked (category=%s) sni=%s src=%s cats=%v",
					cat, sni, srcIP, cats)
				s.recordBlock(sni, srcIP, cat)
				s.sendTLSAlertAndRST(conn)
				return
			}
		}
	}

	s.passThroughWrapped(wrapped)
}

func (s *Server) passThroughWrapped(wrapped *peekedConn) {
	dst, err := originalDst(wrapped.Conn)
	if err != nil {
		return
	}

	remote, err := net.DialTimeout("tcp", dst, s.dialTimeout)
	if err != nil {
		return
	}
	defer remote.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(remote, wrapped); done <- struct{}{} }()
	go func() { _, _ = io.Copy(wrapped.Conn, remote); done <- struct{}{} }()
	<-done
}

func (s *Server) sendTLSAlertAndRST(conn net.Conn) {
	_, _ = conn.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28})
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
}

func (s *Server) recordBlock(sni, srcIP, category string) {
	s.sink.RecordBlock(dns.BlockEvent{
		Domain:   sni,
		SrcIP:    srcIP,
		Category: category,
	})
}

func extractSNI(record []byte) string {
	r := &oneShotReader{data: record}
	conn := &fakeConn{r: r}

	var sni string
	cfg := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, errAbortHandshake
		},
	}
	server := tls.Server(conn, cfg)
	_ = server.Handshake()
	return sni
}

var errAbortHandshake = fmt.Errorf("sniproxy: handshake intentionally aborted after sni capture")

type oneShotReader struct {
	data []byte
	pos  int
}

func (o *oneShotReader) Read(p []byte) (int, error) {
	if o.pos >= len(o.data) {
		return 0, io.EOF
	}
	n := copy(p, o.data[o.pos:])
	o.pos += n
	return n, nil
}

type fakeConn struct {
	r *oneShotReader
}

func (f *fakeConn) Read(b []byte) (int, error)         { return f.r.Read(b) }
func (f *fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (f *fakeConn) Close() error                       { return nil }
func (f *fakeConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (f *fakeConn) SetDeadline(_ time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(_ time.Time) error { return nil }
