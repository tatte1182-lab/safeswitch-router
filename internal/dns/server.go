package dns

import (
"context"
"database/sql"
"encoding/binary"
"io"
"net"
"sync"
"time"
)

type Server struct {
db        *sql.DB
logger    Logger
resolver  *Resolver
blocklist *Blocklist
addr      string
mu        sync.Mutex
cancel    context.CancelFunc
wg        sync.WaitGroup
}

func NewServer(db *sql.DB, logger Logger, resolver *Resolver, blocklist *Blocklist, addr string) *Server {
if addr == "" {
addr = "127.0.0.1:5353"
}
return &Server{db: db, logger: logger, resolver: resolver, blocklist: blocklist, addr: addr}
}

func (s *Server) Name() string { return "dns" }

func (s *Server) Health(ctx context.Context) error { return nil }

func (s *Server) Start(ctx context.Context) error {
if err := s.blocklist.Load(ctx, s.db); err != nil {
s.logger.Printf("[dns] blocklist load failed (empty): %v", err)
} else {
s.logger.Printf("[dns] blocklist loaded domains=%d", s.blocklist.Size())
}
srvCtx, cancel := context.WithCancel(ctx)
s.mu.Lock()
s.cancel = cancel
s.mu.Unlock()
udpConn, err := net.ListenPacket("udp", s.addr)
if err != nil {
cancel()
return err
}
tcpLn, err := net.Listen("tcp", s.addr)
if err != nil {
udpConn.Close()
cancel()
return err
}
s.logger.Printf("[dns] started addr=%s", s.addr)
s.wg.Add(2)
go s.serveUDP(srvCtx, udpConn)
go s.serveTCP(srvCtx, tcpLn)
return nil
}

func (s *Server) Stop(ctx context.Context) error {
s.mu.Lock()
if s.cancel != nil {
s.cancel()
}
s.mu.Unlock()
s.wg.Wait()
s.logger.Printf("[dns] stopped")
return nil
}

func (s *Server) Reload(ctx context.Context) error {
if err := s.blocklist.Load(ctx, s.db); err != nil {
return err
}
s.logger.Printf("[dns] reloaded domains=%d", s.blocklist.Size())
return nil
}

func (s *Server) serveUDP(ctx context.Context, conn net.PacketConn) {
defer s.wg.Done()
defer conn.Close()
go func() { <-ctx.Done(); conn.SetDeadline(time.Now()) }()
buf := make([]byte, 4096)
for {
n, addr, err := conn.ReadFrom(buf)
if err != nil {
select {
case <-ctx.Done():
default:
s.logger.Printf("[dns] udp read: %v", err)
}
return
}
query := make([]byte, n)
copy(query, buf[:n])
srcIP, _, _ := net.SplitHostPort(addr.String())
go func() {
if resp := s.resolver.Resolve(ctx, query, srcIP); resp != nil {
conn.WriteTo(resp, addr)
}
}()
}
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener) {
defer s.wg.Done()
defer ln.Close()
go func() { <-ctx.Done(); ln.Close() }()
for {
conn, err := ln.Accept()
if err != nil {
select {
case <-ctx.Done():
default:
s.logger.Printf("[dns] tcp accept: %v", err)
}
return
}
go s.handleTCP(ctx, conn)
}
}

func (s *Server) handleTCP(ctx context.Context, conn net.Conn) {
defer conn.Close()
_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
var length uint16
if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
return
}
query := make([]byte, length)
if _, err := io.ReadFull(conn, query); err != nil {
return
}
srcIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
resp := s.resolver.Resolve(ctx, query, srcIP)
if resp == nil {
return
}
out := make([]byte, 2+len(resp))
binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
copy(out[2:], resp)
conn.Write(out)
}
