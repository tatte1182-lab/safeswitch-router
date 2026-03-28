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

type Resolver struct {
blocklist *Blocklist
policy    PolicyReader
presence  PresenceReader
logger    Logger
upstreams []string
}

func NewResolver(bl *Blocklist, policy PolicyReader, presence PresenceReader, logger Logger, notifyURL string) *Resolver {
return &Resolver{
blocklist: bl,
policy:    policy,
presence:  presence,
logger:    logger,
upstreams: []string{"185.228.168.168:53", "185.228.169.168:53", "1.1.1.3:53"},
}
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

