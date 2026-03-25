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

func NewResolver(bl *Blocklist, policy PolicyReader, presence PresenceReader, logger Logger) *Resolver {
return &Resolver{
blocklist: bl,
policy:    policy,
presence:  presence,
logger:    logger,
upstreams: []string{"1.1.1.1:53", "9.9.9.9:53", "8.8.8.8:53"},
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
conn, err := net.DialTimeout("udp", upstream, timeout)
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
if err == io.EOF {
return nil, net.ErrClosed
}
return nil, err
}
return buf[:n], nil
}
