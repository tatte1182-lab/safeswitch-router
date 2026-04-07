// internal/dns/blocked_response.go
//
// Replace NXDOMAIN with a sinkhole A record so the browser reaches the
// block page instead of showing a raw DNS error.
//
// Drop this file into internal/dns/ alongside your existing resolver.
// Then in your blocked-domain handler, call BuildBlockedResponse() instead
// of returning a SERVFAIL/NXDOMAIN.
//
// Sinkhole IP: 10.10.0.2 — must be bound on wg0 (see sinkhole.go).
// TTL is kept very short (5s) so the block lifts quickly when a schedule ends.

package dns

import (
	"net"

	"github.com/miekg/dns"
)

const (
	// SinkholeIP is the address the blocked-domain A record points to.
	// This IP must be listening on port 80 (StartSinkhole in sinkhole.go).
	SinkholeIP = "10.10.0.2"

	// blockTTL is intentionally short so cached entries expire quickly
	// when a schedule ends and the domain becomes accessible again.
	blockTTL = 5
)

// BuildBlockedResponse returns a DNS response for a blocked domain.
// For A/AAAA queries it returns the sinkhole IP so the browser gets a
// clean block page. For all other query types it returns NXDOMAIN
// (there's no meaningful sinkhole for MX, TXT, etc.).
func BuildBlockedResponse(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = false

	if len(req.Question) == 0 {
		resp.SetRcode(req, dns.RcodeNameError)
		return resp
	}

	q := req.Question[0]

	switch q.Qtype {
	case dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    blockTTL,
			},
			A: net.ParseIP(SinkholeIP).To4(),
		})

	case dns.TypeAAAA:
		// Return NXDOMAIN for IPv6 — the browser will fall back to IPv4
		// and hit the sinkhole there. Returning a v6 sinkhole address
		// would require binding a v6 address on the interface too.
		resp.SetRcode(req, dns.RcodeNameError)

	default:
		// MX, TXT, NS, etc. — NXDOMAIN is the right answer
		resp.SetRcode(req, dns.RcodeNameError)
	}

	return resp
}

// IsBlockedDomain checks your existing blocklist. Wire this into your
// DNS handler before the upstream query. Example integration:
//
//   func (h *Handler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
//       if len(r.Question) > 0 {
//           name := strings.TrimSuffix(r.Question[0].Name, ".")
//           if h.blocklist.IsBlocked(name) || h.policyBlocked(name) {
//               resp := BuildBlockedResponse(r)
//               w.WriteMsg(resp)
//               return
//           }
//       }
//       h.upstream.ServeDNS(w, r)
//   }
//
// No changes needed to the blocklist seeding or lookup — only the response
// builder changes from NXDOMAIN to sinkhole A record.
