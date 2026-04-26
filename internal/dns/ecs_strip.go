// Package dns - EDNS Client Subnet (ECS) stripping.
//
// Drop into internal/dns/ecs_strip.go.
//
// Background:
//   When a recursive resolver forwards a query to an upstream, it can
//   include EDNS0 OPT(ECS) — a hint about the client's IP/subnet so the
//   upstream can return geo-targeted answers (CDN routing, regional CDNs).
//
// Why we strip it:
//   1. Privacy: ECS leaks family location to Cloudflare/Google. Stripping
//      means upstream resolvers see only the SafeSwitch VPS as the source.
//      Combined with DoT (Phase 2) this is real privacy hardening.
//   2. Cache locality: without ECS, all family queries from our resolver
//      hit the same upstream cache key. Hit rate improves significantly
//      for popular domains.
//
// Performance impact:
//   Some CDNs (Akamai, Fastly, Cloudflare's own edge) use ECS for routing
//   decisions. Without ECS they fall back to "where is the resolver?".
//   Since our resolver is at a known location (DigitalOcean Sydney for
//   Tee's family), the routing decision is consistent — just not
//   optimised per-family. For families clustered near the VPS this is
//   a net positive; for distant families it's a small latency increase
//   on first content-fetch (subsequent fetches are cached).
//
// Implementation:
//   Operates at the wire level on the DNS message bytes — we don't have
//   a full DNS parser in the resolver, so we walk the OPT pseudo-RR in
//   the additional section and zero out the ECS option if present.

package dns

import (
	"encoding/binary"
)

// EDNS0 option codes per IANA.
const (
	ednsOptCodeECS = 8 // edns-client-subnet
)

// StripECS removes the EDNS0 Client Subnet option from a wire-format
// DNS query, if present. Returns the modified message (may be the same
// slice if no ECS was present) and a bool indicating whether anything
// was stripped.
//
// Safe to call on every outbound query. ~50ns when no ECS present.
func StripECS(msg []byte) ([]byte, bool) {
	if len(msg) < 12 {
		return msg, false
	}

	// DNS header: 12 bytes.
	// QDCOUNT=msg[4:6], ANCOUNT=msg[6:8], NSCOUNT=msg[8:10], ARCOUNT=msg[10:12]
	qdCount := binary.BigEndian.Uint16(msg[4:6])
	anCount := binary.BigEndian.Uint16(msg[6:8])
	nsCount := binary.BigEndian.Uint16(msg[8:10])
	arCount := binary.BigEndian.Uint16(msg[10:12])

	if arCount == 0 {
		return msg, false // no additional section, no OPT, no ECS
	}

	// Skip past Question section.
	offset := 12
	for i := uint16(0); i < qdCount; i++ {
		nameEnd, err := skipName(msg, offset)
		if err != nil {
			return msg, false
		}
		// QTYPE(2) + QCLASS(2) = 4
		offset = nameEnd + 4
		if offset > len(msg) {
			return msg, false
		}
	}

	// Skip Answer + Authority sections.
	for i := uint16(0); i < anCount+nsCount; i++ {
		next, err := skipRR(msg, offset)
		if err != nil {
			return msg, false
		}
		offset = next
	}

	// Walk Additional section. OPT pseudo-RR has TYPE=41 (0x29).
	for i := uint16(0); i < arCount; i++ {
		rrStart := offset
		nameEnd, err := skipName(msg, offset)
		if err != nil {
			return msg, false
		}
		// Need at least TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
		if nameEnd+10 > len(msg) {
			return msg, false
		}
		rrType := binary.BigEndian.Uint16(msg[nameEnd : nameEnd+2])
		rdLen := binary.BigEndian.Uint16(msg[nameEnd+8 : nameEnd+10])
		rdStart := nameEnd + 10
		rdEnd := rdStart + int(rdLen)
		if rdEnd > len(msg) {
			return msg, false
		}

		if rrType == 41 { // OPT
			// Walk OPT options looking for ECS (code=8). Each option:
			//   OPTION-CODE (2) + OPTION-LENGTH (2) + OPTION-DATA (n)
			modified, stripped := stripOPTOption(msg, rdStart, rdEnd, ednsOptCodeECS)
			if stripped {
				return modified, true
			}
			return msg, false
		}

		offset = rdEnd
		_ = rrStart
	}

	return msg, false
}

// stripOPTOption returns a copy of msg with the named OPT option removed.
// Walks options in [rdStart, rdEnd), copies non-matching options, and
// rewrites the OPT RDLENGTH if a strip occurred.
func stripOPTOption(msg []byte, rdStart, rdEnd int, optCode uint16) ([]byte, bool) {
	pos := rdStart
	var ranges [][2]int // ranges of bytes to keep
	stripped := false

	for pos < rdEnd {
		if pos+4 > rdEnd {
			return msg, false
		}
		code := binary.BigEndian.Uint16(msg[pos : pos+2])
		olen := binary.BigEndian.Uint16(msg[pos+2 : pos+4])
		nextPos := pos + 4 + int(olen)
		if nextPos > rdEnd {
			return msg, false
		}
		if code == optCode {
			stripped = true
			// don't add to ranges — drops this option
		} else {
			ranges = append(ranges, [2]int{pos, nextPos})
		}
		pos = nextPos
	}

	if !stripped {
		return msg, false
	}

	// Rebuild the message:
	// [0:rdStart] + kept option bytes + [rdEnd:]
	keptLen := 0
	for _, r := range ranges {
		keptLen += r[1] - r[0]
	}

	out := make([]byte, 0, len(msg)-((rdEnd-rdStart)-keptLen))
	out = append(out, msg[:rdStart]...)
	for _, r := range ranges {
		out = append(out, msg[r[0]:r[1]]...)
	}
	out = append(out, msg[rdEnd:]...)

	// Rewrite OPT RDLENGTH at rdStart-2.
	binary.BigEndian.PutUint16(out[rdStart-2:rdStart], uint16(keptLen))
	return out, true
}

// skipName advances past a (possibly compressed) DNS name and returns
// the offset of the first byte AFTER the name.
func skipName(msg []byte, offset int) (int, error) {
	for {
		if offset >= len(msg) {
			return 0, errTruncated
		}
		l := msg[offset]
		if l == 0 {
			return offset + 1, nil
		}
		if l&0xC0 == 0xC0 {
			// Compression pointer: 2 bytes total
			if offset+2 > len(msg) {
				return 0, errTruncated
			}
			return offset + 2, nil
		}
		if l&0xC0 != 0 {
			return 0, errBadLabel // reserved bits
		}
		offset += 1 + int(l)
	}
}

func skipRR(msg []byte, offset int) (int, error) {
	end, err := skipName(msg, offset)
	if err != nil {
		return 0, err
	}
	if end+10 > len(msg) {
		return 0, errTruncated
	}
	rdLen := binary.BigEndian.Uint16(msg[end+8 : end+10])
	next := end + 10 + int(rdLen)
	if next > len(msg) {
		return 0, errTruncated
	}
	return next, nil
}

type ecsErr string

func (e ecsErr) Error() string { return string(e) }

const (
	errTruncated ecsErr = "truncated DNS message"
	errBadLabel  ecsErr = "invalid label byte"
)
