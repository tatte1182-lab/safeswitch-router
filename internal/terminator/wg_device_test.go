package terminator

import (
	"encoding/binary"
	"testing"
)

// buildDNSQuery synthesises a minimal IPv4/UDP/DNS query packet
// for testing. Real packets in the wild come from many resolvers
// with various flag combinations, but the QNAME extraction logic
// only cares about the question section.
func buildDNSQuery(qname string) []byte {
	// IPv4 header (20 bytes), UDP header (8), DNS header (12), question.
	pkt := make([]byte, 20+8+12)

	// IPv4
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP

	// UDP
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // src port
	binary.BigEndian.PutUint16(pkt[22:24], 53)    // dst port (DNS)

	// DNS header
	binary.BigEndian.PutUint16(pkt[28:30], 0xabcd) // id
	binary.BigEndian.PutUint16(pkt[30:32], 0x0100) // flags: standard query
	binary.BigEndian.PutUint16(pkt[32:34], 1)      // qdcount

	// Question section: encode QNAME as length-prefixed labels.
	q := []byte{}
	for _, label := range splitDomain(qname) {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)              // root
	q = append(q, 0, 1, 0, 1)      // QTYPE=A, QCLASS=IN

	pkt = append(pkt, q...)

	// Fix up UDP length now that we know it.
	binary.BigEndian.PutUint16(pkt[24:26], uint16(8+12+len(q)))
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))

	return pkt
}

func splitDomain(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	cur := ""
	for _, r := range s {
		if r == '.' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func TestIsDNSQuery_RecognisesUDP53(t *testing.T) {
	pkt := buildDNSQuery("example.com")
	if !isDNSQuery(pkt) {
		t.Fatal("expected UDP/53 packet to be recognised as DNS")
	}
}

func TestIsDNSQuery_RejectsTooShort(t *testing.T) {
	if isDNSQuery([]byte{0x45, 0x00}) {
		t.Error("expected too-short packet to be rejected")
	}
}

func TestIsDNSQuery_RejectsNonUDP(t *testing.T) {
	pkt := buildDNSQuery("example.com")
	pkt[9] = 6 // TCP
	if isDNSQuery(pkt) {
		t.Error("expected TCP packet to be rejected")
	}
}

func TestIsDNSQuery_RejectsWrongPort(t *testing.T) {
	pkt := buildDNSQuery("example.com")
	binary.BigEndian.PutUint16(pkt[22:24], 80)
	if isDNSQuery(pkt) {
		t.Error("expected non-53 dst port to be rejected")
	}
}

func TestExtractDNSQName_Simple(t *testing.T) {
	pkt := buildDNSQuery("example.com")
	got, err := extractDNSQName(pkt)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "example.com" {
		t.Errorf("got %q, want example.com", got)
	}
}

func TestExtractDNSQName_Subdomain(t *testing.T) {
	pkt := buildDNSQuery("ads.tracker.evil.example.com")
	got, err := extractDNSQName(pkt)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "ads.tracker.evil.example.com" {
		t.Errorf("got %q, want ads.tracker.evil.example.com", got)
	}
}

func TestExtractDNSQName_TruncatedRejected(t *testing.T) {
	pkt := buildDNSQuery("example.com")
	// Truncate inside the QNAME label data — the parser will read
	// a length byte, then run off the end before consuming all
	// declared characters.
	// The QNAME starts at offset 40 (20 IP + 8 UDP + 12 DNS).
	// "example" label is len(7) + 7 bytes → truncate inside it.
	pkt = pkt[:42] // length byte + only 1 char of "example"
	if _, err := extractDNSQName(pkt); err == nil {
		t.Error("expected error on truncated packet, got nil")
	}
}

func TestDecodeWGKey_AcceptsBase64(t *testing.T) {
	// 32 zero bytes base64-encoded
	b64 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	got, err := decodeWGKey(b64)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Errorf("got %q", got)
	}
}

func TestDecodeWGKey_AcceptsHex(t *testing.T) {
	hex64 := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := decodeWGKey(hex64)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != hex64 {
		t.Errorf("got %q, want passthrough", got)
	}
}

func TestDecodeWGKey_RejectsGarbage(t *testing.T) {
	if _, err := decodeWGKey("not-a-key"); err == nil {
		t.Error("expected error on garbage")
	}
}