package dns

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/udp"
)

func makeDNSQuery(domain string) []byte {
	buf := make([]byte, 512)

	// Header
	binary.BigEndian.PutUint16(buf[0:2], 0x0001)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 0x0001)

	// Question section
	offset := 12
	start := 0
	b := []byte(domain)
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == '.' {
			l := i - start
			buf[offset] = byte(l)
			offset++
			copy(buf[offset:], b[start:i])
			offset += l
			start = i + 1
		}
	}
	buf[offset] = 0 // terminator
	offset++
	binary.BigEndian.PutUint16(buf[offset:offset+2], 0x0001) // QTYPE = A
	binary.BigEndian.PutUint16(buf[offset+2:offset+4], 0x0001) // QCLASS = IN
	offset += 4

	return buf[:offset]
}

func TestParseQueryName(t *testing.T) {
	query := makeDNSQuery("www.example.com")

	name, offset, err := ParseQueryName(query)
	if err != nil {
		t.Fatalf("ParseQueryName: %v", err)
	}
	if name != "www.example.com" {
		t.Fatalf("expected 'www.example.com', got '%s'", name)
	}
	if offset < 12 {
		t.Fatalf("offset %d too small", offset)
	}
	t.Logf("Parsed: %s (QTYPE offset=%d)", name, offset)
}

func TestParseQueryNameShort(t *testing.T) {
	query := makeDNSQuery("test.local")
	name, _, err := ParseQueryName(query)
	if err != nil {
		t.Fatalf("ParseQueryName: %v", err)
	}
	if name != "test.local" {
		t.Fatalf("expected 'test.local', got '%s'", name)
	}
}

func TestServfail(t *testing.T) {
	p := NewProxy(net.ParseIP("192.168.65.1"), "127.0.0.1:53") // non-existent upstream

	query := makeDNSQuery("example.com")
	dg := &udp.UDPDatagram{
		SrcIP:   net.ParseIP("192.168.65.2"),
		DstIP:   net.ParseIP("192.168.65.1"),
		SrcPort: 12345,
		DstPort: 53,
		Payload: query,
	}

	// Async handler enqueues query, returns nil
	handler := p.Handler()
	responses := handler(dg)
	if len(responses) != 0 {
		t.Fatalf("expected 0 immediate responses (async), got %d", len(responses))
	}

	// Wait for the async goroutine to fail (dial to 127.0.0.1:53 should fail fast)
	time.Sleep(50 * time.Millisecond)

	// Poll picks up the failed resolution and generates SERVFAIL
	p.Poll()
	ready := p.ConsumeResponses()
	if len(ready) != 1 {
		t.Fatalf("expected 1 response (SERVFAIL) after Poll, got %d", len(ready))
	}
	if string(ready[0].Payload) == string(query) {
		t.Fatal("expected different response from query")
	}
	t.Log("SERVFAIL response generated for unreachable upstream (async)")
}

func TestBuildServfail(t *testing.T) {
	query := makeDNSQuery("example.com")
	resp := BuildServfail(query)
	if len(resp) < 12 {
		t.Fatal("response too short")
	}
	// Check QR bit is set
	if resp[2]&0x80 == 0 {
		t.Fatal("QR bit not set in response")
	}
	// Check RCODE is SERVFAIL
	rcode := resp[3] & 0x0F
	if rcode != 2 {
		t.Fatalf("expected RCODE=SERVFAIL(2), got %d", rcode)
	}
}

func TestReadSystemDNS(t *testing.T) {
	upstream := readSystemDNS()
	t.Logf("System DNS: %s", upstream)
	// Should either find a nameserver or return empty
}

func TestSetUpstream(t *testing.T) {
	p := NewProxy(net.ParseIP("192.168.65.1"), "")
	initial := p.Upstream()
	p.SetUpstream("8.8.8.8:53")
	if p.Upstream() != "8.8.8.8:53" {
		t.Fatalf("expected 8.8.8.8:53, got %s", p.Upstream())
	}
	p.SetUpstream(initial) // restore
}
