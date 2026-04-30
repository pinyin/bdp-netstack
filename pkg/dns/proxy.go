// Package dns implements a minimal DNS proxy integrated into the BDP UDP layer.
package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pinyin/bdp-netstack/pkg/udp"
)

const (
	DNSPort = 53
)

// Proxy is a BDP-style DNS forwarder. It receives DNS queries on UDP port 53
// and forwards them to an upstream DNS server.
type Proxy struct {
	upstream string // "ip:port" of upstream DNS
	listenIP net.IP
}

// NewProxy creates a DNS proxy. upstreamAddr is the upstream DNS server (e.g., "8.8.8.8:53").
// If empty, reads from /etc/resolv.conf.
func NewProxy(listenIP net.IP, upstreamAddr string) *Proxy {
	p := &Proxy{listenIP: listenIP}
	if upstreamAddr != "" {
		p.upstream = upstreamAddr
	} else {
		p.upstream = readSystemDNS()
	}
	return p
}

// Handler returns a udp.Handler for BDP integration.
func (p *Proxy) Handler() udp.Handler {
	return func(dg *udp.UDPDatagram) []*udp.UDPDatagram {
		resp := p.forward(dg)
		if resp == nil {
			return nil
		}
		return []*udp.UDPDatagram{resp}
	}
}

// forward sends a DNS query to upstream and returns the response.
func (p *Proxy) forward(dg *udp.UDPDatagram) *udp.UDPDatagram {
	if p.upstream == "" {
		return p.servfail(dg)
	}

	conn, err := net.Dial("udp", p.upstream)
	if err != nil {
		return p.servfail(dg)
	}
	defer conn.Close()

	if _, err := conn.Write(dg.Payload); err != nil {
		return p.servfail(dg)
	}

	respBuf := make([]byte, 1500)
	n, err := conn.Read(respBuf)
	if err != nil {
		return p.servfail(dg)
	}

	return &udp.UDPDatagram{
		SrcIP:   dg.DstIP,
		DstIP:   dg.SrcIP,
		SrcPort: DNSPort,
		DstPort: dg.SrcPort,
		Payload: respBuf[:n],
	}
}

// servfail returns a SERVFAIL response for failed queries.
func (p *Proxy) servfail(dg *udp.UDPDatagram) *udp.UDPDatagram {
	if len(dg.Payload) < 2 {
		return nil
	}
	resp := make([]byte, len(dg.Payload))
	copy(resp, dg.Payload)
	// Copy transaction ID, set response + SERVFAIL flags
	if len(resp) >= 4 {
		resp[2] = 0x81 // QR=1 (response), Opcode=0, AA=0, TC=0, RD=0
		resp[3] = 0x82 // RA=0, Z=0, RCODE=2 (SERVFAIL)
	}
	return &udp.UDPDatagram{
		SrcIP:   dg.DstIP,
		DstIP:   dg.SrcIP,
		SrcPort: DNSPort,
		DstPort: dg.SrcPort,
		Payload: resp,
	}
}

// readSystemDNS reads the first nameserver from /etc/resolv.conf.
func readSystemDNS() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver ") {
			ip := strings.TrimPrefix(line, "nameserver ")
			ip = strings.TrimSpace(ip)
			// Validate IP
			if net.ParseIP(ip) != nil {
				return net.JoinHostPort(ip, "53")
			}
		}
	}
	return ""
}

// BuildServfail builds a minimal SERVFAIL response for a DNS query.
func BuildServfail(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query))
	copy(resp, query)
	binary.BigEndian.PutUint16(resp[2:4], 0x8182) // QR=1, RCODE=SERVFAIL
	return resp
}

// SetUpstream allows changing the upstream DNS server at runtime.
func (p *Proxy) SetUpstream(addr string) {
	p.upstream = addr
}

func (p *Proxy) Upstream() string {
	return p.upstream
}

// Test helpers

// ParseQueryName extracts the QNAME from a DNS query (for testing).
func ParseQueryName(data []byte) (string, int, error) {
	if len(data) < 12 {
		return "", 0, fmt.Errorf("query too short")
	}
	offset := 12
	var parts []string
	for {
		if offset >= len(data) {
			return "", 0, fmt.Errorf("truncated query")
		}
		l := int(data[offset])
		if l == 0 {
			offset++
			break
		}
		if l&0xC0 != 0 {
			// Compressed name — not handled in this minimal parser
			offset += 2
			break
		}
		offset++
		if offset+l > len(data) {
			return "", 0, fmt.Errorf("truncated label")
		}
		parts = append(parts, string(data[offset:offset+l]))
		offset += l
	}
	return strings.Join(parts, "."), offset, nil
}
