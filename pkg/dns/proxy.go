// Package dns implements a minimal DNS proxy integrated into the BDP UDP layer.
// Upstream resolution is asynchronous to avoid blocking the BDP deliberation loop.
package dns

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/udp"
)

const (
	DNSPort = 53
)

// pendingQuery tracks an in-flight DNS query to upstream.
type pendingQuery struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	query   []byte // original DNS query (for SERVFAIL on failure)
	result  chan *udp.UDPDatagram
}

// Proxy is a BDP-style DNS forwarder. It enqueues DNS queries and resolves
// them asynchronously via goroutines, then surfaces responses via Poll().
type Proxy struct {
	upstream string // "ip:port" of upstream DNS
	listenIP net.IP

	nextID  uint64
	pending map[uint64]*pendingQuery
	ready   []*udp.UDPDatagram
}

// NewProxy creates a DNS proxy. upstreamAddr is the upstream DNS server (e.g., "8.8.8.8:53").
// If empty, reads from /etc/resolv.conf.
func NewProxy(listenIP net.IP, upstreamAddr string) *Proxy {
	p := &Proxy{
		listenIP: listenIP,
		pending:  make(map[uint64]*pendingQuery),
	}
	if upstreamAddr != "" {
		p.upstream = upstreamAddr
	} else {
		p.upstream = readSystemDNS()
	}
	return p
}

// Handler returns a udp.Handler for BDP integration.
// Queries are enqueued for async resolution; responses are delivered via Poll().
func (p *Proxy) Handler() udp.Handler {
	return func(dg *udp.UDPDatagram) []*udp.UDPDatagram {
		p.enqueue(dg)
		return nil // response delivered asynchronously via Poll()
	}
}

// enqueue adds a DNS query to the pending table and starts async resolution.
// The goroutine captures the result channel directly to avoid any data race
// on the pending map.
func (p *Proxy) enqueue(dg *udp.UDPDatagram) {
	if p.upstream == "" {
		resp := p.servfail(dg)
		if resp != nil {
			p.ready = append(p.ready, resp)
		}
		return
	}

	id := atomic.AddUint64(&p.nextID, 1)
	pq := &pendingQuery{
		srcIP:   dg.SrcIP,
		dstIP:   dg.DstIP,
		srcPort: dg.SrcPort,
		dstPort: dg.DstPort,
		query:   dg.Payload,
		result:  make(chan *udp.UDPDatagram, 1),
	}
	p.pending[id] = pq

	// Capture everything the goroutine needs, including the channel.
	// No map access from the goroutine — channel send is the only communication.
	upstream := p.upstream
	query := dg.Payload
	ch := pq.result

	go func() {
		conn, err := net.DialTimeout("udp", upstream, 2*time.Second)
		if err != nil {
			ch <- nil
			return
		}
		defer conn.Close()

		if _, err := conn.Write(query); err != nil {
			ch <- nil
			return
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		respBuf := make([]byte, 1500)
		n, err := conn.Read(respBuf)
		if err != nil {
			ch <- nil
			return
		}

		// Build response datagram with correct addresses
		resp := &udp.UDPDatagram{
			SrcIP:   pq.dstIP,
			DstIP:   pq.srcIP,
			SrcPort: DNSPort,
			DstPort: pq.srcPort,
			Payload: respBuf[:n],
		}
		ch <- resp
	}()
}

// Poll checks for completed DNS resolutions and enqueues responses for delivery.
// Called from the BDP deliberation loop (single goroutine).
func (p *Proxy) Poll() {
	for id, pq := range p.pending {
		select {
		case resp := <-pq.result:
			if resp != nil {
				p.ready = append(p.ready, resp)
			} else {
				// Resolution failed; return SERVFAIL so the VM gets a response
				sf := p.servfail(&udp.UDPDatagram{
					SrcIP: pq.srcIP, DstIP: pq.dstIP,
					SrcPort: pq.srcPort, DstPort: pq.dstPort,
					Payload: pq.query,
				})
				if sf != nil {
					p.ready = append(p.ready, sf)
				}
			}
			delete(p.pending, id)
		default:
		}
	}
}

// ConsumeResponses returns and clears accumulated DNS responses.
func (p *Proxy) ConsumeResponses() []*udp.UDPDatagram {
	out := p.ready
	p.ready = nil
	return out
}

// servfail returns a SERVFAIL response for a failed query (synchronous fallback).
func (p *Proxy) servfail(dg *udp.UDPDatagram) *udp.UDPDatagram {
	if len(dg.Payload) < 2 {
		return nil
	}
	resp := make([]byte, len(dg.Payload))
	copy(resp, dg.Payload)
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
