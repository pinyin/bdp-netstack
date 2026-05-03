// Package udpnat implements outbound UDP NAT / connection tracking for BDP netstack.
// It intercepts VM UDP datagrams to external IPs and proxies data through
// host UDP sockets using a BDP-compatible non-blocking I/O model.
package udpnat

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/udp"
)

const (
	// IdleTimeout is the duration after which an idle UDP NAT entry is cleaned up.
	IdleTimeout = 90 * time.Second
	// MaxUDPPayload is the maximum UDP payload size (65535 - 8 byte UDP header - 20 byte IP header).
	MaxUDPPayload = 65507
)

// Key identifies a UDP NAT entry by the full 4-tuple.
type Key struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

func makeKey(srcIP, dstIP net.IP, srcPort, dstPort uint16) Key {
	var k Key
	copy(k.SrcIP[:], srcIP.To4())
	copy(k.DstIP[:], dstIP.To4())
	k.SrcPort = srcPort
	k.DstPort = dstPort
	return k
}

// Entry represents one tracked UDP "connection".
type Entry struct {
	Key Key

	HostConn *net.UDPConn
	hostFD   int
	hostBuf  []byte

	// Egress: datagrams from VM waiting to be sent to host socket
	egressQ []*udp.UDPDatagram
	// Ingress: datagrams received from host socket waiting to deliver to VM
	ingressQ []*udp.UDPDatagram

	lastActive time.Time
	closed     bool
}

// Table is the UDP NAT connection tracking table.
// All methods are called from the BDP deliberation loop (single goroutine).
type Table struct {
	entries map[Key]*Entry
}

// NewTable creates a new UDP NAT table.
func NewTable() *Table {
	return &Table{
		entries: make(map[Key]*Entry),
	}
}

// Intercept is called by the stack for UDP datagrams destined to external IPs.
// Returns true if the datagram was handled.
func (t *Table) Intercept(dg *udp.UDPDatagram) bool {
	k := makeKey(dg.SrcIP, dg.DstIP, dg.SrcPort, dg.DstPort)

	if entry, ok := t.entries[k]; ok {
		entry.egressQ = append(entry.egressQ, dg)
		entry.lastActive = time.Now()
		return true
	}

	// New entry: dial a connected UDP socket to the external destination
	addr := net.JoinHostPort(dg.DstIP.String(), fmt.Sprintf("%d", dg.DstPort))
	conn, err := net.Dial("udp", addr)
	if err != nil {
		log.Printf("UDP NAT: dial %s failed: %v", addr, err)
		return true // still "handled" — dropped
	}

	udpConn := conn.(*net.UDPConn)

	// Get raw FD for non-blocking reads
	var hostFD int
	rawConn, err := udpConn.SyscallConn()
	if err == nil {
		rawConn.Control(func(fd uintptr) {
			hostFD = int(fd)
			syscall.SetNonblock(hostFD, true)
		})
	}

	entry := &Entry{
		Key:        k,
		HostConn:   udpConn,
		hostFD:     hostFD,
		hostBuf:    make([]byte, MaxUDPPayload),
		egressQ:    []*udp.UDPDatagram{dg},
		lastActive: time.Now(),
	}
	t.entries[k] = entry

	return true
}

// Poll performs non-blocking reads from all host UDP sockets.
// Received data is queued as ingress datagrams for VM delivery.
func (t *Table) Poll() {
	for _, entry := range t.entries {
		if entry.HostConn == nil || entry.closed || entry.hostFD == 0 {
			continue
		}
		t.readHost(entry)
	}
}

// FlushEgress writes all queued VM datagrams to their host sockets.
func (t *Table) FlushEgress() {
	for _, entry := range t.entries {
		if entry.HostConn == nil || entry.closed || len(entry.egressQ) == 0 {
			continue
		}
		t.writeHost(entry)
	}
}

// DeliverToVM returns and clears accumulated ingress datagrams.
func (t *Table) DeliverToVM() []*udp.UDPDatagram {
	var all []*udp.UDPDatagram
	for _, entry := range t.entries {
		all = append(all, entry.ingressQ...)
		entry.ingressQ = nil
	}
	return all
}

// Cleanup removes closed or idle entries.
func (t *Table) Cleanup(now time.Time) {
	for key, entry := range t.entries {
		if entry.closed || now.Sub(entry.lastActive) > IdleTimeout {
			if entry.HostConn != nil {
				entry.HostConn.Close()
			}
			delete(t.entries, key)
		}
	}
}

// Count returns the number of active entries.
func (t *Table) Count() int {
	return len(t.entries)
}

// readHost reads available data from a host UDP socket (non-blocking).
func (t *Table) readHost(entry *Entry) {
	buf := entry.hostBuf
	n, err := syscall.Read(entry.hostFD, buf)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return
		}
		log.Printf("UDP NAT: host read error: %v", err)
		entry.closed = true
		return
	}
	if n == 0 {
		return // UDP can legitimately receive 0-byte datagrams, but rare
	}

	entry.lastActive = time.Now()

	// Build ingress datagram: swap src/dst for VM delivery
	payload := make([]byte, n)
	copy(payload, buf[:n])

	ingress := &udp.UDPDatagram{
		SrcIP:   net.IP(entry.Key.DstIP[:]),
		DstIP:   net.IP(entry.Key.SrcIP[:]),
		SrcPort: entry.Key.DstPort,
		DstPort: entry.Key.SrcPort,
		Payload: payload,
	}
	entry.ingressQ = append(entry.ingressQ, ingress)
}

// writeHost writes queued VM datagrams to the host socket.
func (t *Table) writeHost(entry *Entry) {
	for _, dg := range entry.egressQ {
		_, err := entry.HostConn.Write(dg.Payload)
		if err != nil {
			log.Printf("UDP NAT: host write error: %v", err)
			entry.closed = true
			return
		}
		entry.lastActive = time.Now()
	}
	entry.egressQ = nil
}
