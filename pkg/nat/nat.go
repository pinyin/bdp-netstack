// Package nat implements outbound NAT / conntrack for BDP netstack.
// It intercepts VM TCP SYNs to external IPs and proxies data through
// host TCP connections using a BDP-compatible non-blocking I/O model.
package nat

import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"

	"github.com/pinyin/bdp-netstack/pkg/tcp"
)

// Entry represents one NATed connection.
type Entry struct {
	Key     tcp.Tuple // VM-side tuple (VM_IP:VM_Port → Ext_IP:Ext_Port)
	ExtIP   net.IP
	ExtPort uint16

	// Host-side TCP connection
	HostConn net.Conn
	hostFD   int
	hostBuf  []byte

	// Pointer to the TCP connection in our stack (VM-facing side)
	VMConn *tcp.Conn

	// Closed flags
	HostClosed bool
	VMClosed   bool
}

// Table is the connection tracking table. All methods are called from
// the same goroutine (BDP deliberation loop), so no locking is needed
// for the entries map. However, host I/O uses a sync.Mutex for the
// non-blocking reads from the same goroutine.
type Table struct {
	entries map[tcp.Tuple]*Entry

	// Pending SYNs intercepted this round: need host dial responses
	pendingDials []*pendingDial

	mu sync.Mutex // protects host I/O edge cases
}

type pendingDial struct {
	Entry *Entry
	Seg   *tcp.TCPSegment
}

// NewTable creates a new NAT connection tracking table.
func NewTable() *Table {
	return &Table{
		entries: make(map[tcp.Tuple]*Entry),
	}
}

// Intercept is called by the stack for TCP segments destined to external IPs.
// Returns true if the segment was handled by NAT.
func (t *Table) Intercept(seg *tcp.TCPSegment, tcpState *tcp.TCPState) bool {
	tuple := seg.Tuple.Reverse() // normalize to VM→Ext direction

	// Existing connection?
	if entry, ok := t.entries[tuple]; ok {
		// Inject the segment into our TCP stack for the VM-facing connection
		entry.VMConn.PendingSegs = append(entry.VMConn.PendingSegs, seg)
		return true
	}

	// New SYN?
	if seg.Header.IsSYN() && !seg.Header.IsACK() {
		entry := &Entry{
			Key:     tuple,
			ExtIP:   seg.Tuple.DstIPNet(),
			ExtPort: seg.Tuple.DstPort,
			hostBuf: make([]byte, 65536),
		}

		// Create the VM-facing TCP connection in our stack
		entry.VMConn = tcpState.CreateExternalConn(tuple, seg.Header.SeqNum, seg.Header.WindowSize)

		t.entries[tuple] = entry

		// Queue host dial (done synchronously in Poll to fit BDP model)
		t.pendingDials = append(t.pendingDials, &pendingDial{
			Entry: entry,
			Seg:   seg,
		})

		return true
	}

	return false
}

// Poll performs non-blocking I/O on all host connections.
// Called during the deliberation phase.
func (t *Table) Poll() {
	// Process pending dials
	for _, pd := range t.pendingDials {
		t.doDial(pd)
	}
	t.pendingDials = nil

	// Non-blocking read from all host connections
	for _, entry := range t.entries {
		if entry.HostConn == nil || entry.HostClosed {
			continue
		}
		t.readHost(entry)
	}
}

// ProxyVMToHost copies data from VM receive buffers to host connections.
// Called after TCP deliberation.
func (t *Table) ProxyVMToHost() {
	for _, entry := range t.entries {
		if entry.HostConn == nil || entry.HostClosed || entry.VMConn == nil {
			continue
		}
		t.writeHost(entry)
	}
}

// Cleanup removes closed entries.
func (t *Table) Cleanup() {
	for key, entry := range t.entries {
		// Derive VMClosed from TCP connection state
		if !entry.VMClosed && entry.VMConn != nil && entry.VMConn.FinReceived {
			entry.VMClosed = true
		}
		if entry.HostClosed && entry.VMClosed {
			if entry.HostConn != nil {
				entry.HostConn.Close()
			}
			delete(t.entries, key)
		}
	}
}

// doDial initiates a host TCP connection.
func (t *Table) doDial(pd *pendingDial) {
	entry := pd.Entry
	addr := net.JoinHostPort(entry.ExtIP.String(), fmt.Sprintf("%d", entry.ExtPort))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("NAT: dial %s failed: %v", addr, err)
		// Send RST to VM through the TCP stack
		entry.VMClosed = true
		return
	}

	entry.HostConn = conn

	// Set non-blocking for BDP integration
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		rawConn, err := tcpConn.SyscallConn()
		if err == nil {
			rawConn.Control(func(fd uintptr) {
				entry.hostFD = int(fd)
				syscall.SetNonblock(entry.hostFD, true)
			})
		}
	}
}

// readHost reads available data from a host connection (non-blocking).
func (t *Table) readHost(entry *Entry) {
	if entry.hostFD == 0 {
		return
	}

	buf := entry.hostBuf
	n, err := syscall.Read(entry.hostFD, buf)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return // no data available
		}
		log.Printf("NAT: host read error: %v", err)
		entry.HostClosed = true
		if entry.VMConn != nil {
			entry.VMConn.FinReceived = true
			entry.VMConn.FinSeq = entry.VMConn.RCV_NXT
		}
		return
	}
	if n == 0 {
		entry.HostClosed = true
		if entry.VMConn != nil {
			entry.VMConn.FinReceived = true
			entry.VMConn.FinSeq = entry.VMConn.RCV_NXT
		}
		return
	}

	// Write data to VM-side connection's send buffer
	if entry.VMConn != nil {
		entry.VMConn.WriteSendBuf(buf[:n])
	}
}

// writeHost writes data from VM receive buffer to host connection.
func (t *Table) writeHost(entry *Entry) {
	buf := entry.hostBuf
	n := entry.VMConn.ReadRecvBuf(buf)
	if n == 0 {
		return
	}

	_, err := entry.HostConn.Write(buf[:n])
	if err != nil {
		log.Printf("NAT: host write error: %v", err)
		entry.HostClosed = true
	}
}

// Count returns the number of active NAT entries.
func (t *Table) Count() int {
	return len(t.entries)
}
