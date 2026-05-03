// Package nat implements outbound NAT / conntrack for BDP netstack.
// It intercepts VM TCP SYNs to external IPs and proxies data through
// host TCP connections using a BDP-compatible non-blocking I/O model.
package nat

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/debug"
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

	// Pointer to the TCP connection in our stack (VM-facing side)
	VMConn *tcp.Conn

	// Closed flags
	HostClosed    bool
	VMClosed      bool
	deferredClose bool // host EOF seen but send buffer not yet drained
}

// Table is the connection tracking table. All methods are called from
// the same goroutine (BDP deliberation loop), so no locking is needed.
type Table struct {
	entries map[tcp.Tuple]*Entry

	// Pending SYNs intercepted this round: need host dial responses
	pendingDials []*pendingDial

	tcpState *tcp.TCPState // set during Intercept, used for AppClose
	hostBuf  []byte        // shared read buffer, reused across all entries
}

type dialResult struct {
	conn net.Conn
	fd   int
	err  error
}

type pendingDial struct {
	Entry   *Entry
	Seg     *tcp.TCPSegment
	result  chan dialResult // receives dial result from async goroutine
}

// NewTable creates a new NAT connection tracking table.
func NewTable() *Table {
	return &Table{
		entries: make(map[tcp.Tuple]*Entry),
		hostBuf: make([]byte, 262144),
	}
}

// Intercept is called by the stack for TCP segments destined to external IPs.
// Returns true if the segment was handled by NAT.
func (t *Table) Intercept(seg *tcp.TCPSegment, tcpState *tcp.TCPState) bool {
	t.tcpState = tcpState
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
		}

		// Create the VM-facing TCP connection in our stack
		entry.VMConn = tcpState.CreateExternalConn(tuple, seg.Header.SeqNum, seg.Header.WindowSize, seg.Raw)

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

// PollDials processes pending host dials. Dials are started asynchronously
// to avoid blocking the BDP deliberation loop on remote TCP connects.
// Completed dial results are received via a channel and applied in the
// deliberation goroutine, avoiding data races on entry fields.
func (t *Table) PollDials() {
	var remaining []*pendingDial
	for _, pd := range t.pendingDials {
		if pd.result == nil {
			// Start a new async dial
			t.doDial(pd)
		}
		// Check if dial has completed
		select {
		case result := <-pd.result:
			if result.err != nil {
				log.Printf("NAT: dial %s failed: %v",
					net.JoinHostPort(pd.Entry.ExtIP.String(), fmt.Sprintf("%d", pd.Entry.ExtPort)),
					result.err)
				pd.Entry.VMClosed = true
			} else {
				pd.Entry.HostConn = result.conn
				pd.Entry.hostFD = result.fd
			}
		default:
			remaining = append(remaining, pd)
		}
	}
	t.pendingDials = remaining
}

// PollReads performs non-blocking reads from all host connections.
// Called AFTER TCP deliberation so VM ACKs have freed SendBuf space.
func (t *Table) PollReads() {
	for _, entry := range t.entries {
		if entry.HostConn == nil {
			continue
		}
		if entry.HostClosed {
			if entry.deferredClose && entry.VMConn != nil && entry.VMConn.SendAvail() == 0 {
				entry.deferredClose = false
				if t.tcpState != nil {
					t.tcpState.AppClose(entry.VMConn.Tuple)
				}
			}
			continue
		}
		t.readHost(entry)
	}
}

// Deprecated: Poll is kept for backward compatibility with tests.
// Use PollDials + PollReads instead.
func (t *Table) Poll() {
	t.PollDials()
	t.PollReads()
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
		if !entry.VMClosed && entry.VMConn != nil && entry.VMConn.IsFinReceived() {
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

// doDial starts an asynchronous host TCP connection.
// Results are sent via the result channel and applied by PollDials in the
// deliberation goroutine, avoiding data races on entry fields.
func (t *Table) doDial(pd *pendingDial) {
	pd.result = make(chan dialResult, 1)
	addr := net.JoinHostPort(pd.Entry.ExtIP.String(), fmt.Sprintf("%d", pd.Entry.ExtPort))

	go func() {
		conn, err := net.DialTimeout("tcp", addr, 30*time.Second)
		if err != nil {
			pd.result <- dialResult{err: err}
			return
		}

		fd := 0
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			rawConn, err := tcpConn.SyscallConn()
			if err == nil {
				rawConn.Control(func(f uintptr) {
					fd = int(f)
					syscall.SetNonblock(fd, true)
				})
			}
		}

		pd.result <- dialResult{conn: conn, fd: fd}
	}()
}

// readHost reads available data from a host connection (non-blocking).
// Respects send buffer capacity to avoid silently truncating data.
func (t *Table) readHost(entry *Entry) {
	if entry.hostFD == 0 || entry.VMConn == nil {
		return
	}

	debug.Global.FwdReadCalls.Add(1)

	// Don't read if the VM send buffer is full — backpressure via host socket buffer.
	space := entry.VMConn.SendSpace()
	if space == 0 {
		debug.Global.FwdBufFull.Add(1)
		return
	}

	buf := t.hostBuf
	if space < len(buf) {
		buf = buf[:space]
	}
	n, err := syscall.Read(entry.hostFD, buf)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			debug.Global.FwdReadEAGAIN.Add(1)
			return // no data available
		}
		log.Printf("NAT: host read error: %v", err)
		entry.HostClosed = true
		t.maybeClose(entry)
		return
	}
	if n == 0 {
		entry.HostClosed = true
		t.maybeClose(entry)
		return
	}

	// Write data to VM-side connection's send buffer
	debug.Global.FwdReadBytes.Add(int64(n))
	written := entry.VMConn.WriteSendBuf(buf[:n])
	debug.Global.FwdBufBytes.Add(int64(written))
}

// maybeClose defers AppClose if the send buffer still has unsent data,
// preventing data loss when the host closes before all data is delivered.
func (t *Table) maybeClose(entry *Entry) {
	if entry.VMConn != nil && entry.VMConn.SendAvail() > 0 {
		entry.deferredClose = true
		return
	}
	if t.tcpState != nil && entry.VMConn != nil {
		t.tcpState.AppClose(entry.VMConn.Tuple)
	}
}

// writeHost writes data from VM receive buffer to host connection.
// Uses PeekRecvData/ConsumeRecvData for zero-copy from RecvBuf.
func (t *Table) writeHost(entry *Entry) {
	data := entry.VMConn.PeekRecvData()
	if len(data) == 0 {
		return
	}

	n, err := entry.HostConn.Write(data)
	if n > 0 {
		entry.VMConn.ConsumeRecvData(n)
	}
	if err != nil {
		log.Printf("NAT: host write error: %v", err)
		entry.HostClosed = true
		return
	}
	// If data wrapped around the circular buffer, drain the remaining piece
	if n == len(data) && entry.VMConn.RecvAvail() > 0 {
		more := entry.VMConn.PeekRecvData()
		if len(more) > 0 {
			n2, err2 := entry.HostConn.Write(more)
			if n2 > 0 {
				entry.VMConn.ConsumeRecvData(n2)
			}
			if err2 != nil {
				log.Printf("NAT: host write error (wrapped): %v", err2)
				entry.HostClosed = true
			}
		}
	}
}

// Count returns the number of active NAT entries.
func (t *Table) Count() int {
	return len(t.entries)
}
