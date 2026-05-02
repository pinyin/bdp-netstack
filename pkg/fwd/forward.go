// Package fwd implements TCP port forwarding from host ports to VM ports.
// Uses the same non-blocking I/O model as NAT to fit the BDP deliberation loop.
package fwd

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/debug"
	"github.com/pinyin/bdp-netstack/pkg/tcp"
)

// Entry represents one active forwarded connection.
type Entry struct {
	HostConn      net.Conn
	hostFD        int
	VMConn        *tcp.Conn
	VMAddr        string // "ip:port" for logging
	hostBuf       []byte // pre-allocated read buffer
	HostClosed    bool
	VMClosed      bool
	deferredClose bool // host EOF seen but send buffer not yet drained
}

// Forwarder manages all port forwarding listeners and active connections.
type Forwarder struct {
	gatewayIP net.IP
	mappings  map[uint16]Mapping   // hostPort → mapping
	listeners map[uint16]net.Listener
	entries   map[int]*Entry
	nextPort  uint32 // atomic counter for unique ephemeral source ports
	tcpState  *tcp.TCPState

	mu sync.Mutex
}

func (f *Forwarder) Listeners() map[uint16]net.Listener { return f.listeners }
func (f *Forwarder) Entries() map[int]*Entry             { return f.entries }

// Mapping defines a single port forwarding rule.
type Mapping struct {
	HostPort uint16
	VMIP     net.IP
	VMPort   uint16
}

// New creates a new forwarder.
func New(gatewayIP net.IP, mappings []Mapping) (*Forwarder, error) {
	f := &Forwarder{
		gatewayIP: gatewayIP,
		mappings:  make(map[uint16]Mapping),
		listeners: make(map[uint16]net.Listener),
		entries:   make(map[int]*Entry),
	}

	for _, m := range mappings {
		f.mappings[m.HostPort] = m

		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", m.HostPort))
		if err != nil {
			return nil, fmt.Errorf("listen :%d: %w", m.HostPort, err)
		}
		f.listeners[m.HostPort] = ln
		log.Printf("Forwarder: :%d → %s:%d", m.HostPort, m.VMIP, m.VMPort)
	}

	return f, nil
}

// PollAccept checks all listeners for new connections (non-blocking).
// Called during the deliberation phase.
func (f *Forwarder) PollAccept(tcpState *tcp.TCPState) {
	f.tcpState = tcpState
	for hostPort, ln := range f.listeners {
		for {
			if tl, ok := ln.(*net.TCPListener); ok {
				tl.SetDeadline(time.Now().Add(time.Millisecond))
			}
			conn, err := ln.Accept()
			if err != nil {
				if isEAGAIN(err) || isTimeout(err) {
					break
				}
				log.Printf("Forwarder: accept error on :%d: %v", hostPort, err)
				break
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

			vmTuple, vmAddr := f.createVMTuple(hostPort)
			if vmTuple == nil {
				conn.Close()
				continue
			}

			vmConn := tcpState.ActiveOpen(*vmTuple, 65535)
			f.entries[fd] = &Entry{
				HostConn: conn,
				hostFD:   fd,
				VMConn:   vmConn,
				VMAddr:   vmAddr,
				hostBuf:  make([]byte, 262144),
			}

			log.Printf("Forwarder: new connection :%d → %s", hostPort, vmAddr)
		}
	}
}

// Poll reads from host connections and writes to VM send buffers.
// Called during the deliberation phase, before TCP deliberation.
func (f *Forwarder) Poll() {
	for _, entry := range f.entries {
		if entry.hostFD == 0 {
			continue
		}
		if entry.HostClosed {
			// Deferred close: host EOF was seen but data remains in send buffer.
			// Wait until TCP deliberation drains it before calling AppClose.
			if entry.deferredClose && entry.VMConn != nil && entry.VMConn.SendAvail() == 0 {
				entry.deferredClose = false
				if f.tcpState != nil {
					f.tcpState.AppClose(entry.VMConn.Tuple)
				}
			}
			// Retry AppClose for connections where the first attempt was
			// silently ignored (e.g., connection was in SynSent at the
			// time and the handshake completed later). AppClose is
			// idempotent: once Established/CloseWait, the close proceeds.
			if !entry.deferredClose && !entry.VMClosed && entry.VMConn != nil && f.tcpState != nil {
				f.tcpState.AppClose(entry.VMConn.Tuple)
			}
			continue
		}
		f.readHost(entry)
	}
}

// ProxyVMToHost reads from VM receive buffers and writes to host connections.
// Called after TCP deliberation.
func (f *Forwarder) ProxyVMToHost() {
	for _, entry := range f.entries {
		if entry.HostClosed || entry.VMConn == nil {
			continue
		}
		f.writeHost(entry)
	}
}

// Cleanup removes closed entries.
func (f *Forwarder) Cleanup() {
	for fd, entry := range f.entries {
		// Derive VMClosed from the TCP connection state:
		// - FinReceived means the VM has sent FIN to us
		// - If VMConn is nil, the connection was never fully established
		// - If connection was removed from all TCP states (e.g., AppClose
		//   removed it from SynSent/SynRcvd), treat as VMClosed.
		if !entry.VMClosed && entry.VMConn != nil && entry.VMConn.FinReceived {
			entry.VMClosed = true
		}
		if !entry.VMClosed && entry.VMConn != nil && entry.HostClosed && f.tcpState != nil {
			if !f.tcpState.HasConn(entry.VMConn.Tuple) {
				entry.VMClosed = true
			}
		}
		if entry.HostClosed && entry.VMClosed {
			if entry.HostConn != nil {
				entry.HostConn.Close()
			}
			delete(f.entries, fd)
		}
	}
}

// Mappings returns the configured port mappings (for the stack layer).
// This is needed for stack to set up ARP entries for VM IPs.
func (f *Forwarder) VMTargets() []net.IP {
	seen := make(map[string]bool)
	var ips []net.IP
	for _, entry := range f.entries {
		key := entry.VMAddr
		if !seen[key] {
			seen[key] = true
			// IP is embedded in VMAddr "ip:port"
			host, _, _ := net.SplitHostPort(entry.VMAddr)
			if ip := net.ParseIP(host); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// Count returns the number of active forwarded connections.
func (f *Forwarder) Count() int {
	return len(f.entries)
}

// createVMTuple builds the TCP tuple for the VM-side connection.
func (f *Forwarder) createVMTuple(hostPort uint16) (*tcp.Tuple, string) {
	m, ok := f.mappings[hostPort]
	if !ok {
		return nil, ""
	}
	// Unique ephemeral source port per connection to avoid tuple collisions
	p := atomic.AddUint32(&f.nextPort, 1)
	gwPort := uint16(32768 + (p % 28231)) // 32768..60999, wraps safely
	vmAddr := net.JoinHostPort(m.VMIP.String(), fmt.Sprintf("%d", m.VMPort))
	tuple := tcp.NewTuple(f.gatewayIP, m.VMIP, gwPort, m.VMPort)
	return &tuple, vmAddr
}

// readHost reads from host connection into VM send buffer (non-blocking).
// Respects send buffer capacity to avoid silently truncating data.
func (f *Forwarder) readHost(entry *Entry) {
	if entry.VMConn == nil {
		return
	}

	debug.Global.FwdReadCalls.Add(1)

	// Don't read if the VM send buffer is full — let host socket buffer
	// absorb backpressure naturally.
	space := entry.VMConn.SendSpace()
	if space == 0 {
		debug.Global.FwdBufFull.Add(1)
		return
	}

	buf := entry.hostBuf
	if space < len(buf) {
		buf = buf[:space]
	}
	n, err := syscall.Read(entry.hostFD, buf)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			debug.Global.FwdReadEAGAIN.Add(1)
			return
		}
		log.Printf("Forwarder: host read error: %v", err)
		entry.HostClosed = true
		f.maybeClose(entry)
		return
	}
	if n == 0 {
		log.Printf("Forwarder: host EOF on %s (fd=%d)", entry.VMAddr, entry.hostFD)
		entry.HostClosed = true
		f.maybeClose(entry)
		return
	}

	debug.Global.FwdReadBytes.Add(int64(n))
	written := entry.VMConn.WriteSendBuf(buf[:n])
	debug.Global.FwdBufBytes.Add(int64(written))
}

// maybeClose defers AppClose if the send buffer still has unsent data,
// preventing data loss when the host closes before all data is delivered.
func (f *Forwarder) maybeClose(entry *Entry) {
	if entry.VMConn != nil && entry.VMConn.SendAvail() > 0 {
		entry.deferredClose = true
		return
	}
	if f.tcpState != nil && entry.VMConn != nil {
		f.tcpState.AppClose(entry.VMConn.Tuple)
	}
}

// writeHost writes from VM receive buffer to host connection.
// Uses PeekRecvData/ConsumeRecvData for zero-copy from RecvBuf.
func (f *Forwarder) writeHost(entry *Entry) {
	data := entry.VMConn.PeekRecvData()
	if len(data) == 0 {
		return
	}

	n, err := entry.HostConn.Write(data)
	if n > 0 {
		entry.VMConn.ConsumeRecvData(n)
	}
	if err != nil {
		log.Printf("Forwarder: host write error: %v", err)
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
				log.Printf("Forwarder: host write error (wrapped): %v", err2)
				entry.HostClosed = true
			}
		}
	}
}

func isEAGAIN(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Err == syscall.EAGAIN || opErr.Err == syscall.EWOULDBLOCK
	}
	return false
}

func isTimeout(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Timeout()
	}
	if osErr, ok := err.(*os.SyscallError); ok {
		return osErr.Err == syscall.EAGAIN
	}
	return false
}
