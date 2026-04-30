// Package tcp implements a BDP-style TCP state machine.
// Connections are organized by state into indexed collections;
// a single Deliberate() call batch-processes all connections.
package tcp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ============================================================================
// Protocol constants
// ============================================================================

const (
	FlagFIN uint8 = 1 << iota
	FlagSYN
	FlagRST
	FlagPSH
	FlagACK
	FlagURG
)

// ============================================================================
// Tuple uniquely identifies a TCP connection (4-tuple).
// ============================================================================

type Tuple struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

func IPToArray(ip net.IP) [4]byte {
	var a [4]byte
	ip4 := ip.To4()
	if ip4 != nil {
		copy(a[:], ip4)
	}
	return a
}

func (t Tuple) SrcIPNet() net.IP { return net.IP(t.SrcIP[:]) }
func (t Tuple) DstIPNet() net.IP { return net.IP(t.DstIP[:]) }

func NewTuple(srcIP, dstIP net.IP, srcPort, dstPort uint16) Tuple {
	return Tuple{
		SrcIP:   IPToArray(srcIP),
		DstIP:   IPToArray(dstIP),
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

func (t Tuple) Reverse() Tuple {
	return Tuple{
		SrcIP:   t.DstIP,
		DstIP:   t.SrcIP,
		SrcPort: t.DstPort,
		DstPort: t.SrcPort,
	}
}

func (t Tuple) String() string {
	return fmt.Sprintf("%s:%d→%s:%d", t.SrcIPNet(), t.SrcPort, t.DstIPNet(), t.DstPort)
}

// ============================================================================
// TCPHeader and Segment
// ============================================================================

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      uint8
	WindowSize uint16
	Checksum   uint16
	UrgentPtr  uint16
}

func (h *TCPHeader) HasFlag(f uint8) bool { return h.Flags&f != 0 }
func (h *TCPHeader) IsSYN() bool           { return h.HasFlag(FlagSYN) }
func (h *TCPHeader) IsACK() bool           { return h.HasFlag(FlagACK) }
func (h *TCPHeader) IsFIN() bool           { return h.HasFlag(FlagFIN) }
func (h *TCPHeader) IsRST() bool           { return h.HasFlag(FlagRST) }

type TCPSegment struct {
	Header  *TCPHeader
	Payload []byte
	Tuple   Tuple // derived from IP header + TCP header
	Raw     []byte // original bytes (for checksum validation)
}

// ParseTCPHeader parses a TCP header from raw bytes.
func ParseTCPHeader(data []byte) (*TCPHeader, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("TCP header too short: %d", len(data))
	}
	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: (data[12] >> 4) * 4,
		Flags:      data[13],
		WindowSize: binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
	}, nil
}

// ParseSegment parses a TCP segment from an IP payload.
func ParseSegment(data []byte, srcIP, dstIP net.IP) (*TCPSegment, error) {
	h, err := ParseTCPHeader(data)
	if err != nil {
		return nil, err
	}
	offset := int(h.DataOffset)
	if offset > len(data) {
		offset = len(data)
	}
	return &TCPSegment{
		Header:  h,
		Payload: data[offset:],
		Tuple:   NewTuple(srcIP, dstIP, h.SrcPort, h.DstPort),
		Raw:     data,
	}, nil
}

// Marshal serializes a TCP header to bytes.
func (h *TCPHeader) Marshal() []byte {
	d := make([]byte, 20)
	binary.BigEndian.PutUint16(d[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(d[2:4], h.DstPort)
	binary.BigEndian.PutUint32(d[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(d[8:12], h.AckNum)
	d[12] = (5 << 4) // DataOffset = 5 (20 bytes)
	d[13] = h.Flags
	binary.BigEndian.PutUint16(d[14:16], h.WindowSize)
	binary.BigEndian.PutUint16(d[16:18], 0) // checksum placeholder
	binary.BigEndian.PutUint16(d[18:20], h.UrgentPtr)
	return d
}

// ============================================================================
// Conn: TCP connection state (NO State field!)
// State is encoded by which collection the Conn is in.
// ============================================================================

type Conn struct {
	Tuple Tuple

	// Sequence space
	ISS     uint32
	IRS     uint32
	SND_NXT uint32
	SND_UNA uint32
	RCV_NXT uint32
	SND_WND uint32
	RCV_WND uint32
	Window  uint16 // window to advertise to peer

	// Data buffers
	SendBuf    []byte
	sendHead   int
	sendTail   int
	RecvBuf    []byte
	recvHead   int
	recvTail   int
	recvSize   int

	// Segments received this round (pending processing)
	PendingSegs []*TCPSegment

	// Timer state
	RetransmitAt  int64 // absolute tick when retransmit fires
	TimeWaitUntil int64 // absolute tick when TIME_WAIT expires

	// Delayed ACK
	DataRcvdThisRound bool // new data arrived this round — defer ACK by one round

	// Last ACK sent (to avoid duplicate ACKs)
	LastAckSent uint32
	LastAckTime int64

	// Idle tracking
	LastActivityTick int64 // tick of last data or ACK received

	// Close tracking
	FinSent     bool
	FinReceived bool
	FinSeq      uint32
}

// NewConn creates a connection in the SYN_RCVD state (just received SYN).
func NewConn(tuple Tuple, irs uint32, iss uint32, window uint16, bufSize int) *Conn {
	if bufSize == 0 {
		bufSize = 64 * 1024
	}
	return &Conn{
		Tuple:      tuple,
		ISS:        iss,
		IRS:        irs,
		SND_NXT:    iss,
		SND_UNA:    iss,
		RCV_NXT:    irs + 1,
		SND_WND:    65535,
		RCV_WND:    65535,
		Window:     window,
		SendBuf:    make([]byte, bufSize),
		RecvBuf:    make([]byte, bufSize),
	}
}

// RecvAvail returns the number of bytes available to read.
func (c *Conn) RecvAvail() int { return c.recvSize }

// RecvWritable returns how many bytes can still be written to RecvBuf.
// Capped at 65535 (max TCP window size) to prevent uint16 truncation to zero.
func (c *Conn) RecvWritable() int {
	n := len(c.RecvBuf) - c.recvSize
	if n > 65535 {
		n = 65535
	}
	return n
}

// WriteRecvBuf writes data into the receive buffer.
func (c *Conn) WriteRecvBuf(data []byte) int {
	n := len(data)
	if n > c.RecvWritable() {
		n = c.RecvWritable()
	}
	for i := 0; i < n; i++ {
		c.RecvBuf[c.recvTail] = data[i]
		c.recvTail = (c.recvTail + 1) % len(c.RecvBuf)
	}
	c.recvSize += n
	return n
}

// ReadRecvBuf reads data from the receive buffer (for application consumption).
func (c *Conn) ReadRecvBuf(buf []byte) int {
	n := len(buf)
	if n > c.recvSize {
		n = c.recvSize
	}
	for i := 0; i < n; i++ {
		buf[i] = c.RecvBuf[c.recvHead]
		c.recvHead = (c.recvHead + 1) % len(c.RecvBuf)
	}
	c.recvSize -= n
	return n
}

// SendAvail returns the number of bytes available to send.
func (c *Conn) SendAvail() int {
	if c.sendTail >= c.sendHead {
		return c.sendTail - c.sendHead
	}
	return len(c.SendBuf) - c.sendHead + c.sendTail
}

// WriteSendBuf writes data into the send buffer (from application).
func (c *Conn) WriteSendBuf(data []byte) int {
	avail := len(c.SendBuf) - c.SendAvail()
	if avail == 0 {
		return 0
	}
	n := len(data)
	if n > avail {
		n = avail
	}
	for i := 0; i < n; i++ {
		c.SendBuf[c.sendTail] = data[i]
		c.sendTail = (c.sendTail + 1) % len(c.SendBuf)
	}
	return n
}

// AckSendBuf removes acked bytes from the send buffer.
func (c *Conn) AckSendBuf(seq uint32) {
	if seq <= c.SND_UNA {
		return // duplicate or old ACK
	}
	for c.SND_UNA != seq && c.SendAvail() > 0 {
		c.sendHead = (c.sendHead + 1) % len(c.SendBuf)
		c.SND_UNA++
	}
}

// PeekSendData returns a slice of data ready to send, limited by window.
// Skips bytes that have already been sent but not yet acknowledged
// (tracked by SND_NXT - SND_UNA).
func (c *Conn) PeekSendData(max int) []byte {
	avail := c.SendAvail()
	sent := int(c.SND_NXT - c.SND_UNA)
	if sent >= avail {
		return nil // all buffered data has been sent (awaiting ACK)
	}
	avail -= sent
	if avail == 0 || max == 0 {
		return nil
	}
	n := avail
	if n > max {
		n = max
	}
	data := make([]byte, n)
	start := (c.sendHead + sent) % len(c.SendBuf)
	for i := 0; i < n; i++ {
		data[i] = c.SendBuf[(start+i)%len(c.SendBuf)]
	}
	return data
}

// Server API types

type ListenCallback func(conn *Conn)

type AppData struct {
	Conn *Conn
	Data []byte
}

// ============================================================================
// Helper: Build a TCP segment
// ============================================================================

func BuildSegment(tuple Tuple, seq, ack uint32, flags uint8, window uint16, payload []byte) []byte {
	h := &TCPHeader{
		SrcPort:    tuple.DstPort, // response: swap src/dst
		DstPort:    tuple.SrcPort,
		SeqNum:     seq,
		AckNum:     ack,
		Flags:      flags,
		WindowSize: window,
	}
	headerBytes := h.Marshal()
	if len(payload) > 0 {
		result := make([]byte, 20+len(payload))
		copy(result[:20], headerBytes)
		copy(result[20:], payload)
		return result
	}
	return headerBytes
}

// ============================================================================
// Checksum computation for TCP pseudo-header
// ============================================================================

func TCPChecksum(srcIP, dstIP net.IP, tcpData []byte) uint16 {
	pseudoHdr := make([]byte, 12)
	copy(pseudoHdr[0:4], srcIP.To4())
	copy(pseudoHdr[4:8], dstIP.To4())
	pseudoHdr[8] = 0
	pseudoHdr[9] = 6 // TCP protocol number
	tcpLen := uint16(len(tcpData))
	binary.BigEndian.PutUint16(pseudoHdr[10:12], tcpLen)

	sum := uint32(0)
	allData := append(pseudoHdr, tcpData...)
	for i := 0; i < len(allData)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(allData[i:]))
	}
	if len(allData)%2 == 1 {
		sum += uint32(allData[len(allData)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
