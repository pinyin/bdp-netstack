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
	sendSize   int // bytes in SendBuf (avoids full-vs-empty ambiguity)
	RecvBuf    []byte
	recvHead   int
	recvTail   int
	recvSize   int

	// Segments received this round (pending processing)
	PendingSegs []*TCPSegment

	// Timer state
	RetransmitAt  int64 // absolute tick when retransmit fires
	RetransmitCount int  // number of consecutive retransmits (for exponential backoff)
	TimeWaitUntil int64 // absolute tick when TIME_WAIT expires

	// Last ACK sent (to avoid duplicate ACKs)
	LastAckSent uint32
	LastAckTime int64
	LastAckWin  uint16 // window advertised in last ACK, for window-update detection

	// Idle tracking
	LastActivityTick int64 // tick of last data or ACK received

	// Window scaling (RFC 1323)
	SndShift uint8 // peer's window scale (received in SYN/SYN-ACK, applied to SND_WND)
	RcvShift uint8 // our window scale (sent in SYN/SYN-ACK, applied to advertised WindowSize)

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
		LastAckWin: uint16(min(bufSize, 65535)),
	}
}

// RecvAvail returns the number of bytes available to read.
func (c *Conn) RecvAvail() int { return c.recvSize }

// RecvWritable returns how many bytes can still be written to RecvBuf.
func (c *Conn) RecvWritable() int {
	return len(c.RecvBuf) - c.recvSize
}

// scaledWindow returns the TCP header WindowSize, accounting for window scaling.
// For SYN/SYN-ACK: returns the unscaled window (cap 65535), used with Window Scale option.
// For non-SYN segments: returns the window right-shifted by RcvShift (RFC 1323).
func (c *Conn) scaledWindow(syn bool) uint16 {
	raw := c.RecvWritable()
	if c.RcvShift > 0 && !syn {
		raw = raw >> c.RcvShift
	}
	if raw > 65535 {
		raw = 65535
	}
	return uint16(raw)
}

// WriteRecvBuf writes data into the receive buffer.
func (c *Conn) WriteRecvBuf(data []byte) int {
	n := len(data)
	if n > c.RecvWritable() {
		n = c.RecvWritable()
	}
	if n == 0 {
		return 0
	}
	first := copy(c.RecvBuf[c.recvTail:], data[:min(n, len(c.RecvBuf)-c.recvTail)])
	copy(c.RecvBuf, data[first:n])
	c.recvTail = (c.recvTail + n) % len(c.RecvBuf)
	c.recvSize += n
	return n
}

// ReadRecvBuf reads data from the receive buffer (for application consumption).
func (c *Conn) ReadRecvBuf(buf []byte) int {
	n := len(buf)
	if n > c.recvSize {
		n = c.recvSize
	}
	if n == 0 {
		return 0
	}
	first := copy(buf, c.RecvBuf[c.recvHead:c.recvHead+min(n, len(c.RecvBuf)-c.recvHead)])
	copy(buf[first:n], c.RecvBuf)
	c.recvHead = (c.recvHead + n) % len(c.RecvBuf)
	c.recvSize -= n
	return n
}

// PeekRecvData returns a slice of received data without copying.
// For use by zero-copy consumers (e.g. forwarder writeHost).
// The caller must call ConsumeRecvData after consuming the data.
func (c *Conn) PeekRecvData() []byte {
	if c.recvSize == 0 {
		return nil
	}
	end := c.recvHead + c.recvSize
	if end <= len(c.RecvBuf) {
		return c.RecvBuf[c.recvHead:end]
	}
	return c.RecvBuf[c.recvHead:]
}

// ConsumeRecvData advances the read pointer by n bytes.
// Must be called after PeekRecvData.
func (c *Conn) ConsumeRecvData(n int) {
	if n <= 0 || n > c.recvSize {
		return
	}
	c.recvHead = (c.recvHead + n) % len(c.RecvBuf)
	c.recvSize -= n
}

// SendAvail returns the number of bytes available to send (data in buffer).
func (c *Conn) SendAvail() int { return c.sendSize }

// SendSpace returns the number of free bytes in the send buffer.
func (c *Conn) SendSpace() int { return len(c.SendBuf) - c.sendSize }

// WriteSendBuf writes data into the send buffer (from application).
func (c *Conn) WriteSendBuf(data []byte) int {
	space := len(c.SendBuf) - c.sendSize
	if space == 0 {
		return 0
	}
	n := len(data)
	if n > space {
		n = space
	}
	first := copy(c.SendBuf[c.sendTail:], data[:min(n, len(c.SendBuf)-c.sendTail)])
	copy(c.SendBuf, data[first:n])
	c.sendTail = (c.sendTail + n) % len(c.SendBuf)
	c.sendSize += n
	return n
}

// AckSendBuf removes acked bytes from the send buffer.
func (c *Conn) AckSendBuf(seq uint32) {
	if !seqGT(seq, c.SND_UNA) {
		return // duplicate or old ACK
	}
	acked := int(seq - c.SND_UNA)
	if acked > c.sendSize {
		acked = c.sendSize
	}
	c.sendHead = (c.sendHead + acked) % len(c.SendBuf)
	c.SND_UNA += uint32(acked)
	c.sendSize -= acked
	c.RetransmitCount = 0 // progress made, reset backoff
}

// PeekSendData returns a slice of data ready to send, limited by window.
// Skips bytes that have already been sent but not yet acknowledged
// (tracked by SND_NXT - SND_UNA).
// Returns a slice directly into SendBuf (no copy). The caller must consume
// the data before modifying SendBuf (via AckSendBuf or WriteSendBuf).
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
	start := (c.sendHead + sent) % len(c.SendBuf)
	end := start + n
	if end <= len(c.SendBuf) {
		return c.SendBuf[start:end]
	}
	// Data wraps around; return only the first contiguous piece.
	return c.SendBuf[start:]
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
	return buildSegment(tuple, seq, ack, flags, window, 0, payload)
}

// BuildSegmentWithWScale builds a TCP segment with the Window Scale option
// (RFC 1323). Only meaningful for SYN and SYN-ACK segments. Pass scale=0
// for segments that should not include the option.
func BuildSegmentWithWScale(tuple Tuple, seq, ack uint32, flags uint8, window uint16, scale uint8, payload []byte) []byte {
	return buildSegment(tuple, seq, ack, flags, window, scale, payload)
}

func buildSegment(tuple Tuple, seq, ack uint32, flags uint8, window uint16, scale uint8, payload []byte) []byte {
	hasOptions := scale > 0
	headerLen := 20
	if hasOptions {
		headerLen = 24 // 20 + 4 bytes options (WS:3 + NOP:1)
	}

	d := make([]byte, headerLen)
	binary.BigEndian.PutUint16(d[0:2], tuple.SrcPort)
	binary.BigEndian.PutUint16(d[2:4], tuple.DstPort)
	binary.BigEndian.PutUint32(d[4:8], seq)
	binary.BigEndian.PutUint32(d[8:12], ack)
	d[12] = uint8(headerLen/4) << 4 // DataOffset in 4-byte words
	d[13] = flags
	binary.BigEndian.PutUint16(d[14:16], window)
	binary.BigEndian.PutUint16(d[16:18], 0) // checksum placeholder
	binary.BigEndian.PutUint16(d[18:20], 0) // urgent pointer

	if hasOptions {
		d[20] = 3  // Kind: Window Scale
		d[21] = 3  // Length: 3
		d[22] = scale
		d[23] = 1  // NOP (align to 4-byte boundary)
	}

	if len(payload) > 0 {
		result := make([]byte, headerLen+len(payload))
		copy(result[:headerLen], d)
		copy(result[headerLen:], payload)
		return result
	}
	return d
}

// ParseWindowScale extracts the window scale factor from TCP options in a
// SYN or SYN-ACK segment. Returns 0 if not present or data is too short.
func ParseWindowScale(data []byte) uint8 {
	if len(data) < 20 {
		return 0
	}
	dataOffset := (data[12] >> 4) * 4
	if dataOffset <= 20 {
		return 0
	}
	options := data[20:dataOffset]
	for i := 0; i < len(options); {
		if options[i] == 0 { // End of Option List
			break
		}
		if options[i] == 1 { // NOP
			i++
			continue
		}
		if i+1 >= len(options) {
			break
		}
		kind := options[i]
		length := options[i+1]
		if length < 2 || i+int(length) > len(options) {
			break
		}
		if kind == 3 && length == 3 {
			return options[i+2]
		}
		i += int(length)
	}
	return 0
}

// ============================================================================
// Checksum computation for TCP pseudo-header
// ============================================================================

// Sequence number comparison helpers (RFC 1323: (int32)(a-b) < 0)
// These correctly handle 32-bit sequence number wraparound after ~4GB of data.
func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }
func seqGT(a, b uint32) bool { return int32(a-b) > 0 }
func seqGE(a, b uint32) bool { return int32(a-b) >= 0 }

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
