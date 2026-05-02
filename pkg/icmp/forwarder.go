// Package icmp implements ICMP Echo forwarding from VM to external hosts.
// Uses non-privileged ICMP (SOCK_DGRAM + IPPROTO_ICMP) available on macOS 10.7+
// and Linux with net.ipv4.ping_group_range configured.
package icmp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	xipv4 "golang.org/x/net/ipv4"
)

// Reply represents an ICMP Echo Reply ready to deliver to the VM.
type Reply struct {
	SrcIP   net.IP // external IP that replied
	DstIP   net.IP // VM IP to deliver reply to
	ID      uint16
	Seq     uint16
	Payload []byte
}

// pending tracks an outstanding echo request.
type pending struct {
	srcIP     net.IP
	dstIP     net.IP
	id        uint16
	seq       uint16
	createdAt time.Time
}

// Forwarder proxies ICMP Echo Requests from VM guests to external hosts
// and returns Echo Replies. All methods are designed to be called from
// the BDP deliberation loop.
type Forwarder struct {
	conn    *icmp.PacketConn
	rawConn *xipv4.PacketConn
	pending map[uint32]*pending // key: (id<<16)|seq
	replies []Reply
}

func key(id, seq uint16) uint32 {
	return uint32(id)<<16 | uint32(seq)
}

// New creates a new ICMP forwarder. Uses udp4 protocol for non-privileged ICMP.
func New() (*Forwarder, error) {
	conn, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("icmp listen: %w", err)
	}

	// Set short read deadline for non-blocking behavior
	rawConn := conn.IPv4PacketConn()
	rawConn.SetReadDeadline(time.Now().Add(time.Millisecond))

	return &Forwarder{
		conn:    conn,
		rawConn: rawConn,
		pending: make(map[uint32]*pending),
	}, nil
}

// Forward sends an ICMP Echo Request from the VM to an external host.
// srcIP is the VM's IP, dstIP is the external target.
func (f *Forwarder) Forward(srcIP, dstIP net.IP, id, seq uint16, payload []byte) error {
	msg := icmp.Message{
		Type: xipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(id),
			Seq:  int(seq),
			Data: payload,
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("marshal icmp: %w", err)
	}

	k := key(id, seq)
	f.pending[k] = &pending{
		srcIP:     srcIP,
		dstIP:     dstIP,
		id:        id,
		seq:       seq,
		createdAt: time.Now(),
	}

	dst := &net.UDPAddr{IP: dstIP}
	_, err = f.conn.WriteTo(b, dst)
	if err != nil {
		delete(f.pending, k)
		return fmt.Errorf("write icmp: %w", err)
	}

	return nil
}

// Poll reads available ICMP replies (non-blocking). Called during deliberation.
func (f *Forwarder) Poll() {
	// Reset read deadline for this round. The deadline is an absolute time;
	// without this reset, a past deadline causes every ReadFrom to return
	// immediately with a timeout, making the forwarder non-functional.
	f.rawConn.SetReadDeadline(time.Now().Add(time.Millisecond))

	buf := make([]byte, 1500)
	for {
		n, _, peer, err := f.rawConn.ReadFrom(buf)
		if err != nil {
			if isEAGAIN(err) {
				return
			}
			// Deadline exceeded also means no data — silently return
			if isTimeout(err) {
				return
			}
			log.Printf("ICMP forwarder: read error: %v", err)
			return
		}

		msg, err := icmp.ParseMessage(1, buf[:n]) // 1 = ICMPv4
		if err != nil {
			continue
		}

		if msg.Type != xipv4.ICMPTypeEchoReply {
			continue
		}

		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			continue
		}

		k := key(uint16(echo.ID), uint16(echo.Seq))
		p, ok := f.pending[k]
		if !ok {
			continue // stray reply or already timed out
		}
		delete(f.pending, k)

		_ = peer // peer address confirmed by id/seq matching

		f.replies = append(f.replies, Reply{
			SrcIP:   p.dstIP,
			DstIP:   p.srcIP,
			ID:      p.id,
			Seq:     p.seq,
			Payload: echo.Data,
		})
	}
}

// ConsumeReplies returns and clears accumulated replies.
func (f *Forwarder) ConsumeReplies() []Reply {
	r := f.replies
	f.replies = nil
	return r
}

// Cleanup removes stale pending entries older than the given duration.
func (f *Forwarder) Cleanup(timeout time.Duration) {
	now := time.Now()
	for k, p := range f.pending {
		if now.Sub(p.createdAt) > timeout {
			delete(f.pending, k)
		}
	}
}

// BuildICMPReplyPacket builds an IPv4 packet containing an ICMP Echo Reply.
// This uses our internal ipv4.Packet type, so it lives here with only
// net.IP inputs to avoid a circular dependency on pkg/ipv4.
func BuildICMPReplyData(id, seq uint16, payload []byte) []byte {
	hdr := make([]byte, 8)
	hdr[0] = 0 // Echo Reply
	hdr[1] = 0 // Code
	// bytes 2-3: checksum (computed below)
	binary.BigEndian.PutUint16(hdr[4:6], id)
	binary.BigEndian.PutUint16(hdr[6:8], seq)

	full := append(hdr, payload...)
	cs := icmpChecksum(full)
	binary.BigEndian.PutUint16(full[2:4], cs)

	return full
}

func icmpChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
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
	return false
}
