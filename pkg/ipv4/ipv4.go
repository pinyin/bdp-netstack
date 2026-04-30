// Package ipv4 handles IPv4 packet parsing, routing, and ICMP.
package ipv4

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	VersionIHL = 0x45 // Version 4, IHL 5 (20 bytes)
	MaxPktSize = 65535

	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17

	ICMPTypeEchoReply   = 0
	ICMPTypeEchoRequest  = 8
)

type Packet struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Payload    []byte
}

// ParsePacket parses an IPv4 packet from raw bytes.
// All slice fields are deep-copied to avoid aliasing the caller's buffer.
func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("packet too short: %d", len(data))
	}

	verIHL := data[0]
	ihl := (verIHL & 0x0F) * 4
	if ihl < 20 || int(ihl) > len(data) {
		return nil, fmt.Errorf("invalid IHL: %d", ihl)
	}

	totalLen := binary.BigEndian.Uint16(data[2:4])
	if int(totalLen) > len(data) {
		totalLen = uint16(len(data))
	}

	srcIP := make(net.IP, 4)
	copy(srcIP, data[12:16])
	dstIP := make(net.IP, 4)
	copy(dstIP, data[16:20])

	pkt := &Packet{
		Version:    verIHL >> 4,
		IHL:        ihl,
		TOS:        data[1],
		TotalLen:   totalLen,
		ID:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      data[6] >> 5,
		FragOffset: (binary.BigEndian.Uint16(data[6:8]) & 0x1FFF),
		TTL:        data[8],
		Protocol:   data[9],
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIP:      srcIP,
		DstIP:      dstIP,
	}

	// Payload
	payloadEnd := int(totalLen)
	if payloadEnd > len(data) {
		payloadEnd = len(data)
	}
	if int(ihl) < payloadEnd {
		payloadLen := payloadEnd - int(ihl)
		pkt.Payload = make([]byte, payloadLen)
		copy(pkt.Payload, data[ihl:payloadEnd])
	}

	return pkt, nil
}

// Serialize serializes an IPv4 packet to wire format.
func (p *Packet) Serialize() []byte {
	ihl := uint8(20)
	if p.IHL > 0 {
		ihl = p.IHL
	}

	totalLen := int(ihl) + len(p.Payload)
	buf := make([]byte, totalLen)

	buf[0] = (4 << 4) | (ihl / 4)
	buf[1] = p.TOS
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], p.ID)
	fragField := (uint16(p.Flags) << 13) | (p.FragOffset & 0x1FFF)
	binary.BigEndian.PutUint16(buf[6:8], fragField)
	buf[8] = p.TTL
	buf[9] = p.Protocol
	// Checksum placeholder
	binary.BigEndian.PutUint16(buf[10:12], 0)
	copy(buf[12:16], p.SrcIP.To4())
	copy(buf[16:20], p.DstIP.To4())
	copy(buf[20:], p.Payload)

	// Compute checksum
	cs := Checksum(buf[:int(ihl)])
	binary.BigEndian.PutUint16(buf[10:12], cs)

	return buf
}

// IsForUs checks if this packet is destined for our IP.
func (p *Packet) IsForUs(ourIP net.IP) bool {
	return p.DstIP.Equal(ourIP) || p.DstIP.Equal(net.IPv4bcast)
}

// IsFragmented checks if this is a fragmented packet.
func (p *Packet) IsFragmented() bool {
	return p.FragOffset != 0 || (p.Flags&0x01) != 0 // MF flag
}

// NotFragment checks if this is not a fragment (for protocol handlers).
func (p *Packet) NotFragment() bool {
	return !p.IsFragmented()
}

// ICMPPacket represents an ICMP message.
type ICMPPacket struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	RestHdr  uint32 // bytes 4-7 of ICMP header (id/seq for Echo, etc.)
	Payload  []byte
}

// ParseICMP parses an ICMP packet from IPv4 payload.
func ParseICMP(data []byte) (*ICMPPacket, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ICMP packet too short: %d", len(data))
	}
	return &ICMPPacket{
		Type:     data[0],
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		RestHdr:  binary.BigEndian.Uint32(data[4:8]),
		Payload:  data[8:],
	}, nil
}

// Serialize serializes an ICMP packet.
func (i *ICMPPacket) Serialize() []byte {
	buf := make([]byte, 8+len(i.Payload))
	buf[0] = i.Type
	buf[1] = i.Code
	binary.BigEndian.PutUint16(buf[2:4], 0) // checksum placeholder
	binary.BigEndian.PutUint32(buf[4:8], i.RestHdr)
	copy(buf[8:], i.Payload)
	cs := Checksum(buf)
	binary.BigEndian.PutUint16(buf[2:4], cs)
	return buf
}

// BuildEchoReply builds an ICMP Echo Reply from an Echo Request.
func BuildEchoReply(req *ICMPPacket) *ICMPPacket {
	return &ICMPPacket{
		Type:    ICMPTypeEchoReply,
		Code:    0,
		RestHdr: req.RestHdr,
		Payload: req.Payload,
	}
}

// Checksum computes the IPv4 one's complement checksum.
func Checksum(data []byte) uint16 {
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

// FragReasm handles fragment reassembly. Simplification: we drop fragments
// and expect the TCP layer to use small enough segments (MTU 1500).
// A production implementation would track fragment buffers per (src, dst, id, protocol).
type FragReasm struct {
	// TODO: implement if needed for production use
}
