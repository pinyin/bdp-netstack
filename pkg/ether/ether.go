// Package ether handles raw Ethernet frames from/to the VM via unixgram socket.
// This is the externalization boundary — raw packet I/O happens here.
package ether

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	MinFrameSize    = 60
	HeaderSize      = 14
	MaxPayloadSize  = 1500

	EtherTypeIPv4 = 0x0800
	EtherTypeARP  = 0x0806

	ARPRequest = 1
	ARPReply   = 2

	HardwareTypeEthernet = 1
)

var (
	BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ZeroMAC      = net.HardwareAddr{0, 0, 0, 0, 0, 0}
)

type Frame struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16
	Payload   []byte
}

type ARPPacket struct {
	HardwareType uint16
	ProtocolType uint16
	HardwareLen  uint8
	ProtocolLen  uint8
	Operation    uint16
	SenderMAC    net.HardwareAddr
	SenderIP     net.IP
	TargetMAC    net.HardwareAddr
	TargetIP     net.IP
}

// ParseFrame parses a raw Ethernet frame.
// All slice fields are deep-copied to avoid aliasing the caller's buffer,
// which is critical since ReadAllFrames reuses the same buffer for multiple reads.
func ParseFrame(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}
	dstMAC := make(net.HardwareAddr, 6)
	copy(dstMAC, data[0:6])
	srcMAC := make(net.HardwareAddr, 6)
	copy(srcMAC, data[6:12])
	payload := make([]byte, len(data)-HeaderSize)
	copy(payload, data[HeaderSize:])
	return &Frame{
		DstMAC:    dstMAC,
		SrcMAC:    srcMAC,
		EtherType: binary.BigEndian.Uint16(data[12:14]),
		Payload:   payload,
	}, nil
}

// Serialize serializes a frame to wire format.
func (f *Frame) Serialize() []byte {
	buf := make([]byte, HeaderSize+len(f.Payload))
	copy(buf[0:6], f.DstMAC)
	copy(buf[6:12], f.SrcMAC)
	binary.BigEndian.PutUint16(buf[12:14], f.EtherType)
	copy(buf[HeaderSize:], f.Payload)
	return buf
}

// ParseARP parses an ARP packet from an Ethernet payload.
// All slice fields are deep-copied to avoid aliasing the caller's buffer.
func ParseARP(data []byte) (*ARPPacket, error) {
	if len(data) < 28 {
		return nil, errors.New("ARP packet too short")
	}
	senderMAC := make(net.HardwareAddr, 6)
	copy(senderMAC, data[8:14])
	senderIP := make(net.IP, 4)
	copy(senderIP, data[14:18])
	targetMAC := make(net.HardwareAddr, 6)
	copy(targetMAC, data[18:24])
	targetIP := make(net.IP, 4)
	copy(targetIP, data[24:28])
	return &ARPPacket{
		HardwareType: binary.BigEndian.Uint16(data[0:2]),
		ProtocolType: binary.BigEndian.Uint16(data[2:4]),
		HardwareLen:  data[4],
		ProtocolLen:  data[5],
		Operation:    binary.BigEndian.Uint16(data[6:8]),
		SenderMAC:    senderMAC,
		SenderIP:     senderIP,
		TargetMAC:    targetMAC,
		TargetIP:     targetIP,
	}, nil
}

// SerializeARP serializes an ARP packet.
func (a *ARPPacket) Serialize() []byte {
	buf := make([]byte, 28)
	binary.BigEndian.PutUint16(buf[0:2], a.HardwareType)
	binary.BigEndian.PutUint16(buf[2:4], a.ProtocolType)
	buf[4] = a.HardwareLen
	buf[5] = a.ProtocolLen
	binary.BigEndian.PutUint16(buf[6:8], a.Operation)
	copy(buf[8:14], a.SenderMAC)
	copy(buf[14:18], a.SenderIP.To4())
	copy(buf[18:24], a.TargetMAC)
	copy(buf[24:28], a.TargetIP.To4())
	return buf
}

// BuildARPReply builds an ARP reply for the given target.
func BuildARPReply(senderMAC net.HardwareAddr, senderIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP) *ARPPacket {
	return &ARPPacket{
		HardwareType: HardwareTypeEthernet,
		ProtocolType: EtherTypeIPv4,
		HardwareLen:  6,
		ProtocolLen:  4,
		Operation:    ARPReply,
		SenderMAC:    senderMAC,
		SenderIP:     senderIP.To4(),
		TargetMAC:    targetMAC,
		TargetIP:     targetIP.To4(),
	}
}
