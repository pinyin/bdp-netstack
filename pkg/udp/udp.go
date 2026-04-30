// Package udp implements a minimal BDP-style UDP layer.
// Datagrams are dispatched to registered handlers during the deliberation phase.
package udp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// UDPDatagram represents a parsed UDP datagram with metadata.
type UDPDatagram struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Payload []byte
}

// Header returns a parsed UDP header from raw bytes.
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// ParseUDP parses a UDP header + payload from an IPv4 payload.
// The returned payload is deep-copied to avoid aliasing the caller's buffer.
func ParseUDP(data []byte) (*UDPHeader, []byte, error) {
	if len(data) < 8 {
		return nil, nil, fmt.Errorf("UDP header too short: %d", len(data))
	}
	hdr := &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}
	payloadLen := int(hdr.Length) - 8
	if payloadLen < 0 {
		payloadLen = 0
	}
	if payloadLen > len(data)-8 {
		payloadLen = len(data) - 8
	}
	payload := make([]byte, payloadLen)
	copy(payload, data[8:8+payloadLen])
	return hdr, payload, nil
}

// BuildDatagram constructs a UDP datagram for output.
func BuildDatagram(srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 8 + len(payload)
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[6:8], 0) // checksum optional for IPv4
	copy(buf[8:], payload)
	return buf
}

// Handler receives UDP datagrams and optionally returns responses.
// Return nil if no response is needed.
type Handler func(dg *UDPDatagram) []*UDPDatagram

// Mux dispatches UDP datagrams to registered handlers by port.
// BDP-style: all datagrams are processed in batch during deliberation.
type Mux struct {
	handlers map[uint16]Handler
	outputs  []*UDPDatagram
}

// NewMux creates a new UDP multiplexer.
func NewMux() *Mux {
	return &Mux{
		handlers: make(map[uint16]Handler),
	}
}

// Register registers a handler for a specific UDP port.
func (m *Mux) Register(port uint16, h Handler) {
	m.handlers[port] = h
}

// Deliver dispatches a datagram to the appropriate handler and collects responses.
func (m *Mux) Deliver(dg *UDPDatagram) {
	h, ok := m.handlers[dg.DstPort]
	if !ok {
		return // no handler → drop
	}
	responses := h(dg)
	m.outputs = append(m.outputs, responses...)
}

// ConsumeOutputs returns and clears accumulated output datagrams.
func (m *Mux) ConsumeOutputs() []*UDPDatagram {
	out := m.outputs
	m.outputs = nil
	return out
}
