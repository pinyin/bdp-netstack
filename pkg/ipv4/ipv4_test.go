package ipv4

import (
	"net"
	"testing"
)

func TestParsePacket(t *testing.T) {
	// Build an ICMP Echo Request packet
	pkt := &Packet{
		Version:  4,
		IHL:      20,
		TOS:      0,
		ID:       0x1234,
		TTL:      64,
		Protocol: ProtocolICMP,
		SrcIP:    net.ParseIP("192.168.65.2"),
		DstIP:    net.ParseIP("192.168.65.1"),
		Payload:  []byte{8, 0, 0, 0, 0, 0, 0, 0}, // ICMP Echo Request
	}

	data := pkt.Serialize()
	parsed, err := ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if parsed.Protocol != ProtocolICMP {
		t.Fatalf("expected ICMP protocol, got %d", parsed.Protocol)
	}
	if !parsed.SrcIP.Equal(pkt.SrcIP) {
		t.Fatalf("SrcIP mismatch: %s vs %s", parsed.SrcIP, pkt.SrcIP)
	}
	if !parsed.DstIP.Equal(pkt.DstIP) {
		t.Fatalf("DstIP mismatch: %s vs %s", parsed.DstIP, pkt.DstIP)
	}
	if parsed.ID != 0x1234 {
		t.Fatalf("ID mismatch: %d", parsed.ID)
	}
}

func TestParseTCPPacket(t *testing.T) {
	// TCP SYN: 20 bytes IP + 20 bytes TCP header
	tcpHeader := make([]byte, 20)
	tcpHeader[12] = 0x50 // DataOffset=5, flags=0
	tcpHeader[13] = 0x02 // SYN flag

	pkt := &Packet{
		Version:  4,
		IHL:      20,
		TOS:      0,
		ID:       0x5678,
		TTL:      64,
		Protocol: ProtocolTCP,
		SrcIP:    net.ParseIP("192.168.65.2"),
		DstIP:    net.ParseIP("192.168.65.1"),
		Payload:  tcpHeader,
	}

	data := pkt.Serialize()
	parsed, err := ParsePacket(data)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if parsed.Protocol != ProtocolTCP {
		t.Fatalf("expected TCP protocol, got %d", parsed.Protocol)
	}
	if len(parsed.Payload) != 20 {
		t.Fatalf("expected 20 byte payload, got %d", len(parsed.Payload))
	}
}

func TestIsForUs(t *testing.T) {
	gw := net.ParseIP("192.168.65.1")

	pkt := &Packet{DstIP: net.ParseIP("192.168.65.1")}
	if !pkt.IsForUs(gw) {
		t.Fatal("expected IsForUs for gateway IP")
	}

	pkt = &Packet{DstIP: net.ParseIP("8.8.8.8")}
	if pkt.IsForUs(gw) {
		t.Fatal("expected not IsForUs for external IP")
	}

	pkt = &Packet{DstIP: net.IPv4bcast}
	if !pkt.IsForUs(gw) {
		t.Fatal("expected IsForUs for broadcast")
	}
}

func TestICMPEchoReply(t *testing.T) {
	req := &ICMPPacket{
		Type:    ICMPTypeEchoRequest,
		Code:    0,
		Payload: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
	}

	reply := BuildEchoReply(req)
	if reply.Type != ICMPTypeEchoReply {
		t.Fatalf("expected EchoReply, got %d", reply.Type)
	}
	if reply.Code != 0 {
		t.Fatalf("expected Code=0, got %d", reply.Code)
	}
	if len(reply.Payload) != len(req.Payload) {
		t.Fatal("payload length mismatch")
	}
}

func TestChecksum(t *testing.T) {
	// Test with known values
	data := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	cs := Checksum(data)
	if cs == 0 {
		t.Fatal("checksum should not be zero")
	}
	// Verify that inserting the checksum makes the computed sum = 0xFFFF
	data[10] = byte(cs >> 8)
	data[11] = byte(cs)
	cs2 := Checksum(data)
	if cs2 != 0 {
		t.Fatalf("checksum verification failed: got %04x", cs2)
	}
}

func TestPacketRoundtrip(t *testing.T) {
	payload := []byte("hello world")
	original := &Packet{
		Version:  4,
		IHL:      20,
		TOS:      0,
		ID:       0xABCD,
		TTL:      64,
		Protocol: ProtocolUDP,
		SrcIP:    net.ParseIP("10.0.0.1"),
		DstIP:    net.ParseIP("10.0.0.2"),
		Payload:  payload,
	}

	serialized := original.Serialize()
	parsed, err := ParsePacket(serialized)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	if parsed.Protocol != ProtocolUDP {
		t.Fatal("protocol mismatch")
	}
	if !parsed.SrcIP.Equal(original.SrcIP) {
		t.Fatal("SrcIP mismatch")
	}
	if !parsed.DstIP.Equal(original.DstIP) {
		t.Fatal("DstIP mismatch")
	}
	if string(parsed.Payload) != string(payload) {
		t.Fatalf("payload mismatch: '%s' vs '%s'", string(parsed.Payload), string(payload))
	}
	if parsed.ID != 0xABCD {
		t.Fatalf("ID mismatch: %d", parsed.ID)
	}
}
