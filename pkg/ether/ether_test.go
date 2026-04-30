package ether

import (
	"net"
	"testing"
)

func TestParseFrame(t *testing.T) {
	// Build a minimal ARP request frame
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	srcMAC, _ := net.ParseMAC("02:00:00:00:00:01")

	frame := &Frame{
		DstMAC:    dstMAC,
		SrcMAC:    srcMAC,
		EtherType: EtherTypeARP,
		Payload:   make([]byte, 28), // minimal ARP payload
	}

	data := frame.Serialize()

	parsed, err := ParseFrame(data)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if parsed.EtherType != EtherTypeARP {
		t.Fatalf("expected EtherType ARP, got %04x", parsed.EtherType)
	}
	if !equalMAC(parsed.DstMAC, dstMAC) {
		t.Fatal("DstMAC mismatch")
	}
	if !equalMAC(parsed.SrcMAC, srcMAC) {
		t.Fatal("SrcMAC mismatch")
	}
}

func TestParseARPRequest(t *testing.T) {
	senderMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	senderIP := net.ParseIP("192.168.65.2")
	targetIP := net.ParseIP("192.168.65.1")

	arp := &ARPPacket{
		HardwareType: 1, // Ethernet
		ProtocolType: 0x0800,
		HardwareLen:  6,
		ProtocolLen:  4,
		Operation:    ARPRequest,
		SenderMAC:  senderMAC,
		SenderIP:   senderIP,
		TargetMAC:  make(net.HardwareAddr, 6), // unknown
		TargetIP:   targetIP,
	}

	data := arp.Serialize()
	parsed, err := ParseARP(data)
	if err != nil {
		t.Fatalf("ParseARP: %v", err)
	}
	if parsed.Operation != ARPRequest {
		t.Fatal("expected ARPRequest")
	}
	if !parsed.SenderIP.Equal(senderIP) {
		t.Fatalf("SenderIP mismatch: %s vs %s", parsed.SenderIP, senderIP)
	}
	if !parsed.TargetIP.Equal(targetIP) {
		t.Fatalf("TargetIP mismatch: %s vs %s", parsed.TargetIP, targetIP)
	}
}

func TestBuildARPReply(t *testing.T) {
	gatewayMAC, _ := net.ParseMAC("5a:94:ef:e4:0c:ee")
	gatewayIP := net.ParseIP("192.168.65.1")
	senderMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	senderIP := net.ParseIP("192.168.65.2")

	reply := BuildARPReply(gatewayMAC, gatewayIP, senderMAC, senderIP)

	if reply.Operation != ARPReply {
		t.Fatal("expected ARPReply")
	}
	if !reply.SenderIP.Equal(gatewayIP) {
		t.Fatalf("SenderIP should be gateway IP, got %s", reply.SenderIP)
	}
	if !reply.TargetIP.Equal(senderIP) {
		t.Fatalf("TargetIP should be sender IP, got %s", reply.TargetIP)
	}
	if !equalMAC(reply.SenderMAC, gatewayMAC) {
		t.Fatal("SenderMAC should be gateway MAC")
	}
	if !equalMAC(reply.TargetMAC, senderMAC) {
		t.Fatal("TargetMAC should be sender MAC")
	}
}

func TestARPResolver(t *testing.T) {
	resolver := NewARPResolver()
	ip := net.ParseIP("192.168.65.2")
	mac, _ := net.ParseMAC("02:00:00:00:00:01")

	resolver.Set(ip, mac)

	got, ok := resolver.Lookup(ip)
	if !ok {
		t.Fatal("lookup failed")
	}
	if !equalMAC(got, mac) {
		t.Fatal("MAC mismatch")
	}

	// Lookup unknown IP
	unknown := net.ParseIP("10.0.0.1")
	_, ok = resolver.Lookup(unknown)
	if ok {
		t.Fatal("expected lookup failure for unknown IP")
	}
}

func equalMAC(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
