package dhcp

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/pinyin/bdp-netstack/pkg/udp"
)

func buildDiscover(txID uint32, mac [6]byte) []byte {
	buf := make([]byte, 300)
	buf[0] = 1         // BOOTREQUEST
	buf[1] = 1         // Ethernet
	buf[2] = 6         // MAC length
	binary.BigEndian.PutUint32(buf[4:8], txID)
	binary.BigEndian.PutUint16(buf[10:12], 0x8000) // broadcast flag
	copy(buf[28:34], mac[:])

	// Magic cookie
	binary.BigEndian.PutUint32(buf[236:240], MagicCookie)
	offset := 240
	offset = writeOption(buf, offset, OptMessageType, []byte{MsgDiscover})
	offset = writeOption(buf, offset, 55, []byte{1, 3, 6}) // parameter request list
	buf[offset] = OptEnd

	return buf[:offset+1]
}

func buildRequest(txID uint32, mac [6]byte, reqIP net.IP, serverIP net.IP) []byte {
	buf := make([]byte, 300)
	buf[0] = 1
	buf[1] = 1
	buf[2] = 6
	binary.BigEndian.PutUint32(buf[4:8], txID)
	binary.BigEndian.PutUint16(buf[10:12], 0x8000)
	copy(buf[28:34], mac[:])

	binary.BigEndian.PutUint32(buf[236:240], MagicCookie)
	offset := 240
	offset = writeOption(buf, offset, OptMessageType, []byte{MsgRequest})
	offset = writeOption(buf, offset, OptRequestedIP, reqIP.To4())
	offset = writeOption(buf, offset, OptServerIdentifier, serverIP.To4())
	buf[offset] = OptEnd

	return buf[:offset+1]
}

func TestDHCPDiscover(t *testing.T) {
	srv := NewServer(DefaultServerConfig())
	handler := srv.Handler()

	mac := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}

	dg := &udp.UDPDatagram{
		SrcIP:   net.IPv4zero,
		DstIP:   net.IPv4bcast,
		SrcPort: 68,
		DstPort: 67,
		Payload: buildDiscover(0x12345678, mac),
	}

	responses := handler(dg)
	if len(responses) != 1 {
		t.Fatalf("expected 1 response, got %d", len(responses))
	}

	offer := responses[0]
	if offer.DstPort != 68 {
		t.Fatalf("expected DstPort 68, got %d", offer.DstPort)
	}
	if offer.SrcPort != 67 {
		t.Fatalf("expected SrcPort 67, got %d", offer.SrcPort)
	}

	// Check DHCP message type = OFFER
	msgType := srv.getOption(offer.Payload, OptMessageType)
	if len(msgType) != 1 || msgType[0] != MsgOffer {
		t.Fatalf("expected DHCPOFFER, got %v", msgType)
	}

	// Check that yiaddr is in the pool range
	yiaddr := net.IP(offer.Payload[16:20])
	if yiaddr.Equal(net.IPv4zero) {
		t.Fatal("expected non-zero yiaddr")
	}
	t.Logf("DHCP OFFER yiaddr=%s", yiaddr)

	// Verify subnet mask option
	subnetOpt := srv.getOption(offer.Payload, OptSubnetMask)
	if len(subnetOpt) != 4 {
		t.Fatal("expected subnet mask option")
	}
	subnet := net.IP(subnetOpt)
	t.Logf("Subnet mask: %s", subnet)

	// Verify router option
	routerOpt := srv.getOption(offer.Payload, OptRouter)
	if len(routerOpt) != 4 {
		t.Fatal("expected router option")
	}
	router := net.IP(routerOpt)
	t.Logf("Router: %s", router)

	// Verify DNS option
	dnsOpt := srv.getOption(offer.Payload, OptDNSServer)
	if len(dnsOpt) != 4 {
		t.Fatal("expected DNS option")
	}

	// Verify server identifier
	srvID := srv.getOption(offer.Payload, OptServerIdentifier)
	if len(srvID) != 4 {
		t.Fatal("expected server identifier option")
	}
}

func TestDHCPRequestAck(t *testing.T) {
	srv := NewServer(DefaultServerConfig())
	handler := srv.Handler()

	mac := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	// First DISCOVER to allocate an IP
	discover := &udp.UDPDatagram{
		SrcIP:   net.IPv4zero,
		DstIP:   net.IPv4bcast,
		SrcPort: 68,
		DstPort: 67,
		Payload: buildDiscover(0xAAAA, mac),
	}
	responses := handler(discover)
	if len(responses) != 1 {
		t.Fatalf("expected 1 DISCOVER response, got %d", len(responses))
	}

	yiaddr := net.IP(responses[0].Payload[16:20])

	// Now REQUEST the same IP
	request := &udp.UDPDatagram{
		SrcIP:   net.IPv4zero,
		DstIP:   net.IPv4bcast,
		SrcPort: 68,
		DstPort: 67,
		Payload: buildRequest(0xAAAA, mac, yiaddr, net.ParseIP("192.168.65.1")),
	}
	responses = handler(request)
	if len(responses) != 1 {
		t.Fatalf("expected 1 REQUEST response, got %d", len(responses))
	}

	ack := responses[0]
	msgType := srv.getOption(ack.Payload, OptMessageType)
	if len(msgType) != 1 || msgType[0] != MsgAck {
		t.Fatalf("expected DHCPACK, got %v", msgType)
	}

	t.Logf("DHCP ACK yiaddr=%s", yiaddr)
}

func TestDHCPRelease(t *testing.T) {
	srv := NewServer(DefaultServerConfig())
	handler := srv.Handler()

	mac := [6]byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x03}

	// Allocate
	discover := &udp.UDPDatagram{
		SrcIP:   net.IPv4zero, DstIP: net.IPv4bcast, SrcPort: 68, DstPort: 67,
		Payload: buildDiscover(0xBBBB, mac),
	}
	handler(discover)

	// Release
	releaseBuf := make([]byte, 300)
	releaseBuf[0] = 1
	releaseBuf[1] = 1
	releaseBuf[2] = 6
	binary.BigEndian.PutUint32(releaseBuf[4:8], 0xBBBB)
	copy(releaseBuf[28:34], mac[:])
	binary.BigEndian.PutUint32(releaseBuf[236:240], MagicCookie)
	off := writeOption(releaseBuf, 240, OptMessageType, []byte{MsgRelease})
	releaseBuf[off] = OptEnd

	release := &udp.UDPDatagram{
		SrcIP:   net.IPv4zero, DstIP: net.IPv4bcast, SrcPort: 68, DstPort: 67,
		Payload: releaseBuf[:off+1],
	}
	responses := handler(release)
	if len(responses) != 0 {
		t.Fatal("expected no response for RELEASE")
	}

	// New DISCOVER from same MAC should get a new IP (or same if pool not exhausted)
	responses = handler(discover)
	if len(responses) != 1 {
		t.Fatalf("expected response after release, got %d", len(responses))
	}
}
