// Package dhcp implements a minimal DHCP server integrated into the BDP UDP layer.
package dhcp

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/pinyin/bdp-netstack/pkg/udp"
)

const (
	ServerPort = 67
	ClientPort = 68

	OpReply = 2

	// DHCP message types
	MsgDiscover = 1
	MsgOffer    = 2
	MsgRequest  = 3
	MsgAck      = 5
	MsgNak      = 6
	MsgRelease  = 7
	MsgInform   = 8

	// DHCP options
	OptSubnetMask       = 1
	OptRouter           = 3
	OptDNSServer        = 6
	OptDomainName       = 15
	OptRequestedIP      = 50
	OptLeaseTime        = 51
	OptMessageType      = 53
	OptServerIdentifier = 54
	OptEnd              = 255

	MagicCookie = 0x63825363
)

// ServerConfig holds DHCP server configuration.
type ServerConfig struct {
	GatewayIP  net.IP
	SubnetMask net.IP
	DNSIP      net.IP
	DomainName string
	PoolStart  net.IP
	PoolSize   int
}

// DefaultServerConfig returns a default configuration for the BDP test subnet.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		GatewayIP:  net.ParseIP("192.168.65.1"),
		SubnetMask: net.ParseIP("255.255.255.0"),
		DNSIP:      net.ParseIP("192.168.65.1"),
		DomainName: "bdp.local",
		PoolStart:  net.ParseIP("192.168.65.2"),
		PoolSize:   50,
	}
}

// OnLease is called when a DHCP ACK assigns an IP to a client MAC.
// This allows the stack to learn the VM's ARP entry (IP → MAC).
var OnLease func(clientIP net.IP, clientMAC net.HardwareAddr)

// Server is a BDP-style DHCP server. It has no goroutines; all processing
// happens during deliberation by the UDP layer calling the handler.
type Server struct {
	cfg       ServerConfig
	leases    map[[6]byte]*Lease // keyed by client MAC
	allocated map[[4]byte]bool   // keyed by IP
	nextIP    net.IP
}

// Lease represents an IP lease to a client.
type Lease struct {
	ClientMAC [6]byte
	IP        net.IP
}

// NewServer creates a DHCP server.
func NewServer(cfg ServerConfig) *Server {
	return &Server{
		cfg:       cfg,
		leases:    make(map[[6]byte]*Lease),
		allocated: make(map[[4]byte]bool),
		nextIP:    make(net.IP, 4),
	}
}

// Handler returns a udp.Handler that integrates with the BDP UDP mux.
func (s *Server) Handler() udp.Handler {
	return func(dg *udp.UDPDatagram) []*udp.UDPDatagram {
		resp := s.process(dg)
		if resp == nil {
			return nil
		}
		return []*udp.UDPDatagram{resp}
	}
}

// process handles a single DHCP message.
func (s *Server) process(dg *udp.UDPDatagram) *udp.UDPDatagram {
	if len(dg.Payload) < 240 {
		return nil // minimum DHCP message size
	}

	op := dg.Payload[0]
	if op != 1 { // not a request
		return nil
	}

	clientMAC := [6]byte{}
	copy(clientMAC[:], dg.Payload[28:34])

	msgType := s.getOption(dg.Payload, OptMessageType)
	if len(msgType) < 1 {
		return nil
	}

	switch msgType[0] {
	case MsgDiscover:
		log.Printf("DHCP: DISCOVER from %s", clientMAC)
		return s.buildOffer(dg, clientMAC)
	case MsgRequest:
		log.Printf("DHCP: REQUEST from %s", clientMAC)
		return s.buildAck(dg, clientMAC)
	case MsgRelease:
		log.Printf("DHCP: RELEASE from %s", clientMAC)
		s.releaseLease(clientMAC)
		return nil
	}
	return nil
}

// buildOffer allocates an IP and builds a DHCPOFFER.
func (s *Server) buildOffer(dg *udp.UDPDatagram, clientMAC [6]byte) *udp.UDPDatagram {
	ip := s.allocateIP(clientMAC)
	if ip == nil {
		return nil
	}

	txID := dg.Payload[4:8]
	payload := s.buildResponse(MsgOffer, txID, clientMAC, ip)
	log.Printf("DHCP: OFFER %s to %s (broadcast)", ip, clientMAC)
	return &udp.UDPDatagram{
		SrcIP:   s.cfg.GatewayIP,
		DstIP:   net.IPv4bcast,
		SrcPort: ServerPort,
		DstPort: ClientPort,
		Payload: payload,
	}
}

// buildAck builds a DHCPACK (or DHCPNAK).
func (s *Server) buildAck(dg *udp.UDPDatagram, clientMAC [6]byte) *udp.UDPDatagram {
	txID := dg.Payload[4:8]

	reqIPOpt := s.getOption(dg.Payload, OptRequestedIP)
	var reqIP net.IP
	if len(reqIPOpt) >= 4 {
		reqIP = net.IP(reqIPOpt[:4])
	} else {
		// Use ciaddr from the message
		reqIP = net.IP(dg.Payload[12:16])
	}

	if reqIP == nil || reqIP.Equal(net.IPv4zero) {
		return nil
	}

	// Check if this IP is leased to this client
	lease, exists := s.leases[clientMAC]
	msgType := MsgNak
	if exists && lease.IP.Equal(reqIP) {
		msgType = MsgAck
	}

	payload := s.buildResponse(byte(msgType), txID, clientMAC, reqIP)
	dstIP := net.IPv4bcast
	if msgType == MsgAck {
		dstIP = reqIP
	}
	typeName := "NAK"
	if msgType == MsgAck {
		typeName = "ACK"
	}
	log.Printf("DHCP: %s %s to %s (dst=%s)", typeName, reqIP, clientMAC, dstIP)

	if msgType == MsgAck && OnLease != nil {
		OnLease(reqIP, net.HardwareAddr(clientMAC[:]))
	}

	return &udp.UDPDatagram{
		SrcIP:   s.cfg.GatewayIP,
		DstIP:   dstIP,
		SrcPort: ServerPort,
		DstPort: ClientPort,
		Payload: payload,
	}
}

// buildResponse constructs a DHCP response message.
func (s *Server) buildResponse(msgType byte, txID []byte, clientMAC [6]byte, assignedIP net.IP) []byte {
	// Fixed fields: 236 bytes + options
	buf := make([]byte, 300)

	buf[0] = OpReply           // op
	buf[1] = 1                 // htype (Ethernet)
	buf[2] = 6                 // hlen (MAC length)
	buf[3] = 0                 // hops
	copy(buf[4:8], txID)       // xid
	binary.BigEndian.PutUint16(buf[8:10], 0)  // secs
	binary.BigEndian.PutUint16(buf[10:12], 0x8000) // flags (broadcast)
	// ciaddr, yiaddr, siaddr, giaddr — zeros
	copy(buf[16:20], assignedIP.To4()) // yiaddr
	copy(buf[28:34], clientMAC[:])     // chaddr
	// Server host name, boot file — zeros (not needed)

	// Magic cookie
	binary.BigEndian.PutUint32(buf[236:240], MagicCookie)

	offset := 240

	// Option 53: Message Type
	offset = writeOption(buf, offset, OptMessageType, []byte{msgType})

	// Option 54: Server Identifier
	offset = writeOption(buf, offset, OptServerIdentifier, s.cfg.GatewayIP.To4())

	// Option 1: Subnet Mask
	offset = writeOption(buf, offset, OptSubnetMask, s.cfg.SubnetMask.To4())

	// Option 3: Router
	offset = writeOption(buf, offset, OptRouter, s.cfg.GatewayIP.To4())

	// Option 6: DNS Server
	offset = writeOption(buf, offset, OptDNSServer, s.cfg.DNSIP.To4())

	// Option 51: Lease Time (3600 seconds)
	lt := make([]byte, 4)
	binary.BigEndian.PutUint32(lt, 3600)
	offset = writeOption(buf, offset, OptLeaseTime, lt)

	// Option 15: Domain Name
	if s.cfg.DomainName != "" {
		offset = writeOption(buf, offset, OptDomainName, []byte(s.cfg.DomainName))
	}

	// Option 255: End
	buf[offset] = OptEnd
	offset++

	return buf[:offset]
}

// allocateIP allocates an IP address for a client.
func (s *Server) allocateIP(clientMAC [6]byte) net.IP {
	// Return existing lease if any
	if lease, ok := s.leases[clientMAC]; ok {
		return lease.IP
	}

	// Allocate new IP from pool
	poolStart := s.cfg.PoolStart.To4()
	base := binary.BigEndian.Uint32(poolStart)
	for i := 0; i < s.cfg.PoolSize; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, base+uint32(i))

		key := [4]byte{ip[0], ip[1], ip[2], ip[3]}
		if !s.allocated[key] {
			s.allocated[key] = true
			s.leases[clientMAC] = &Lease{
				ClientMAC: clientMAC,
				IP:        ip,
			}
			return ip
		}
	}
	return nil
}

// releaseLease releases an IP lease for a client.
func (s *Server) releaseLease(clientMAC [6]byte) {
	if lease, ok := s.leases[clientMAC]; ok {
		ip := lease.IP.To4()
		key := [4]byte{ip[0], ip[1], ip[2], ip[3]}
		delete(s.allocated, key)
		delete(s.leases, clientMAC)
	}
}

// getOption extracts a DHCP option from the message.
func (s *Server) getOption(data []byte, optType byte) []byte {
	if len(data) < 240 {
		return nil
	}
	cookie := binary.BigEndian.Uint32(data[236:240])
	if cookie != MagicCookie {
		return nil
	}
	i := 240
	for i < len(data) {
		t := data[i]
		if t == OptEnd {
			return nil
		}
		if i+2 > len(data) {
			return nil
		}
		l := int(data[i+1])
		if i+2+l > len(data) {
			return nil
		}
		if t == optType {
			return data[i+2 : i+2+l]
		}
		i += 2 + l
	}
	return nil
}

func writeOption(buf []byte, offset int, optType byte, val []byte) int {
	buf[offset] = optType
	buf[offset+1] = byte(len(val))
	copy(buf[offset+2:], val)
	return offset + 2 + len(val)
}
