// Package stack assembles all protocol layers into a single BDP deliberation loop.
package stack

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/dhcp"
	"github.com/pinyin/bdp-netstack/pkg/dns"
	"github.com/pinyin/bdp-netstack/pkg/ether"
	"github.com/pinyin/bdp-netstack/pkg/fwd"
	"github.com/pinyin/bdp-netstack/pkg/icmp"
	"github.com/pinyin/bdp-netstack/pkg/ipv4"
	"github.com/pinyin/bdp-netstack/pkg/nat"
	"github.com/pinyin/bdp-netstack/pkg/tcp"
	"github.com/pinyin/bdp-netstack/pkg/udp"
)

// Config holds all configuration for the network stack.
type Config struct {
	SocketPath    string        // vfkit unixgram socket path
	GatewayMAC    net.HardwareAddr
	GatewayIP     net.IP
	SubnetCIDR    string
	MTU           int
	BPT           time.Duration
	TCPBufSize    int
	PortForwards  []fwd.Mapping // host port → VM IP:Port mappings
	Debug         bool
}

func DefaultConfig() Config {
	gwMAC, _ := net.ParseMAC("5a:94:ef:e4:0c:ee")
	return Config{
		SocketPath: "/tmp/bdp-stack.sock",
		GatewayMAC: gwMAC,
		GatewayIP:  net.ParseIP("192.168.65.1"),
		SubnetCIDR: "192.168.65.0/24",
		MTU:        1500,
		BPT:        1 * time.Millisecond,
		TCPBufSize: 64 * 1024,
	}
}

// Stack is the full network stack. Single goroutine.
type Stack struct {
	cfg   Config
	conn  *ether.VFKitConn
	arp   *ether.ARPResolver
	tcpState *tcp.TCPState

	// UDP + services
	udpMux  *udp.Mux
	dhcpSrv *dhcp.Server

	// NAT / conntrack
	natTable *nat.Table

	// Port forwarding
	fwd *fwd.Forwarder

	// ICMP forwarding (VM → external hosts)
	icmpFwd *icmp.Forwarder

	// Stats
	bytesIn  uint64
	bytesOut uint64
}

// New creates a new network stack.
func New(cfg Config, tcpState *tcp.TCPState) *Stack {
	tcpState.SetGatewayIP(cfg.GatewayIP)

	s := &Stack{
		cfg:      cfg,
		arp:      ether.NewARPResolver(),
		tcpState: tcpState,
		udpMux:   udp.NewMux(),
		natTable: nat.NewTable(),
	}

	// Set up DHCP server
	dhcpCfg := dhcp.ServerConfig{
		GatewayIP:  cfg.GatewayIP,
		SubnetMask: net.IPv4(255, 255, 255, 0),
		DNSIP:      cfg.GatewayIP,
		DomainName: "bdp.local",
		PoolStart:  net.IPv4(192, 168, 65, 2),
		PoolSize:   50,
	}
	s.dhcpSrv = dhcp.NewServer(dhcpCfg)
	s.udpMux.Register(dhcp.ServerPort, s.dhcpSrv.Handler())

	// Set up DNS proxy
	dnsProxy := dns.NewProxy(cfg.GatewayIP, "")
	log.Printf("DNS upstream: %s", dnsProxy.Upstream())
	s.udpMux.Register(dns.DNSPort, dnsProxy.Handler())

	// Set up port forwarding
	if len(cfg.PortForwards) > 0 {
		var err error
		s.fwd, err = fwd.New(cfg.GatewayIP, cfg.PortForwards)
		if err != nil {
			log.Printf("port forwarding setup failed: %v", err)
		}
	}

	// Set up ICMP forwarder (non-privileged, works in sandbox)
	var err error
	s.icmpFwd, err = icmp.New()
	if err != nil {
		log.Printf("ICMP forwarder: %v (VM-to-external ping will not work)", err)
	}

	// ARP: statically map gateway IP to our MAC
	s.arp.Set(cfg.GatewayIP, cfg.GatewayMAC)

	return s
}

// Run starts the BDP deliberation loop.
func (s *Stack) Run(ctx context.Context) error {
	if s.cfg.SocketPath != "" {
		conn, err := ether.ListenVFKit(s.cfg.SocketPath)
		if err != nil {
			return fmt.Errorf("listen vfkit: %w", err)
		}
		s.conn = conn
		defer s.conn.Close()

		if err := s.conn.SetNonBlocking(); err != nil {
			return fmt.Errorf("set nonblocking: %w", err)
		}
	}

	ticker := time.NewTicker(s.cfg.BPT)
	defer ticker.Stop()

	log.Printf("BDP netstack running, BPT=%v, gateway=%s", s.cfg.BPT, s.cfg.GatewayIP)

	tickCount := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case now := <-ticker.C:
			tickCount++
			if tickCount <= 3 && s.cfg.Debug {
				log.Printf("tick #%d", tickCount)
			}
			s.deliberate(now)
		}
	}
}

// deliberate executes one full round of batch processing.
func (s *Stack) deliberate(now time.Time) {
	// Phase 1: Read all available Ethernet frames (externalization)
	if s.conn != nil {
		frames, err := s.conn.ReadAllFrames(context.TODO())
		if err != nil {
			log.Printf("read frames: %v", err)
		}
		if s.cfg.Debug && len(frames) > 0 {
			log.Printf("deliberate: read %d frames", len(frames))
		}
		for _, frame := range frames {
			s.processFrame(frame)
			s.bytesIn += uint64(len(frame.Payload))
		}
	}

	// Phase 2: Forwarder — accept new connections + poll host reads
	if s.fwd != nil {
		s.fwd.PollAccept(s.tcpState)
		s.fwd.Poll()
	}

	// Phase 3: NAT — poll host connections (non-blocking reads → VM send buffers)
	s.natTable.Poll()

	// Phase 4: TCP layer deliberation (batch-process all connections)
	s.tcpState.Deliberate(now)

	// Phase 5: ICMP forwarder — read host echo replies
	if s.icmpFwd != nil {
		s.icmpFwd.Poll()
	}

	// Phase 6: Forwarder — proxy VM receive buffers to host
	if s.fwd != nil {
		s.fwd.ProxyVMToHost()
	}

	// Phase 6: NAT — proxy VM receive buffers to host connections
	s.natTable.ProxyVMToHost()

	// Phase 7: Write outgoing TCP segments
	for _, seg := range s.tcpState.ConsumeOutputs() {
		s.sendSegment(seg)
	}

	// Phase 9: Write outgoing UDP datagrams
	for _, dg := range s.udpMux.ConsumeOutputs() {
		s.sendDatagram(dg)
	}

	// Phase 10: Write ICMP replies to VM
	if s.icmpFwd != nil {
		for _, reply := range s.icmpFwd.ConsumeReplies() {
			s.sendICMPReply(reply)
		}
	}

	// Phase 11: Forwarder cleanup
	if s.fwd != nil {
		s.fwd.Cleanup()
	}

	// Phase 12: NAT cleanup
	s.natTable.Cleanup()
}

// sendICMPReply writes an ICMP Echo Reply back to the VM.
func (s *Stack) sendICMPReply(reply icmp.Reply) {
	dstMAC, ok := s.arp.Lookup(reply.DstIP)
	if !ok {
		log.Printf("ICMP reply: no ARP entry for %s", reply.DstIP)
		return
	}

	icmpData := icmp.BuildICMPReplyData(reply.ID, reply.Seq, reply.Payload)

	ipPkt := &ipv4.Packet{
		Version:  4,
		IHL:      20,
		TOS:      0,
		ID:       0,
		TTL:      64,
		Protocol: ipv4.ProtocolICMP,
		SrcIP:    reply.SrcIP,
		DstIP:    reply.DstIP,
		Payload:  icmpData,
	}

	s.writeIPv4Packet(dstMAC, ipPkt)
}

// processFrame processes one incoming Ethernet frame.
func (s *Stack) processFrame(frame *ether.Frame) {
	if s.cfg.Debug {
		log.Printf("Frame: src=%s dst=%s type=%04x len=%d", frame.SrcMAC, frame.DstMAC, frame.EtherType, len(frame.Payload))
	}
	switch frame.EtherType {
	case ether.EtherTypeARP:
		s.processARP(frame)
	case ether.EtherTypeIPv4:
		s.processIPv4(frame)
	}
}

// processARP handles ARP requests for our gateway IP.
func (s *Stack) processARP(frame *ether.Frame) {
	arpPkt, err := ether.ParseARP(frame.Payload)
	if err != nil {
		return
	}

	// Learn sender's MAC from any ARP packet
	s.arp.Set(arpPkt.SenderIP, arpPkt.SenderMAC)
	if s.cfg.Debug {
		log.Printf("ARP learn: %s → %s (op=%d, target=%s)", arpPkt.SenderIP, arpPkt.SenderMAC, arpPkt.Operation, arpPkt.TargetIP)
	}

	// Reply to ARP requests for our gateway IP
	if arpPkt.Operation == ether.ARPRequest && arpPkt.TargetIP.Equal(s.cfg.GatewayIP) {
		reply := ether.BuildARPReply(s.cfg.GatewayMAC, s.cfg.GatewayIP,
			arpPkt.SenderMAC, arpPkt.SenderIP)
		outFrame := &ether.Frame{
			DstMAC:    arpPkt.SenderMAC,
			SrcMAC:    s.cfg.GatewayMAC,
			EtherType: ether.EtherTypeARP,
			Payload:   reply.Serialize(),
		}
		if err := s.conn.WriteFrame(outFrame); err != nil {
			log.Printf("write ARP reply: %v", err)
		}
		s.bytesOut += uint64(len(outFrame.Payload))
	}
}

// processIPv4 processes one incoming IPv4 packet.
func (s *Stack) processIPv4(frame *ether.Frame) {
	pkt, err := ipv4.ParsePacket(frame.Payload)
	if err != nil {
		if s.cfg.Debug {
			log.Printf("parse IPv4: %v", err)
		}
		return
	}

	// TCP to external IPs → NAT
	if pkt.Protocol == ipv4.ProtocolTCP && !pkt.IsForUs(s.cfg.GatewayIP) {
		s.processNAT(frame, pkt)
		return
	}

	// ICMP to external IPs → forwarder
	if pkt.Protocol == ipv4.ProtocolICMP && !pkt.IsForUs(s.cfg.GatewayIP) {
		s.processICMPForward(frame, pkt)
		return
	}

	if !pkt.IsForUs(s.cfg.GatewayIP) {
		return
	}

	switch pkt.Protocol {
	case ipv4.ProtocolICMP:
		s.processICMP(frame, pkt)
	case ipv4.ProtocolTCP:
		s.processTCP(frame, pkt)
	case ipv4.ProtocolUDP:
		s.processUDP(frame, pkt)
	}
}

// processICMP handles ICMP Echo Request -> Echo Reply.
func (s *Stack) processICMP(frame *ether.Frame, pkt *ipv4.Packet) {
	icmp, err := ipv4.ParseICMP(pkt.Payload)
	if err != nil {
		log.Printf("ICMP parse error: %v", err)
		return
	}
	if icmp.Type != ipv4.ICMPTypeEchoRequest {
		return
	}

	log.Printf("ICMP: Echo Request from %s to %s", pkt.SrcIP, pkt.DstIP)

	reply := ipv4.BuildEchoReply(icmp)
	ipReply := &ipv4.Packet{
		Version:  4,
		IHL:      20,
		TOS:      0,
		ID:       pkt.ID,
		TTL:      64,
		Protocol: ipv4.ProtocolICMP,
		SrcIP:    pkt.DstIP,
		DstIP:    pkt.SrcIP,
		Payload:  reply.Serialize(),
	}

	log.Printf("ICMP: Echo Reply from %s to %s via %s", ipReply.SrcIP, ipReply.DstIP, frame.SrcMAC)
	s.writeIPv4Packet(frame.SrcMAC, ipReply)
}

// processICMPForward forwards ICMP Echo Requests to external hosts.
func (s *Stack) processICMPForward(frame *ether.Frame, pkt *ipv4.Packet) {
	if s.icmpFwd == nil {
		return
	}

	icmpPkt, err := ipv4.ParseICMP(pkt.Payload)
	if err != nil {
		return
	}
	if icmpPkt.Type != ipv4.ICMPTypeEchoRequest {
		return
	}

	id := uint16(icmpPkt.RestHdr >> 16)
	seq := uint16(icmpPkt.RestHdr & 0xFFFF)

	log.Printf("ICMP fwd: %s → %s (id=%d, seq=%d)", pkt.SrcIP, pkt.DstIP, id, seq)
	if err := s.icmpFwd.Forward(pkt.SrcIP, pkt.DstIP, id, seq, icmpPkt.Payload); err != nil {
		log.Printf("ICMP fwd error: %v", err)
	}
}

// processTCP processes one incoming TCP segment.
func (s *Stack) processTCP(frame *ether.Frame, pkt *ipv4.Packet) {
	seg, err := tcp.ParseSegment(pkt.Payload, pkt.SrcIP, pkt.DstIP)
	if err != nil {
		if s.cfg.Debug {
			log.Printf("parse TCP: %v", err)
		}
		return
	}

	s.tcpState.InjectSegment(seg)
}

// processUDP processes one incoming UDP datagram.
func (s *Stack) processUDP(frame *ether.Frame, pkt *ipv4.Packet) {
	hdr, payload, err := udp.ParseUDP(pkt.Payload)
	if err != nil {
		if s.cfg.Debug {
			log.Printf("parse UDP: %v", err)
		}
		return
	}

	dg := &udp.UDPDatagram{
		SrcIP:   pkt.SrcIP,
		DstIP:   pkt.DstIP,
		SrcPort: hdr.SrcPort,
		DstPort: hdr.DstPort,
		Payload: payload,
	}

	if s.cfg.Debug {
		log.Printf("UDP recv: %s:%d → %s:%d (len=%d)", dg.SrcIP, dg.SrcPort, dg.DstIP, dg.DstPort, len(payload))
	}

	s.udpMux.Deliver(dg)
}

// processNAT handles TCP segments destined to external IPs (outbound NAT).
func (s *Stack) processNAT(frame *ether.Frame, pkt *ipv4.Packet) {
	seg, err := tcp.ParseSegment(pkt.Payload, pkt.SrcIP, pkt.DstIP)
	if err != nil {
		if s.cfg.Debug {
			log.Printf("parse NAT TCP: %v", err)
		}
		return
	}

	s.natTable.Intercept(seg, s.tcpState)
}

// sendSegment encapsulates a TCP segment in IP/Ethernet and writes to vfkit.
func (s *Stack) sendSegment(seg *tcp.TCPSegment) {
	dstIP := seg.Tuple.DstIPNet()
	dstMAC, ok := s.arp.Lookup(dstIP)
	if !ok {
		log.Printf("no ARP entry for %s, dropping TCP segment (flags=%d, sport=%d, dport=%d)", dstIP, seg.Header.Flags, seg.Tuple.SrcPort, seg.Tuple.DstPort)
		return
	}

	log.Printf("TCP send: %s:%d → %s:%d (flags=%d, seq=%d, ack=%d, len=%d, dstMAC=%s)",
		seg.Tuple.SrcIPNet(), seg.Tuple.SrcPort,
		dstIP, seg.Tuple.DstPort,
		seg.Header.Flags, seg.Header.SeqNum, seg.Header.AckNum,
		len(seg.Payload), dstMAC)

	tcpHeader := &tcp.TCPHeader{
		SrcPort:    seg.Tuple.SrcPort,
		DstPort:    seg.Tuple.DstPort,
		SeqNum:     seg.Header.SeqNum,
		AckNum:     seg.Header.AckNum,
		Flags:      seg.Header.Flags,
		WindowSize: seg.Header.WindowSize,
	}
	tcpBytes := tcpHeader.Marshal()
	if len(seg.Payload) > 0 {
		tcpBytes = append(tcpBytes, seg.Payload...)
	}
	cs := tcp.TCPChecksum(seg.Tuple.SrcIPNet(), seg.Tuple.DstIPNet(), tcpBytes)
	tcpBytes[16] = byte(cs >> 8)
	tcpBytes[17] = byte(cs)

	ipPkt := &ipv4.Packet{
		Version:  4,
		IHL:      20,
		TOS:      0,
		ID:       uint16(time.Now().UnixNano() & 0xFFFF),
		TTL:      64,
		Protocol: ipv4.ProtocolTCP,
		SrcIP:    net.IP(seg.Tuple.SrcIP[:]),
		DstIP:    net.IP(seg.Tuple.DstIP[:]),
		Payload:  tcpBytes,
	}

	s.writeIPv4Packet(dstMAC, ipPkt)
}

// sendDatagram encapsulates a UDP datagram in IP/Ethernet and writes to vfkit.
func (s *Stack) sendDatagram(dg *udp.UDPDatagram) {
	dstMAC, ok := s.arp.Lookup(dg.DstIP)
	if !ok {
		// Broadcast
		dstMAC, _ = net.ParseMAC("ff:ff:ff:ff:ff:ff")
	}
	if s.cfg.Debug {
		log.Printf("UDP send: %s:%d → %s:%d (len=%d, bcast=%v)", dg.SrcIP, dg.SrcPort, dg.DstIP, dg.DstPort, len(dg.Payload), !ok)
	}

	udpBytes := udp.BuildDatagram(dg.SrcPort, dg.DstPort, dg.Payload)

	ipPkt := &ipv4.Packet{
		Version:  4,
		IHL:      20,
		TOS:      0,
		ID:       uint16(time.Now().UnixNano() & 0xFFFF),
		TTL:      64,
		Protocol: ipv4.ProtocolUDP,
		SrcIP:    dg.SrcIP,
		DstIP:    dg.DstIP,
		Payload:  udpBytes,
	}

	s.writeIPv4Packet(dstMAC, ipPkt)
}

// writeIPv4Packet serializes and writes an IP packet as an Ethernet frame.
func (s *Stack) writeIPv4Packet(dstMAC net.HardwareAddr, pkt *ipv4.Packet) {
	if s.conn == nil {
		return
	}
	ipBytes := pkt.Serialize()
	frame := &ether.Frame{
		DstMAC:    dstMAC,
		SrcMAC:    s.cfg.GatewayMAC,
		EtherType: ether.EtherTypeIPv4,
		Payload:   ipBytes,
	}

	if err := s.conn.WriteFrame(frame); err != nil {
		log.Printf("write frame: %v", err)
	}
	s.bytesOut += uint64(len(ipBytes))
}

// TCPState returns the TCP state engine.
func (s *Stack) TCPState() *tcp.TCPState {
	return s.tcpState
}

// BytesIn returns total bytes received.
func (s *Stack) BytesIn() uint64 { return s.bytesIn }

// BytesOut returns total bytes sent.
func (s *Stack) BytesOut() uint64 { return s.bytesOut }
