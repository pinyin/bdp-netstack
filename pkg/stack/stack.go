// Package stack assembles all protocol layers into a single BDP deliberation loop.
package stack

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/debug"
	"github.com/pinyin/bdp-netstack/pkg/dhcp"
	"github.com/pinyin/bdp-netstack/pkg/dns"
	"github.com/pinyin/bdp-netstack/pkg/ether"
	"github.com/pinyin/bdp-netstack/pkg/fwd"
	"github.com/pinyin/bdp-netstack/pkg/icmp"
	"github.com/pinyin/bdp-netstack/pkg/ipv4"
	"github.com/pinyin/bdp-netstack/pkg/nat"
	"github.com/pinyin/bdp-netstack/pkg/tcp"
	"github.com/pinyin/bdp-netstack/pkg/udp"
	"github.com/pinyin/bdp-netstack/pkg/udpnat"
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

	// UDP NAT (VM → external hosts)
	udpNAT *udpnat.Table

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
		udpNAT:   udpnat.NewTable(),
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
		// DHCP will learn the VM's MAC→IP mapping when ACK is sent,
		// so the forwarder's first TCP SYN can resolve the VM's MAC.
		dhcp.OnLease = func(clientIP net.IP, clientMAC net.HardwareAddr) {
			if s.cfg.Debug {
				log.Printf("ARP learn from DHCP: %s → %s", clientIP, clientMAC)
			}
			s.arp.Set(clientIP, clientMAC)
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

	// Set TCP write callback so segments are written to the socket inline
	// during deliberation. This ensures SND_NXT is only advanced after a
	// successful write, preventing data loss when socket buffer is full.
	tcpState.SetWriteFunc(func(seg *tcp.TCPSegment) error {
		return s.sendSegment(seg)
	})

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

	// Phase 1.5: Pre-process ACKs — eagerly update SND_UNA from VM ACKs
	// that arrived in Phase 1. This ensures Phase 2 (Forwarder Poll) and
	// Phase 3 (NAT Poll) see accurate SendSpace before reading from host
	// sockets. Safe because ACK processing is idempotent.
	s.tcpState.PreProcessACKs()

	// Phase 2: Forwarder — accept new connections + poll host reads
	if s.fwd != nil {
		s.fwd.PollAccept(s.tcpState)
		s.fwd.Poll()
	}

	// Phase 3: NAT — poll host connections (non-blocking reads → VM send buffers)
	s.natTable.Poll()

	// Phase 4: UDP NAT — poll host UDP sockets (non-blocking reads → ingress queue)
	s.udpNAT.Poll()

	// Phase 5: TCP layer deliberation (batch-process all connections)
	s.tcpState.Deliberate(now)

	// Phase 6: ICMP forwarder — read host echo replies
	if s.icmpFwd != nil {
		s.icmpFwd.Poll()
	}

	// Phase 7: Forwarder — proxy VM receive buffers to host
	if s.fwd != nil {
		s.fwd.ProxyVMToHost()
	}

	// Phase 8: NAT — proxy VM receive buffers to host connections
	s.natTable.ProxyVMToHost()

	// Phase 9: UDP NAT — write queued VM datagrams to host sockets
	s.udpNAT.FlushEgress()

	// Phase 10: Write any remaining TCP segments (only used when writeFunc
	// is nil, e.g. in tests). With writeFunc set, segments are written
	// inline during Phase 5 and ts.outputs is always empty.
	for _, seg := range s.tcpState.ConsumeOutputs() {
		if err := s.sendSegment(seg); err != nil {
			// ENOBUFS already tracked in sendSegment
			if err == syscall.ENOBUFS {
				break // socket buffer full; defer remaining to next tick
			}
			log.Printf("write frame: %v", err)
		}
	}

	// Phase 11: Write outgoing UDP datagrams
	for _, dg := range s.udpMux.ConsumeOutputs() {
		s.sendDatagram(dg)
	}

	// Phase 12: Write ICMP replies to VM
	if s.icmpFwd != nil {
		for _, reply := range s.icmpFwd.ConsumeReplies() {
			s.sendICMPReply(reply)
		}
	}

	// Phase 13: UDP NAT — deliver host responses to VM
	for _, dg := range s.udpNAT.DeliverToVM() {
		s.sendDatagram(dg)
	}

	// Phase 14: Forwarder cleanup
	if s.fwd != nil {
		s.fwd.Cleanup()
	}

	// Phase 15: NAT cleanup
	s.natTable.Cleanup()

	// Phase 16: UDP NAT cleanup
	s.udpNAT.Cleanup(now)

	// Print periodic debug stats (every ~1s)
	debug.Global.PrintIfDue()
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

	_ = s.writeIPv4Packet(dstMAC, ipPkt)
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

	// Learn source IP→MAC from every IPv4 frame, matching gvproxy's
	// Switch CAM behavior. This ensures the forwarder can send unicast
	// TCP SYNs to the VM immediately after the VM sends its first IP
	// packet (DNS query, ARP request, etc.), without waiting for a
	// dedicated ARP exchange.
	s.arp.Set(pkt.SrcIP, frame.SrcMAC)

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

	// UDP to external IPs → UDP NAT
	if pkt.Protocol == ipv4.ProtocolUDP && !pkt.IsForUs(s.cfg.GatewayIP) {
		s.processUDPNAT(frame, pkt)
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
	_ = s.writeIPv4Packet(frame.SrcMAC, ipReply)
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

// processUDPNAT forwards UDP datagrams to external hosts via UDP NAT.
func (s *Stack) processUDPNAT(frame *ether.Frame, pkt *ipv4.Packet) {
	hdr, payload, err := udp.ParseUDP(pkt.Payload)
	if err != nil {
		return
	}

	dg := &udp.UDPDatagram{
		SrcIP:   pkt.SrcIP,
		DstIP:   pkt.DstIP,
		SrcPort: hdr.SrcPort,
		DstPort: hdr.DstPort,
		Payload: payload,
	}

	s.udpNAT.Intercept(dg)
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

	// Log incoming data and control segments
	if len(seg.Payload) > 0 {
		preview := len(seg.Payload)
		if preview > 32 {
			preview = 32
		}
		log.Printf("TCP RECV: %s:%d→%s:%d seq=%d ack=%d flags=%02x len=%d payload=%x",
			seg.Tuple.SrcIPNet(), seg.Tuple.SrcPort,
			seg.Tuple.DstIPNet(), seg.Tuple.DstPort,
			seg.Header.SeqNum, seg.Header.AckNum,
			seg.Header.Flags, len(seg.Payload),
			seg.Payload[:preview])
	} else if seg.Header.IsSYN() || seg.Header.IsFIN() || seg.Header.IsRST() {
		log.Printf("TCP RECV: %s:%d→%s:%d seq=%d ack=%d flags=%02x win=%d (control)",
			seg.Tuple.SrcIPNet(), seg.Tuple.SrcPort,
			seg.Tuple.DstIPNet(), seg.Tuple.DstPort,
			seg.Header.SeqNum, seg.Header.AckNum,
			seg.Header.Flags, seg.Header.WindowSize)
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
// Returns the write error, or nil on success.
func (s *Stack) sendSegment(seg *tcp.TCPSegment) error {
	dstIP := seg.Tuple.DstIPNet()
	dstMAC, ok := s.arp.Lookup(dstIP)
	if !ok {
		debug.Global.OutARPMiss.Add(1)
		log.Printf("no ARP entry for %s, dropping TCP segment (flags=%d, sport=%d, dport=%d)", dstIP, seg.Header.Flags, seg.Tuple.SrcPort, seg.Tuple.DstPort)
		return nil
	}

	tcpBytes := seg.Raw
	if tcpBytes == nil {
		// Fallback for segments not built via BuildSegment (shouldn't happen)
		tcpHdr := seg.Header.Marshal()
		tcpBytes = append(tcpHdr, seg.Payload...)
	}
	cs := tcp.TCPChecksum(seg.Tuple.SrcIPNet(), seg.Tuple.DstIPNet(), tcpBytes)
	tcpBytes[16] = byte(cs >> 8)
	tcpBytes[17] = byte(cs)

	// Verify checksum: one's complement sum of entire segment + pseudo-header
	// should be 0xFFFF (0x0000 after one's complement)
	verify := tcp.TCPChecksum(seg.Tuple.SrcIPNet(), seg.Tuple.DstIPNet(), tcpBytes)
	if verify != 0 {
		log.Printf("TCP CHECKSUM ERROR: computed=%04x verify=%04x tuple=%s seq=%d ack=%d len=%d",
			cs, verify, seg.Tuple, seg.Header.SeqNum, seg.Header.AckNum, len(seg.Payload))
	}

	// Debug: log data segments with payload > 50 bytes to trace SSH/KEXINIT flow
	if len(seg.Payload) > 50 {
		preview := len(seg.Payload)
		if preview > 64 {
			preview = 64
		}
		log.Printf("TCP DATA: %s:%d→%s:%d seq=%d ack=%d flags=%02x win=%d len=%d cs=%04x payload=%x",
			seg.Tuple.SrcIPNet(), seg.Tuple.SrcPort,
			dstIP, seg.Tuple.DstPort,
			seg.Header.SeqNum, seg.Header.AckNum,
			seg.Header.Flags, seg.Header.WindowSize,
			len(seg.Payload), cs,
			seg.Payload[:preview])
	} else if s.cfg.Debug {
		log.Printf("TCP send: %s:%d → %s:%d (flags=%d, seq=%d, ack=%d, len=%d, dstMAC=%s)",
			seg.Tuple.SrcIPNet(), seg.Tuple.SrcPort,
			dstIP, seg.Tuple.DstPort,
			seg.Header.Flags, seg.Header.SeqNum, seg.Header.AckNum,
			len(seg.Payload), dstMAC)
	}

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

	debug.Global.OutSegs.Add(1)
	debug.Global.OutBytes.Add(int64(len(seg.Payload)))
	err := s.writeIPv4Packet(dstMAC, ipPkt)
	if err == syscall.ENOBUFS {
		debug.Global.OutBufFull.Add(1)
	}
	return err
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

	_ = s.writeIPv4Packet(dstMAC, ipPkt)
}

// writeIPv4Packet serializes and writes an IP packet as an Ethernet frame.
func (s *Stack) writeIPv4Packet(dstMAC net.HardwareAddr, pkt *ipv4.Packet) error {
	if s.conn == nil {
		return nil
	}
	ipBytes := pkt.Serialize()
	frame := &ether.Frame{
		DstMAC:    dstMAC,
		SrcMAC:    s.cfg.GatewayMAC,
		EtherType: ether.EtherTypeIPv4,
		Payload:   ipBytes,
	}

	if err := s.conn.WriteFrame(frame); err != nil {
		return err
	}
	s.bytesOut += uint64(len(ipBytes))
	return nil
}

// TCPState returns the TCP state engine.
func (s *Stack) TCPState() *tcp.TCPState {
	return s.tcpState
}

// BytesIn returns total bytes received.
func (s *Stack) BytesIn() uint64 { return s.bytesIn }

// BytesOut returns total bytes sent.
func (s *Stack) BytesOut() uint64 { return s.bytesOut }
