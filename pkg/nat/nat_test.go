package nat

import (
	"net"
	"testing"

	"github.com/pinyin/bdp-netstack/pkg/tcp"
)

func TestTableInterceptNewSYN(t *testing.T) {
	nt := NewTable()

	tsCfg := tcp.DefaultConfig()
	tsCfg.GatewayIP = net.ParseIP("192.168.65.1")
	tsCfg.BufferSize = 65536
	ts := tcp.NewTCPState(tsCfg)

	// Simulate a SYN from VM to external IP
	vmIP := net.ParseIP("192.168.65.2")
	extIP := net.ParseIP("93.184.216.34")

	synSeg := fakeTCPSegment(vmIP, extIP, 12345, 80, 1000, 0, tcp.FlagSYN, nil)

	handled := nt.Intercept(synSeg, ts)
	if !handled {
		t.Fatal("expected SYN to be handled by NAT")
	}

	if nt.Count() != 1 {
		t.Fatalf("expected 1 NAT entry, got %d", nt.Count())
	}

	// The connection should be created in our TCP stack
	if ts.ConnectionCount() != 1 {
		t.Fatalf("expected 1 TCP connection, got %d", ts.ConnectionCount())
	}

	// Check that pending dials were queued
	if len(nt.pendingDials) != 1 {
		t.Fatalf("expected 1 pending dial, got %d", len(nt.pendingDials))
	}
}

func TestTableInterceptExistingConn(t *testing.T) {
	nt := NewTable()

	tsCfg := tcp.DefaultConfig()
	tsCfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := tcp.NewTCPState(tsCfg)

	vmIP := net.ParseIP("192.168.65.2")
	extIP := net.ParseIP("93.184.216.34")

	// First SYN creates entry
	syn1 := fakeTCPSegment(vmIP, extIP, 12345, 80, 1000, 0, tcp.FlagSYN, nil)
	nt.Intercept(syn1, ts)

	// Second segment (e.g., ACK for SYN-ACK) goes to existing entry
	ack := fakeTCPSegment(vmIP, extIP, 12345, 80, 1001, 1, tcp.FlagACK, nil)
	handled := nt.Intercept(ack, ts)
	if !handled {
		t.Fatal("expected ACK to be handled by NAT")
	}

	if nt.Count() != 1 {
		t.Fatalf("expected still 1 NAT entry, got %d", nt.Count())
	}

	// Check the segment was added to the VM connection
	for _, entry := range nt.entries {
		if len(entry.VMConn.PendingSegs) != 1 {
			t.Fatalf("expected 1 pending seg on VM conn, got %d", len(entry.VMConn.PendingSegs))
		}
	}
}

func TestTableCleanup(t *testing.T) {
	nt := NewTable()

	tsCfg := tcp.DefaultConfig()
	tsCfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := tcp.NewTCPState(tsCfg)

	vmIP := net.ParseIP("192.168.65.2")
	extIP := net.ParseIP("93.184.216.34")

	syn := fakeTCPSegment(vmIP, extIP, 12345, 80, 1000, 0, tcp.FlagSYN, nil)
	nt.Intercept(syn, ts)

	// Mark entry as closed on both sides and cleanup
	for _, entry := range nt.entries {
		entry.HostClosed = true
		entry.VMClosed = true
	}
	nt.Cleanup()

	if nt.Count() != 0 {
		t.Fatalf("expected 0 entries after cleanup, got %d", nt.Count())
	}
}

func TestTableNonSYNIgnored(t *testing.T) {
	nt := NewTable()
	tsCfg := tcp.DefaultConfig()
	tsCfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := tcp.NewTCPState(tsCfg)

	vmIP := net.ParseIP("192.168.65.2")
	extIP := net.ParseIP("93.184.216.34")

	// Non-SYN segment to unknown destination should not create entry
	ack := fakeTCPSegment(vmIP, extIP, 12345, 80, 1001, 0, tcp.FlagACK, nil)
	handled := nt.Intercept(ack, ts)
	if handled {
		t.Fatal("expected non-SYN to be ignored for unknown connection")
	}
	if nt.Count() != 0 {
		t.Fatalf("expected 0 entries, got %d", nt.Count())
	}
}

// fakeTCPSegment creates a test TCP segment with the given parameters.
func fakeTCPSegment(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) *tcp.TCPSegment {
	h := &tcp.TCPHeader{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		Flags:      flags,
		WindowSize: 65535,
		DataOffset: 20,
	}
	return &tcp.TCPSegment{
		Header:  h,
		Payload: payload,
		Tuple:   tcp.NewTuple(srcIP, dstIP, srcPort, dstPort),
	}
}
