package udpnat

import (
	"net"
	"testing"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/udp"
)

func TestInterceptNewDatagram(t *testing.T) {
	table := NewTable()

	srcIP := net.ParseIP("192.168.65.2")
	dstIP := net.ParseIP("8.8.8.8")
	dg := &udp.UDPDatagram{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 12345,
		DstPort: 53,
		Payload: []byte("test-dns-query"),
	}

	handled := table.Intercept(dg)
	if !handled {
		t.Fatal("Intercept should return true for external UDP datagram")
	}
	if table.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", table.Count())
	}

	// Verify the key
	k := makeKey(srcIP, dstIP, 12345, 53)
	entry, ok := table.entries[k]
	if !ok {
		t.Fatal("entry not found for key")
	}
	if len(entry.egressQ) != 1 {
		t.Fatalf("expected 1 egress datagram, got %d", len(entry.egressQ))
	}
	if entry.closed {
		t.Fatal("new entry should not be closed")
	}
}

func TestInterceptExisting(t *testing.T) {
	table := NewTable()

	srcIP := net.ParseIP("192.168.65.2")
	dstIP := net.ParseIP("1.1.1.1")
	dg1 := &udp.UDPDatagram{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 12345,
		DstPort: 53,
		Payload: []byte("query-1"),
	}
	dg2 := &udp.UDPDatagram{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: 12345,
		DstPort: 53,
		Payload: []byte("query-2"),
	}

	table.Intercept(dg1)
	table.Intercept(dg2)

	if table.Count() != 1 {
		t.Fatalf("expected 1 entry (same key), got %d", table.Count())
	}

	k := makeKey(srcIP, dstIP, 12345, 53)
	entry := table.entries[k]
	if len(entry.egressQ) != 2 {
		t.Fatalf("expected 2 egress datagrams, got %d", len(entry.egressQ))
	}
}

func TestInterceptDifferentDestinations(t *testing.T) {
	table := NewTable()

	srcIP := net.ParseIP("192.168.65.2")
	dg1 := &udp.UDPDatagram{
		SrcIP: srcIP, DstIP: net.ParseIP("8.8.8.8"),
		SrcPort: 12345, DstPort: 53,
		Payload: []byte("query-1"),
	}
	dg2 := &udp.UDPDatagram{
		SrcIP: srcIP, DstIP: net.ParseIP("1.1.1.1"),
		SrcPort: 12345, DstPort: 53,
		Payload: []byte("query-2"),
	}

	table.Intercept(dg1)
	table.Intercept(dg2)

	if table.Count() != 2 {
		t.Fatalf("expected 2 entries (different destinations), got %d", table.Count())
	}
}

func TestInterceptSameSrcDifferentPorts(t *testing.T) {
	table := NewTable()

	srcIP := net.ParseIP("192.168.65.2")
	dstIP := net.ParseIP("8.8.8.8")
	dg1 := &udp.UDPDatagram{
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: 12345, DstPort: 53,
		Payload: []byte("query-1"),
	}
	dg2 := &udp.UDPDatagram{
		SrcIP: srcIP, DstIP: dstIP,
		SrcPort: 12346, DstPort: 53,
		Payload: []byte("query-2"),
	}

	table.Intercept(dg1)
	table.Intercept(dg2)

	if table.Count() != 2 {
		t.Fatalf("expected 2 entries (different src ports), got %d", table.Count())
	}
}

func TestFlushEgress(t *testing.T) {
	// This test verifies FlushEgress processes queues without panicking.
	// Actual UDP writes are tested via integration/e2e tests.
	table := NewTable()

	dg := &udp.UDPDatagram{
		SrcIP:   net.ParseIP("192.168.65.2"),
		DstIP:   net.ParseIP("8.8.8.8"),
		SrcPort: 12345,
		DstPort: 53,
		Payload: []byte("test"),
	}

	table.Intercept(dg)

	// FlushEgress should not panic even if host socket write fails
	table.FlushEgress()

	// After flush, egress queue should be empty
	k := makeKey(net.ParseIP("192.168.65.2"), net.ParseIP("8.8.8.8"), 12345, 53)
	entry := table.entries[k]
	if len(entry.egressQ) != 0 {
		t.Fatalf("expected empty egress queue after flush, got %d", len(entry.egressQ))
	}
}

func TestCleanup(t *testing.T) {
	table := NewTable()

	// Create an entry via Intercept (which sets lastActive = time.Now())
	dg := &udp.UDPDatagram{
		SrcIP:   net.ParseIP("192.168.65.2"),
		DstIP:   net.ParseIP("8.8.8.8"),
		SrcPort: 12345,
		DstPort: 53,
		Payload: []byte("test"),
	}
	table.Intercept(dg)

	if table.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", table.Count())
	}

	// Advance time beyond idle timeout
	future := time.Now().Add(IdleTimeout + time.Second)
	table.Cleanup(future)

	if table.Count() != 0 {
		t.Fatalf("expected 0 entries after idle timeout, got %d", table.Count())
	}
}

func TestCleanupKeepsActiveEntry(t *testing.T) {
	table := NewTable()

	dg := &udp.UDPDatagram{
		SrcIP:   net.ParseIP("192.168.65.2"),
		DstIP:   net.ParseIP("8.8.8.8"),
		SrcPort: 12345,
		DstPort: 53,
		Payload: []byte("test"),
	}
	table.Intercept(dg)

	// Cleanup at current time should NOT remove active entry
	table.Cleanup(time.Now())

	if table.Count() != 1 {
		t.Fatalf("expected 1 active entry, got %d", table.Count())
	}
}

func TestDeliverToVM(t *testing.T) {
	table := NewTable()

	// Manually add an ingress datagram to simulate host data
	k := makeKey(net.ParseIP("192.168.65.2"), net.ParseIP("8.8.8.8"), 12345, 53)
	entry := &Entry{
		Key:        k,
		lastActive: time.Now(),
	}
	entry.ingressQ = append(entry.ingressQ, &udp.UDPDatagram{
		SrcIP:   net.ParseIP("8.8.8.8"),
		DstIP:   net.ParseIP("192.168.65.2"),
		SrcPort: 53,
		DstPort: 12345,
		Payload: []byte("dns-response"),
	})
	table.entries[k] = entry

	delivered := table.DeliverToVM()
	if len(delivered) != 1 {
		t.Fatalf("expected 1 delivered datagram, got %d", len(delivered))
	}
	if delivered[0].SrcPort != 53 || delivered[0].DstPort != 12345 {
		t.Fatalf("expected ports (53, 12345), got (%d, %d)", delivered[0].SrcPort, delivered[0].DstPort)
	}

	// After delivery, ingress queue should be cleared
	if len(entry.ingressQ) != 0 {
		t.Fatalf("expected empty ingress queue after delivery, got %d", len(entry.ingressQ))
	}
}

func TestMakeKey(t *testing.T) {
	srcIP := net.ParseIP("192.168.65.2")
	dstIP := net.ParseIP("8.8.8.8")
	k := makeKey(srcIP, dstIP, 12345, 53)

	if k.SrcPort != 12345 || k.DstPort != 53 {
		t.Fatalf("ports mismatch: %d, %d", k.SrcPort, k.DstPort)
	}
	if net.IP(k.SrcIP[:]).String() != "192.168.65.2" {
		t.Fatalf("src IP mismatch: %s", net.IP(k.SrcIP[:]).String())
	}
	if net.IP(k.DstIP[:]).String() != "8.8.8.8" {
		t.Fatalf("dst IP mismatch: %s", net.IP(k.DstIP[:]).String())
	}
}
