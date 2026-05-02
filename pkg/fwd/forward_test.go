package fwd

import (
	"fmt"
	"net"
	"testing"

	"github.com/pinyin/bdp-netstack/pkg/tcp"
)

// freePort returns an available TCP port on localhost.
func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestForwarderNew(t *testing.T) {
	p1, p2 := freePort(), freePort()
	mappings := []Mapping{
		{HostPort: uint16(p1), VMIP: net.ParseIP("192.168.65.2"), VMPort: 22},
		{HostPort: uint16(p2), VMIP: net.ParseIP("192.168.65.2"), VMPort: 80},
	}

	f, err := New(net.ParseIP("192.168.65.1"), mappings)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if len(f.listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %d", len(f.listeners))
	}
	if len(f.mappings) != 2 {
		t.Fatalf("expected 2 mappings, got %d", len(f.mappings))
	}

	// Close listeners to release ports
	for _, ln := range f.listeners {
		ln.Close()
	}
}

func TestForwarderAccept(t *testing.T) {
	port := freePort()
	mappings := []Mapping{
		{HostPort: uint16(port), VMIP: net.ParseIP("192.168.65.2"), VMPort: 22},
	}

	f, err := New(net.ParseIP("192.168.65.1"), mappings)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		for _, ln := range f.listeners {
			ln.Close()
		}
	}()

	tsCfg := tcp.DefaultConfig()
	tsCfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := tcp.NewTCPState(tsCfg)

	// Dial the forwarded port
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// PollAccept should accept the connection and create a VM-side TCP conn
	f.PollAccept(ts)

	if f.Count() != 1 {
		t.Fatalf("expected 1 forwarded connection, got %d", f.Count())
	}

	// The TCP stack should have a connection in SynSent
	if ts.ConnectionCount() != 1 {
		t.Fatalf("expected 1 TCP connection, got %d", ts.ConnectionCount())
	}

	t.Log("Forwarder accepted connection and created TCP connection in SynSent")
}

func TestForwarderCleanup(t *testing.T) {
	port := freePort()
	mappings := []Mapping{
		{HostPort: uint16(port), VMIP: net.ParseIP("192.168.65.2"), VMPort: 22},
	}

	f, err := New(net.ParseIP("192.168.65.1"), mappings)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		for _, ln := range f.listeners {
			ln.Close()
		}
	}()

	// Manually add an entry and mark it closed
	f.entries[5] = &Entry{
		HostConn:   nil,
		VMConn:     nil,
		HostClosed: true,
		VMClosed:   true,
	}
	if f.Count() != 1 {
		t.Fatalf("expected 1 entry, got %d", f.Count())
	}

	f.Cleanup()
	if f.Count() != 0 {
		t.Fatalf("expected 0 entries after cleanup, got %d", f.Count())
	}
}

func TestCreateVMTuple(t *testing.T) {
	f := &Forwarder{
		gatewayIP: net.ParseIP("192.168.65.1"),
		mappings: map[uint16]Mapping{
			2222: {HostPort: 2222, VMIP: net.ParseIP("192.168.65.2"), VMPort: 22},
		},
	}

	tuple, addr := f.createVMTuple(2222)
	if tuple == nil {
		t.Fatal("expected non-nil tuple")
	}
	// Source port should be in ephemeral range (32768..60999)
	if tuple.SrcPort < 32768 || tuple.SrcPort > 60999 {
		t.Fatalf("expected gw port in 32768..60999, got %d", tuple.SrcPort)
	}
	if tuple.DstPort != 22 {
		t.Fatalf("expected VM port 22, got %d", tuple.DstPort)
	}
	if !tuple.SrcIPNet().Equal(net.ParseIP("192.168.65.1")) {
		t.Fatalf("expected src IP 192.168.65.1, got %s", tuple.SrcIPNet())
	}
	if addr != "192.168.65.2:22" {
		t.Fatalf("expected addr 192.168.65.2:22, got %s", addr)
	}
}
