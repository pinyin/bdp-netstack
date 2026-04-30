package udp

import (
	"net"
	"testing"
)

func TestParseUDP(t *testing.T) {
	payload := []byte("hello")
	datagram := BuildDatagram(1234, 53, payload)

	hdr, p, err := ParseUDP(datagram)
	if err != nil {
		t.Fatalf("ParseUDP: %v", err)
	}
	if hdr.SrcPort != 1234 {
		t.Fatalf("expected src port 1234, got %d", hdr.SrcPort)
	}
	if hdr.DstPort != 53 {
		t.Fatalf("expected dst port 53, got %d", hdr.DstPort)
	}
	if string(p) != "hello" {
		t.Fatalf("expected payload 'hello', got '%s'", string(p))
	}
}

func TestMuxDispatch(t *testing.T) {
	mux := NewMux()
	var received *UDPDatagram

	mux.Register(53, func(dg *UDPDatagram) []*UDPDatagram {
		received = dg
		return []*UDPDatagram{{
			SrcIP:   dg.DstIP,
			DstIP:   dg.SrcIP,
			SrcPort: dg.DstPort,
			DstPort: dg.SrcPort,
			Payload: []byte("response"),
		}}
	})

	dg := &UDPDatagram{
		SrcIP:   net.ParseIP("192.168.65.2"),
		DstIP:   net.ParseIP("192.168.65.1"),
		SrcPort: 12345,
		DstPort: 53,
		Payload: []byte("query"),
	}
	mux.Deliver(dg)

	if received == nil {
		t.Fatal("handler not called")
	}
	if string(received.Payload) != "query" {
		t.Fatalf("expected 'query', got '%s'", string(received.Payload))
	}

	outputs := mux.ConsumeOutputs()
	if len(outputs) != 1 {
		t.Fatalf("expected 1 output, got %d", len(outputs))
	}
	if string(outputs[0].Payload) != "response" {
		t.Fatalf("expected 'response', got '%s'", string(outputs[0].Payload))
	}
}

func TestMuxNoHandler(t *testing.T) {
	mux := NewMux()
	dg := &UDPDatagram{
		SrcIP:   net.ParseIP("192.168.65.2"),
		DstIP:   net.ParseIP("192.168.65.1"),
		SrcPort: 12345,
		DstPort: 9999, // no handler
		Payload: []byte("data"),
	}
	mux.Deliver(dg)
	if len(mux.ConsumeOutputs()) != 0 {
		t.Fatal("expected no output for unhandled port")
	}
}
