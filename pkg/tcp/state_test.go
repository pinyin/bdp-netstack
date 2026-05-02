package tcp

import (
	"net"
	"testing"
	"time"
)

func TestHandshake(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")

	ts := NewTCPState(cfg)

	var accepted *Conn
	ts.Listen(func(c *Conn) {
		accepted = c
	})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	// Step 1: VM sends SYN → should create SynRcvd entry
	synSeg := fakeSegment(vmIP, gwIP, 12345, 8080, 1000, 0, FlagSYN, nil)
	ts.InjectSegment(synSeg)
	ts.Deliberate(time.Now())

	if len(ts.SynRcvd) != 1 {
		t.Fatalf("expected 1 SynRcvd connection, got %d", len(ts.SynRcvd))
	}

	// Should have generated a SYN-ACK
	outputs := ts.ConsumeOutputs()
	if len(outputs) == 0 {
		t.Fatal("expected SYN-ACK output")
	}
	synAck := outputs[0]
	if !synAck.Header.HasFlag(FlagSYN | FlagACK) {
		t.Fatalf("expected SYN|ACK, got flags=%02x", synAck.Header.Flags)
	}
	if synAck.Header.AckNum != 1001 { // IRS + 1
		t.Fatalf("expected ACK=1001, got %d", synAck.Header.AckNum)
	}

	// Step 2: VM sends ACK confirming SYN-ACK → should move to Established
	ackSeg := fakeSegment(vmIP, gwIP, 12345, 8080, 1001, synAck.Header.SeqNum+1, FlagACK, nil)
	ts.InjectSegment(ackSeg)
	ts.Deliberate(time.Now())

	if len(ts.SynRcvd) != 0 {
		t.Fatalf("expected 0 SynRcvd, got %d", len(ts.SynRcvd))
	}

	var conn *Conn
	for _, c := range ts.Established {
		conn = c
		break
	}
	if conn == nil {
		t.Fatal("expected connection in Established")
	}

	if accepted == nil {
		t.Fatal("expected accept callback to be called")
	}
	if accepted != conn {
		t.Fatal("accepted connection != established connection")
	}

	t.Logf("Handshake complete: %s", conn.Tuple)
}

func TestDataTransfer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")

	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	// Complete handshake
	doHandshake(t, ts, vmIP, gwIP, 12345, 8080)

	var conn *Conn
	for _, c := range ts.Established {
		conn = c
		break
	}

	// Send data from VM
	payload := []byte("hello world")
	dataSeg := fakeSegment(vmIP, gwIP, 12345, 8080, 1001, conn.ISS+1, FlagACK|FlagPSH, payload)
	ts.InjectSegment(dataSeg)
	ts.Deliberate(time.Now())

	buf := make([]byte, 1024)
	n := conn.ReadRecvBuf(buf)
	if n != len(payload) {
		t.Fatalf("expected %d bytes, got %d", len(payload), n)
	}
	if string(buf[:n]) != "hello world" {
		t.Fatalf("expected 'hello world', got '%s'", string(buf[:n]))
	}

	// Immediate ACK: ACK is sent in the same round as data receipt.
	// With 1ms BPT, the peer naturally gets one ACK per tick covering all
	// segments in the batch — that's already perfect batching without
	// extra round-trip delays that would starve the peer's cwnd.
	outputs := ts.ConsumeOutputs()
	hasAck := false
	for _, out := range outputs {
		if out.Header.HasFlag(FlagACK) && out.Header.AckNum == 1001+uint32(len(payload)) {
			hasAck = true
		}
	}
	if !hasAck {
		t.Fatal("expected immediate ACK for received data")
	}
}

func TestForwardCascade(t *testing.T) {
	// Verify that a connection cascades through multiple states in one round.
	// Active close path: ESTABLISHED → FIN_WAIT1 → FIN_WAIT2 (app closes first)
	// Passive close path: ESTABLISHED → CLOSE_WAIT → LAST_ACK (peer FIN first)
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")

	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	// Test 1: Passive close cascade (peer FIN → CloseWait → (AppClose) → LastAck)
	doHandshake(t, ts, vmIP, gwIP, 12345, 8080)
	var conn *Conn
	for _, c := range ts.Established {
		conn = c
		break
	}

	// Inject FIN from peer → should go to CloseWait
	finSeg := fakeSegment(vmIP, gwIP, 12345, 8080, 1001, conn.ISS+1, FlagACK|FlagFIN, nil)
	ts.InjectSegment(finSeg)
	ts.Deliberate(time.Now())

	if _, ok := ts.CloseWait[conn.Tuple]; !ok {
		t.Fatalf("expected connection in CloseWait after peer FIN. CloseWait=%d, Established=%d",
			len(ts.CloseWait), len(ts.Established))
	}

	// Now AppClose + last ACK in same round: CloseWait → LastAck → cleanup
	ts.AppClose(conn.Tuple)
	ackOurFin := fakeSegment(vmIP, gwIP, 12345, 8080, 1002, conn.ISS+2, FlagACK, nil)
	ts.InjectSegment(ackOurFin)
	ts.Deliberate(time.Now())

	if _, ok := ts.LastAck[conn.Tuple]; ok {
		t.Fatal("expected connection cleaned up from LastAck after ACK of our FIN")
	}
	if ts.ConnectionCount() != 0 {
		t.Fatalf("expected 0 connections after cleanup, got %d", ts.ConnectionCount())
	}

	// Consume leftover outputs from test 1 to avoid contaminating test 2's handshake
	ts.ConsumeOutputs()

	// Test 2: Active close cascade (app close → FinWait1, then ACK → FinWait2)
	doHandshake(t, ts, vmIP, gwIP, 12346, 8080)
	for _, c := range ts.Established {
		conn = c
		break
	}

	// Round 1: AppClose moves to FinWait1, advanceFinWait1 sends FIN
	ts.AppClose(conn.Tuple)
	ts.Deliberate(time.Now())

	if _, ok := ts.FinWait1[conn.Tuple]; !ok {
		t.Fatalf("expected connection in FinWait1 after AppClose. FinWait1=%d, Established=%d",
			len(ts.FinWait1), len(ts.Established))
	}

	// Round 2: VM ACKs our FIN → FinWait2
	ackFin := fakeSegment(vmIP, gwIP, 12346, 8080, 1001, conn.ISS+2, FlagACK, nil)
	ts.InjectSegment(ackFin)
	ts.Deliberate(time.Now())

	if _, ok := ts.FinWait2[conn.Tuple]; !ok {
		t.Fatalf("expected connection in FinWait2 after FIN ACK. FinWait1=%d, FinWait2=%d",
			len(ts.FinWait1), len(ts.FinWait2))
	}
}

func TestStateAsPosition(t *testing.T) {
	// Verify that a connection's state IS its collection membership
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")

	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	// Handshake
	doHandshake(t, ts, vmIP, gwIP, 12345, 8080)

	// Verify the conn is only in Established, not in any other collection
	if ts.ConnectionCount() != 1 {
		t.Fatalf("expected 1 total connection, got %d", ts.ConnectionCount())
	}
	if len(ts.Established) != 1 {
		t.Fatalf("expected 1 in Established, got %d", len(ts.Established))
	}
	if len(ts.SynRcvd) != 0 {
		t.Fatal("conn should NOT be in SynRcvd")
	}
	if len(ts.FinWait1) != 0 {
		t.Fatal("conn should NOT be in FinWait1")
	}

	// The connection has no State field to read — its state is purely positional
}

func TestActiveOpen(t *testing.T) {
	// Test that ActiveOpen creates a conn in SynSent, sends SYN,
	// and on SYN-ACK reply transitions to Established.
	cfg := DefaultConfig()
	cfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := NewTCPState(cfg)

	gwIP := net.ParseIP("192.168.65.1")
	vmIP := net.ParseIP("192.168.65.2")

	// Active open: GW initiates connection to VM port 22
	tuple := NewTuple(gwIP, vmIP, 32768, 22)
	conn := ts.ActiveOpen(tuple, 65535)

	if conn == nil {
		t.Fatal("ActiveOpen returned nil")
	}
	if len(ts.SynSent) != 1 {
		t.Fatalf("expected 1 SynSent, got %d", len(ts.SynSent))
	}

	// Deliberate should trigger SYN send
	ts.Deliberate(time.Now())
	outputs := ts.ConsumeOutputs()

	if len(outputs) == 0 {
		t.Fatal("expected SYN output")
	}
	syn := outputs[0]
	if !syn.Header.HasFlag(FlagSYN) || syn.Header.HasFlag(FlagACK) {
		t.Fatalf("expected pure SYN, got flags=%02x", syn.Header.Flags)
	}
	if syn.Header.SeqNum != conn.ISS {
		t.Fatalf("expected SYN seq=%d, got %d", conn.ISS, syn.Header.SeqNum)
	}

	// VM responds with SYN-ACK
	synAckSeg := fakeSegment(vmIP, gwIP, 22, 32768, 5000, conn.ISS+1, FlagSYN|FlagACK, nil)
	ts.InjectSegment(synAckSeg)
	ts.Deliberate(time.Now())

	// Connection should now be in Established
	if len(ts.SynSent) != 0 {
		t.Fatalf("expected 0 SynSent, got %d", len(ts.SynSent))
	}
	if _, ok := ts.Established[tuple]; !ok {
		t.Fatal("expected connection in Established")
	}

	// Should have sent ACK for SYN-ACK
	outputs = ts.ConsumeOutputs()
	hasAck := false
	for _, out := range outputs {
		if out.Header.HasFlag(FlagACK) && out.Header.AckNum == 5001 {
			hasAck = true
		}
	}
	if !hasAck {
		t.Fatal("expected ACK for SYN-ACK")
	}
}

func TestIdleTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")
	cfg.IdleTimeout = 100 * time.Millisecond

	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	// Establish a connection
	doHandshake(t, ts, vmIP, gwIP, 12345, 8080)

	if ts.ConnectionCount() != 1 {
		t.Fatalf("expected 1 connection, got %d", ts.ConnectionCount())
	}

	// Advance tick past idle timeout (10ms per slot, so 100ms = 10 slots)
	ts.tick += int64(100*time.Millisecond) / int64(ts.timerWheel.SlotDuration())
	ts.tick += 1 // one past the threshold

	ts.reclaimIdle()

	if ts.ConnectionCount() != 0 {
		t.Fatalf("expected 0 connections after idle timeout, got %d", ts.ConnectionCount())
	}
}

func TestPreProcessACKsDoesNotCorruptSendBuf(t *testing.T) {
	// Regression test: PreProcessACKs should NOT call AckSendBuf for SynSent
	// connections, because the ACK covers the SYN byte (control flag), not a
	// data byte in the SendBuf. If AckSendBuf is called with the SYN-ACK's
	// AckNum, sendHead advances by 1 and the first data byte is lost.
	//
	// This bug caused SSH to fail: "SSH-2.0-OpenSSH_10.2\r\n" (22 bytes)
	// was truncated to "SH-2.0-OpenSSH_10.2\r\n" (21 bytes), which the
	// VM SSH server rejected as "Invalid SSH identification string."
	cfg := DefaultConfig()
	cfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := NewTCPState(cfg)

	gwIP := net.ParseIP("192.168.65.1")
	vmIP := net.ParseIP("192.168.65.2")

	// Active open: forwarder creates SynSent connection
	tuple := NewTuple(gwIP, vmIP, 32769, 22)
	conn := ts.ActiveOpen(tuple, 65535)

	// Deliberate to send SYN
	ts.Deliberate(time.Now())
	ts.ConsumeOutputs()

	// Write 22 bytes to SendBuf — simulates forwarder reading SSH ident
	testData := []byte("SSH-2.0-OpenSSH_10.2\r\n")
	if len(testData) != 22 {
		t.Fatalf("test data must be 22 bytes, got %d", len(testData))
	}
	n := conn.WriteSendBuf(testData)
	if n != 22 {
		t.Fatalf("WriteSendBuf returned %d, expected 22", n)
	}
	if conn.SendAvail() != 22 {
		t.Fatalf("SendAvail = %d, expected 22", conn.SendAvail())
	}
	sendHeadBefore := conn.sendHead

	// Inject SYN-ACK from VM
	synAckSeg := fakeSegment(vmIP, gwIP, 22, 32769, 5000, conn.ISS+1, FlagSYN|FlagACK, nil)
	ts.InjectSegment(synAckSeg)

	// PreProcessACKs should NOT touch SynSent connections
	ts.PreProcessACKs()

	// SendBuf must be unchanged: sendHead still at 0, sendSize still 22
	if conn.sendHead != sendHeadBefore {
		t.Fatalf("PreProcessACKs moved sendHead from %d to %d — SYN byte was incorrectly consumed from SendBuf",
			sendHeadBefore, conn.sendHead)
	}
	if conn.SendAvail() != 22 {
		t.Fatalf("PreProcessACKs corrupted SendBuf: SendAvail = %d, expected 22", conn.SendAvail())
	}

	// Deliberate: advanceSynSent → Established, then advanceEstablished → send data
	ts.Deliberate(time.Now())

	// Verify connection moved to Established
	if _, ok := ts.Established[tuple]; !ok {
		t.Fatal("expected connection in Established after SYN-ACK")
	}

	// Verify the 22-byte data was sent correctly
	outputs := ts.ConsumeOutputs()
	var dataLen int
	for _, out := range outputs {
		if len(out.Payload) > 0 {
			dataLen += len(out.Payload)
			if len(out.Payload) != 22 {
				t.Errorf("data payload length = %d, expected 22", len(out.Payload))
			}
			if string(out.Payload) != string(testData) {
				t.Errorf("data payload = %q, expected %q", string(out.Payload), string(testData))
			}
		}
	}
	if dataLen != 22 {
		t.Errorf("total data sent = %d bytes, expected 22", dataLen)
	}
}

func TestZeroWindowFlowControl(t *testing.T) {
	// Peer advertises WindowSize=0 → we must NOT send data.
	// Regression: the old code had `if window == 0 { window = 65535 }`
	// which ignored the peer's zero-window advertisement entirely.
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	doHandshake(t, ts, vmIP, gwIP, 12345, 8080)

	var conn *Conn
	for _, c := range ts.Established {
		conn = c
		break
	}

	// Write data to send
	ts.AppWrite(conn.Tuple, []byte("hello world"))
	ts.Deliberate(time.Now())
	outputs := ts.ConsumeOutputs()

	// Should have sent data in the first round
	var dataSent bool
	for _, out := range outputs {
		if len(out.Payload) > 0 {
			dataSent = true
		}
	}
	if !dataSent {
		t.Fatal("expected data segments in first round")
	}

	// Peer ACKs our data but sets WindowSize=0 (closes the receive window).
	// AckNum must cover the data we just sent.
	ackSeg := fakeSegment(vmIP, gwIP, 12345, 8080, 1001, conn.SND_NXT, FlagACK, nil)
	ackSeg.Header.WindowSize = 0
	ts.InjectSegment(ackSeg)

	// Write more data — this MUST NOT be sent because window is closed.
	ts.AppWrite(conn.Tuple, []byte("more data"))
	ts.Deliberate(time.Now())
	outputs = ts.ConsumeOutputs()

	for _, out := range outputs {
		if len(out.Payload) > 0 {
			t.Fatal("sent data despite zero-window advertisement from peer")
		}
	}

	// Peer reopens window → data should flow again.
	reopenSeg := fakeSegment(vmIP, gwIP, 12345, 8080, 1001, conn.SND_NXT, FlagACK, nil)
	reopenSeg.Header.WindowSize = 65535
	ts.InjectSegment(reopenSeg)
	ts.Deliberate(time.Now())
	outputs = ts.ConsumeOutputs()

	dataSent = false
	for _, out := range outputs {
		if len(out.Payload) > 0 {
			dataSent = true
		}
	}
	if !dataSent {
		t.Fatal("expected data after window reopened")
	}
}

func TestLastAckFINAckDetection(t *testing.T) {
	// ACK that covers data but NOT the FIN must not clean up the connection.
	// Regression: advanceLastAck treated any ACK that advanced SND_UNA
	// as acking the FIN (since FinSent is always true in LastAck).
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	doHandshake(t, ts, vmIP, gwIP, 12345, 8080)

	var conn *Conn
	for _, c := range ts.Established {
		conn = c
		break
	}
	iss := conn.ISS

	// Round 1: Send data. SND_NXT advances past ISS.
	ts.AppWrite(conn.Tuple, []byte("hello"))
	ts.Deliberate(time.Now())
	ts.ConsumeOutputs()

	sndNxtAfterData := conn.SND_NXT // ISS+1+5 = ISS+6

	// Round 2: Peer sends standalone FIN without acking our data.
	// AckNum=ISS+1 so SND_UNA stays at ISS+1.
	finSeg := fakeSegment(vmIP, gwIP, 12345, 8080, 1001, iss+1, FlagACK|FlagFIN, nil)
	ts.InjectSegment(finSeg)
	ts.Deliberate(time.Now())

	if _, ok := ts.CloseWait[conn.Tuple]; !ok {
		t.Fatalf("expected conn in CloseWait after peer FIN, got Established=%d CloseWait=%d",
			len(ts.Established), len(ts.CloseWait))
	}

	// Round 3: AppClose + sendFIN.
	ts.AppClose(conn.Tuple)
	ts.Deliberate(time.Now())

	if _, ok := ts.LastAck[conn.Tuple]; !ok {
		t.Fatalf("expected conn in LastAck after AppClose, got CloseWait=%d LastAck=%d",
			len(ts.CloseWait), len(ts.LastAck))
	}

	sndNxtAfterFIN := conn.SND_NXT // sndNxtAfterData + 1

	// Round 4: ACK covers our data (up to sndNxtAfterData) but NOT the FIN.
	// The FIN seq is sndNxtAfterData, so an ACK with AckNum=sndNxtAfterData
	// means "I received up to before the FIN; FIN is NOT acked."
	dataOnlyAck := fakeSegment(vmIP, gwIP, 12345, 8080, 1002, sndNxtAfterData, FlagACK, nil)
	ts.InjectSegment(dataOnlyAck)
	ts.Deliberate(time.Now())

	if _, ok := ts.LastAck[conn.Tuple]; !ok {
		t.Fatal("connection incorrectly cleaned up: ACK covered data but NOT the FIN")
	}

	// Round 5: ACK that covers the FIN (AckNum == sndNxtAfterFIN).
	finAck := fakeSegment(vmIP, gwIP, 12345, 8080, 1002, sndNxtAfterFIN, FlagACK, nil)
	ts.InjectSegment(finAck)
	ts.Deliberate(time.Now())

	if _, ok := ts.LastAck[conn.Tuple]; ok {
		t.Fatal("connection should be cleaned up after FIN is acked")
	}
	if ts.ConnectionCount() != 0 {
		t.Fatalf("expected 0 connections, got %d", ts.ConnectionCount())
	}
}

func TestEstablishedToCloseWaitPreservesData(t *testing.T) {
	// Data arriving in the same batch as FIN must survive the
	// Established→CloseWait transition.
	// Regression: advanceEstablished set conn.PendingSegs=nil on
	// state transition, discarding data that arrived with the FIN.
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	doHandshake(t, ts, vmIP, gwIP, 12345, 8080)

	var conn *Conn
	for _, c := range ts.Established {
		conn = c
		break
	}

	// Inject a data segment and a FIN segment in the same batch.
	// The data segment has SeqNum=RCV_NXT and the FIN follows it.
	payload := []byte("data-before-fin")
	dataSeg := fakeSegment(vmIP, gwIP, 12345, 8080, conn.RCV_NXT, conn.ISS+1, FlagACK, payload)
	finSeq := conn.RCV_NXT + uint32(len(payload))
	finSeg := fakeSegment(vmIP, gwIP, 12345, 8080, finSeq, conn.ISS+1, FlagACK|FlagFIN, nil)
	ts.InjectSegment(dataSeg)
	ts.InjectSegment(finSeg)

	ts.Deliberate(time.Now())

	// Connection should be in CloseWait
	if _, ok := ts.CloseWait[conn.Tuple]; !ok {
		t.Fatalf("expected conn in CloseWait, got Established=%d CloseWait=%d",
			len(ts.Established), len(ts.CloseWait))
	}

	// Data must be readable from RecvBuf
	if conn.RecvAvail() != len(payload) {
		t.Fatalf("data lost during Established→CloseWait: RecvAvail=%d, expected %d",
			conn.RecvAvail(), len(payload))
	}
	buf := make([]byte, 1024)
	n := conn.ReadRecvBuf(buf)
	if n != len(payload) || string(buf[:n]) != string(payload) {
		t.Fatalf("RecvBuf content wrong: got %q, expected %q", buf[:n], payload)
	}
}

func TestFinWait1FINAckAfterData(t *testing.T) {
	// FIN ack detection must work correctly when data was sent before FIN.
	// Regression: used `AckNum > ISS+1` heuristic which is wrong when
	// SND_NXT has advanced past ISS+1 due to data bytes.
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	doHandshake(t, ts, vmIP, gwIP, 12346, 8080)

	var conn *Conn
	for _, c := range ts.Established {
		conn = c
		break
	}

	// Write data then close — data is sent before FIN in the same round.
	ts.AppWrite(conn.Tuple, []byte("hello"))
	ts.AppClose(conn.Tuple)
	ts.Deliberate(time.Now())

	if _, ok := ts.FinWait1[conn.Tuple]; !ok {
		t.Fatalf("expected conn in FinWait1 after AppClose, got FinWait1=%d",
			len(ts.FinWait1))
	}

	sndNxtAfterFIN := conn.SND_NXT // ISS+1+5+1 = ISS+7

	// ACK covers data (5 bytes) but NOT the FIN.
	// AckNum = ISS+6. FIN is at seq ISS+6 (ISS+1+5).
	// AckNum=ISS+6 means "next expected is ISS+6" — the FIN is NOT acked.
	dataOnlyAck := fakeSegment(vmIP, gwIP, 12346, 8080, 1001, sndNxtAfterFIN-1, FlagACK, nil)
	ts.InjectSegment(dataOnlyAck)
	ts.Deliberate(time.Now())

	if _, ok := ts.FinWait1[conn.Tuple]; !ok {
		t.Fatal("FIN_WAIT1→FIN_WAIT2 transition triggered by data-only ACK; FIN was not acked")
	}

	// ACK that covers the FIN.
	finAck := fakeSegment(vmIP, gwIP, 12346, 8080, 1001, sndNxtAfterFIN, FlagACK, nil)
	ts.InjectSegment(finAck)
	ts.Deliberate(time.Now())

	if _, ok := ts.FinWait2[conn.Tuple]; !ok {
		t.Fatal("FIN_WAIT1→FIN_WAIT2 expected after FIN ack")
	}
}

func TestTimerWheelLastTickInit(t *testing.T) {
	// TimerWheel.lastTick starts at 0. Verify the first Expired() call
	// does not incorrectly expire timers scheduled after initialization.
	// Regression: lastTick defaulted to 0, causing the first Expired()
	// to scan all slots from 0 to currentTick, expiring everything.
	tw := NewTimerWheel(10*time.Millisecond, 100)

	// Advance to "now" and THEN schedule a timer at tick+10.
	now := time.Now()
	tick := tw.Advance(now)

	// Schedule a timer far in the future.
	futureTuple := Tuple{SrcPort: 1, DstPort: 2}
	tw.Schedule(futureTuple, tick+100)

	// Expired should return nothing — our timer is far in the future.
	expired := tw.Expired(tick)
	if len(expired) != 0 {
		t.Fatalf("Expired returned %d tuples, expected 0 (lastTick was not initialized)", len(expired))
	}

	// Advance much further — now the timer should fire.
	farTick := tick + 200
	expired = tw.Expired(farTick)
	found := false
	for _, e := range expired {
		if e == futureTuple {
			found = true
		}
	}
	if !found {
		t.Fatal("timer scheduled at tick+100 did not fire at tick+200")
	}
}

func TestRecvDataIncludesSynRcvd(t *testing.T) {
	// RecvData must find connections in SynRcvd, since RFC 793 allows
	// data in SYN-ACK segments. Regression: SynRcvd was missing from
	// the state collections searched by RecvData.
	cfg := DefaultConfig()
	cfg.ListenPort = 8080
	cfg.GatewayIP = net.ParseIP("192.168.65.1")
	ts := NewTCPState(cfg)
	ts.Listen(func(c *Conn) {})

	vmIP := net.ParseIP("192.168.65.2")
	gwIP := net.ParseIP("192.168.65.1")

	// Initiate handshake: VM sends SYN, we reply SYN-ACK.
	// Connection is now in SynRcvd.
	synSeg := fakeSegment(vmIP, gwIP, 12345, 8080, 1000, 0, FlagSYN, nil)
	ts.InjectSegment(synSeg)
	ts.Deliberate(time.Now())

	if len(ts.SynRcvd) != 1 {
		t.Fatalf("expected 1 SynRcvd, got %d", len(ts.SynRcvd))
	}

	// Manually inject data into the SynRcvd connection's RecvBuf, simulating
	// data that arrived with the SYN (unusual but RFC-permitted).
	var conn *Conn
	for _, c := range ts.SynRcvd {
		conn = c
		break
	}
	conn.WriteRecvBuf([]byte("early-data"))

	// RecvData should be able to read this data.
	tuple := conn.Tuple
	buf := make([]byte, 1024)
	n := ts.RecvData(tuple, buf)
	if n != 10 {
		t.Fatalf("RecvData returned %d bytes from SynRcvd conn, expected 10", n)
	}
	if string(buf[:n]) != "early-data" {
		t.Fatalf("RecvData returned %q, expected %q", buf[:n], "early-data")
	}
}

// ============================================================================
// Helpers
// ============================================================================

func fakeSegment(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) *TCPSegment {
	h := &TCPHeader{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ack,
		Flags:      flags,
		WindowSize: 65535,
		DataOffset: 20,
	}
	return &TCPSegment{
		Header:  h,
		Payload: payload,
		Tuple:   NewTuple(srcIP, dstIP, srcPort, dstPort),
	}
}

func doHandshake(t *testing.T, ts *TCPState, vmIP, gwIP net.IP, srcPort, dstPort uint16) {
	t.Helper()
	synSeg := fakeSegment(vmIP, gwIP, srcPort, dstPort, 1000, 0, FlagSYN, nil)
	ts.InjectSegment(synSeg)
	ts.Deliberate(time.Now())

	outputs := ts.ConsumeOutputs()
	if len(outputs) == 0 {
		t.Fatal("no SYN-ACK in handshake")
	}
	synAck := outputs[0]

	ackSeg := fakeSegment(vmIP, gwIP, srcPort, dstPort, 1001, synAck.Header.SeqNum+1, FlagACK, nil)
	ts.InjectSegment(ackSeg)
	ts.Deliberate(time.Now())
}
