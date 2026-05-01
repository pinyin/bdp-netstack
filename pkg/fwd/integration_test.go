package fwd

import (
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/tcp"
)

// ============================================================================
// Integration tests for forwarder → TCP deliberation pipeline.
// Uses real socket pairs (no mocks, no vfkit) to exercise the full data path.
// ============================================================================

// setupPipe creates a connected socket pair and a forwarder entry in Established state.
func setupPipe(t *testing.T, bufSize int) (*Forwarder, *Entry, *tcp.TCPState, *tcp.Conn, net.Conn, func()) {
	t.Helper()

	hostLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var hostConn net.Conn
	dialDone := make(chan struct{})
	go func() {
		hostConn, _ = net.Dial("tcp", hostLn.Addr().String())
		close(dialDone)
	}()

	readConn, err := hostLn.Accept()
	if err != nil {
		hostLn.Close()
		t.Fatalf("accept: %v", err)
	}
	<-dialDone

	var hostFD int
	if tcpConn, ok := readConn.(*net.TCPConn); ok {
		rawConn, _ := tcpConn.SyscallConn()
		rawConn.Control(func(fd uintptr) {
			hostFD = int(fd)
			syscall.SetNonblock(hostFD, true)
		})
	}

	cfg := tcp.DefaultConfig()
	if bufSize > 0 {
		cfg.BufferSize = bufSize
	}
	cfg.BPT = 1 * time.Millisecond
	cfg.MTU = 1500
	tcpState := tcp.NewTCPState(cfg)

	gwIP := net.ParseIP("192.168.65.1")
	vmIP := net.ParseIP("192.168.65.2")
	vmTuple := tcp.NewTuple(gwIP, vmIP, 33333, 22)
	vmConn := tcpState.ActiveOpen(vmTuple, 65535)

	delete(tcpState.SynSent, vmTuple)
	vmConn.IRS = 1000
	vmConn.RCV_NXT = 1001
	vmConn.SND_UNA = vmConn.ISS + 1
	vmConn.SND_NXT = vmConn.ISS + 1
	vmConn.SND_WND = 65535
	vmConn.LastActivityTick = time.Now().UnixNano() / int64(time.Millisecond)
	tcpState.Established[vmTuple] = vmConn

	f := &Forwarder{
		gatewayIP: gwIP,
		mappings:  make(map[uint16]Mapping),
		listeners: make(map[uint16]net.Listener),
		entries:   make(map[int]*Entry),
		tcpState:  tcpState,
	}

	entry := &Entry{
		HostConn: readConn,
		hostFD:   hostFD,
		VMConn:   vmConn,
		VMAddr:   "192.168.65.2:22",
		hostBuf:  make([]byte, 65536),
	}
	f.entries[hostFD] = entry

	cleanup := func() {
		hostConn.Close()
		readConn.Close()
		hostLn.Close()
	}
	return f, entry, tcpState, vmConn, hostConn, cleanup
}

// runDeliberationLoop runs the BDP loop, returns (bytesOutput, ticksElapsed).
// Stops when totalOutput >= wantBytes or deadline reached.
func runDeliberationLoop(t *testing.T, f *Forwarder, tcpState *tcp.TCPState, vmConn *tcp.Conn, wantBytes int, deadline time.Time) (int, int) {
	t.Helper()

	totalOutput := 0
	ticks := 0
	start := time.Now()

	for time.Now().Before(deadline) {
		ticks++

		f.Poll()
		tcpState.Deliberate(time.Now())
		f.ProxyVMToHost()

		for _, seg := range tcpState.ConsumeOutputs() {
			if len(seg.Payload) > 0 {
				totalOutput += len(seg.Payload)
			}
		}

		if vmConn.SND_NXT > vmConn.SND_UNA {
			vmConn.AckSendBuf(vmConn.SND_NXT)
		}

		if totalOutput >= wantBytes {
			elapsed := time.Since(start)
			t.Logf("done: %d bytes in %d ticks (%.2fs, %.2f MB/s)",
				totalOutput, ticks, elapsed.Seconds(),
				float64(totalOutput)/elapsed.Seconds()/1024/1024)
			return totalOutput, ticks
		}

		time.Sleep(1 * time.Millisecond)
	}

	t.Logf("deadline reached: %d / %d bytes in %d ticks", totalOutput, wantBytes, ticks)
	return totalOutput, ticks
}

// ============================================================================
// Test cases
// ============================================================================

func TestIntegration_1MBTransfer(t *testing.T) {
	f, _, tcpState, vmConn, hostConn, cleanup := setupPipe(t, 64*1024)
	defer cleanup()

	dataSize := 1024 * 1024
	buf := make([]byte, dataSize)
	for i := range buf {
		buf[i] = byte(i % 251)
	}

	// Writer goroutine: write 1MB then close
	go func() {
		written := 0
		for written < dataSize {
			n, err := hostConn.Write(buf[written:])
			if err != nil {
				return
			}
			written += n
		}
	}()

	output, _ := runDeliberationLoop(t, f, tcpState, vmConn, dataSize,
		time.Now().Add(5*time.Second))

	// Close to unblock writer
	hostConn.Close()

	if output < dataSize {
		t.Errorf("only %d / %d bytes transferred (%.1f%%)", output, dataSize,
			float64(output)/float64(dataSize)*100)
	}
}

func TestIntegration_BufferExactlyFull(t *testing.T) {
	// Small buffer (4096 bytes) makes full-wraparound happen frequently.
	f, _, tcpState, vmConn, hostConn, cleanup := setupPipe(t, 4096)
	defer cleanup()

	dataSize := 20480 // 20KB cycles through 4KB buffer ~5 times
	buf := make([]byte, dataSize)
	for i := range buf {
		buf[i] = byte(i % 251)
	}

	go func() {
		written := 0
		for written < dataSize {
			n, _ := hostConn.Write(buf[written:])
			written += n
		}
	}()

	output, _ := runDeliberationLoop(t, f, tcpState, vmConn, dataSize,
		time.Now().Add(5*time.Second))
	hostConn.Close()

	if output < dataSize {
		t.Errorf("buffer-full: only %d / %d bytes", output, dataSize)
	}
}

func TestIntegration_MultipleConnections(t *testing.T) {
	f, _, ts, c1, hostConn1, cleanup1 := setupPipe(t, 64*1024)
	defer cleanup1()

	// Second connection
	hostLn2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer hostLn2.Close()
	go func() {
		conn, _ := net.Dial("tcp", hostLn2.Addr().String())
		// Use conn for writing from goroutine
		buf := make([]byte, 512*1024)
		for i := range buf {
			buf[i] = 0xBB
		}
		w := 0
		for w < len(buf) {
			n, _ := conn.Write(buf[w:])
			w += n
		}
		conn.Close()
	}()
	readConn2, _ := hostLn2.Accept()
	defer readConn2.Close()

	var hostFD2 int
	if tc, ok := readConn2.(*net.TCPConn); ok {
		rc, _ := tc.SyscallConn()
		rc.Control(func(fd uintptr) {
			hostFD2 = int(fd)
			syscall.SetNonblock(hostFD2, true)
		})
	}

	gwIP := net.ParseIP("192.168.65.1")
	vmIP := net.ParseIP("192.168.65.2")
	vmTuple2 := tcp.NewTuple(gwIP, vmIP, 33334, 22)
	c2 := ts.ActiveOpen(vmTuple2, 65535)
	delete(ts.SynSent, vmTuple2)
	c2.IRS = 2000
	c2.RCV_NXT = 2001
	c2.SND_UNA = c2.ISS + 1
	c2.SND_NXT = c2.ISS + 1
	c2.SND_WND = 65535
	c2.LastActivityTick = time.Now().UnixNano() / int64(time.Millisecond)
	ts.Established[vmTuple2] = c2

	e2 := &Entry{
		HostConn: readConn2,
		hostFD:   hostFD2,
		VMConn:   c2,
		VMAddr:   "192.168.65.2:22",
		hostBuf:  make([]byte, 65536),
	}
	f.entries[hostFD2] = e2

	dataSize := 256 * 1024 // 256KB each
	buf1 := make([]byte, dataSize)
	for i := range buf1 {
		buf1[i] = 0xAA
	}

	go func() {
		w := 0
		for w < dataSize {
			n, _ := hostConn1.Write(buf1[w:])
			w += n
		}
	}()

	var output1, output2 int64
	deadline := time.Now().Add(5 * time.Second)

	for time.Now().Before(deadline) {
		f.Poll()
		ts.Deliberate(time.Now())
		f.ProxyVMToHost()

		for _, seg := range ts.ConsumeOutputs() {
			if len(seg.Payload) > 0 {
				if seg.Tuple.SrcPort == 33333 {
					atomic.AddInt64(&output1, int64(len(seg.Payload)))
				} else {
					atomic.AddInt64(&output2, int64(len(seg.Payload)))
				}
			}
		}

		if c1.SND_NXT > c1.SND_UNA {
			c1.AckSendBuf(c1.SND_NXT)
		}
		if c2.SND_NXT > c2.SND_UNA {
			c2.AckSendBuf(c2.SND_NXT)
		}

		o1 := int(atomic.LoadInt64(&output1))
		o2 := int(atomic.LoadInt64(&output2))
		if o1 >= dataSize && o2 >= dataSize {
			break
		}

		time.Sleep(1 * time.Millisecond)
	}

	hostConn1.Close()

	o1 := int(atomic.LoadInt64(&output1))
	o2 := int(atomic.LoadInt64(&output2))
	if o1 < dataSize {
		t.Errorf("conn1: %d / %d bytes", o1, dataSize)
	}
	if o2 < dataSize {
		t.Errorf("conn2: %d / %d bytes", o2, dataSize)
	}
}

func TestIntegration_SmallTransfer(t *testing.T) {
	f, _, tcpState, vmConn, hostConn, cleanup := setupPipe(t, 64*1024)
	defer cleanup()

	payload := []byte("Hello, BDP integration test!")
	go func() {
		hostConn.Write(payload)
	}()

	output, _ := runDeliberationLoop(t, f, tcpState, vmConn, len(payload),
		time.Now().Add(2*time.Second))
	hostConn.Close()

	if output < len(payload) {
		t.Errorf("small transfer: only %d / %d bytes", output, len(payload))
	}
}

func TestIntegration_DataIntegrity(t *testing.T) {
	f, _, tcpState, vmConn, hostConn, cleanup := setupPipe(t, 64*1024)
	defer cleanup()

	// Send pattern that makes corruption obvious
	dataSize := 10000
	pattern := make([]byte, dataSize)
	for i := range pattern {
		pattern[i] = byte(i % 256)
	}

	// Collect output segments to verify content
	var mu sync.Mutex
	var received []byte

	go func() {
		w := 0
		for w < dataSize {
			n, _ := hostConn.Write(pattern[w:])
			w += n
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	totalOutput := 0

	for time.Now().Before(deadline) && totalOutput < dataSize {
		f.Poll()
		tcpState.Deliberate(time.Now())
		f.ProxyVMToHost()

		for _, seg := range tcpState.ConsumeOutputs() {
			if len(seg.Payload) > 0 {
				totalOutput += len(seg.Payload)
				mu.Lock()
				received = append(received, seg.Payload...)
				mu.Unlock()
			}
		}

		if vmConn.SND_NXT > vmConn.SND_UNA {
			vmConn.AckSendBuf(vmConn.SND_NXT)
		}

		time.Sleep(1 * time.Millisecond)
	}

	hostConn.Close()

	if totalOutput < dataSize {
		t.Fatalf("only %d / %d bytes", totalOutput, dataSize)
	}

	// Verify every byte matches the pattern
	for i, b := range received {
		expected := byte(i % 256)
		if b != expected {
			t.Fatalf("data corruption at byte %d: got %02x, expected %02x", i, b, expected)
		}
	}
	t.Logf("data integrity OK: %d bytes verified", len(received))
}

func TestIntegration_HostCloseBeforeBufferDrained(t *testing.T) {
	// Small buffer (4096 bytes) to ensure send buffer is still draining when
	// host EOF arrives. This exercises the deferred close mechanism.
	f, entry, tcpState, vmConn, hostConn, cleanup := setupPipe(t, 4096)
	defer cleanup()

	dataSize := 32768 // 32KB through 4KB buffer cycles ~8 times
	pattern := make([]byte, dataSize)
	for i := range pattern {
		pattern[i] = byte(i % 256)
	}

	// Writer goroutine: write all data then close immediately
	writeDone := make(chan struct{})
	go func() {
		w := 0
		for w < dataSize {
			n, err := hostConn.Write(pattern[w:])
			if err != nil {
				return
			}
			w += n
		}
		hostConn.Close()
		close(writeDone)
	}()

	// Collect received data
	var received []byte
	totalOutput := 0
	deadline := time.Now().Add(5 * time.Second)
	deferredCloseSeen := false

	for time.Now().Before(deadline) && totalOutput < dataSize {
		f.Poll()
		tcpState.Deliberate(time.Now())
		f.ProxyVMToHost()

		// Check if deferred close is active
		if entry.HostClosed && entry.deferredClose {
			deferredCloseSeen = true
		}

		for _, seg := range tcpState.ConsumeOutputs() {
			if len(seg.Payload) > 0 {
				totalOutput += len(seg.Payload)
				received = append(received, seg.Payload...)
			}
		}

		if vmConn.SND_NXT > vmConn.SND_UNA {
			vmConn.AckSendBuf(vmConn.SND_NXT)
		}

		// Stop early if host has fully closed and all data delivered
		if entry.VMClosed || (entry.HostClosed && !entry.deferredClose && totalOutput >= dataSize) {
			break
		}

		time.Sleep(1 * time.Millisecond)
	}

	<-writeDone

	if totalOutput < dataSize {
		t.Errorf("only %d / %d bytes transferred (%.1f%%)", totalOutput, dataSize,
			float64(totalOutput)/float64(dataSize)*100)
	}

	if !deferredCloseSeen {
		t.Log("deferred close was not triggered (buffer may have drained before EOF)")
	} else {
		t.Log("deferred close triggered successfully")
	}

	// Verify data integrity
	for i, b := range received {
		expected := byte(i % 256)
		if b != expected {
			t.Fatalf("data corruption at byte %d: got %02x, expected %02x", i, b, expected)
		}
	}
	t.Logf("close-before-drain: %d bytes verified, deferredClose=%v", len(received), deferredCloseSeen)
}
