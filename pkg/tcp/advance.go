package tcp

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/debug"
)

// ============================================================================
// Phase 1: Timer processing — may move connections BACKWARD
// (to "earlier" collections, which were already processed → deferred to next round)
// ============================================================================

func (ts *TCPState) processTimers() {
	expired := ts.timerWheel.Expired(ts.tick)

	for _, tuple := range expired {
		// Check each state collection for this tuple
		if conn, ok := ts.SynSent[tuple]; ok {
			// Retransmit SYN: reset SND_NXT so advanceSynSent re-sends
			conn.SND_NXT = conn.ISS
			conn.RetransmitAt = 0
		}
		if conn, ok := ts.SynRcvd[tuple]; ok {
			// Retransmit SYN-ACK: reset SND_NXT so advanceSynRcvd re-sends
			conn.SND_NXT = conn.ISS
			conn.RetransmitAt = 0
		}
		if conn, ok := ts.LastAck[tuple]; ok {
			// Retransmit FIN: allow advanceLastAck to re-send
			conn.FinSent = false
			conn.RetransmitAt = 0
		}
		if conn, ok := ts.Established[tuple]; ok {
			// Retransmit: reset SND_NXT so PeekSendData re-reads unacked data
			conn.SND_NXT = conn.SND_UNA
			conn.RetransmitCount++
			conn.RetransmitAt = 0
		}
		if _, ok := ts.TimeWait[tuple]; ok {
			// TIME_WAIT expired — the connection is ready to be reclaimed
			delete(ts.TimeWait, tuple)
		}
	}
}

// ============================================================================
// Phase 2: Dispatch pending segments to their target connections.
// Creates new connections in SynRcvd for SYN packets to the listener.
// ============================================================================

func (ts *TCPState) dispatchSegments() {
	for _, seg := range ts.pending {
		// Reverse the tuple to match our local view
		tuple := seg.Tuple.Reverse()

		// Find the connection in any state collection
		if conn := ts.findConn(tuple); conn != nil {
			conn.PendingSegs = append(conn.PendingSegs, seg)
			conn.LastActivityTick = ts.tick
			continue
		}

		// Not an existing connection — check for SYN to listener
		if seg.Header.IsSYN() && !seg.Header.IsACK() && seg.Tuple.DstPort == ts.listenPort && ts.listener != nil {
			ts.createSynRcvd(seg)
			continue
		}

		// No listener or not SYN — send RST
		if !seg.Header.IsRST() {
			// For simplicity, drop (a full impl would send RST)
		}
	}
	ts.pending = nil
}

// findConn looks up a connection in all state collections.
func (ts *TCPState) findConn(tuple Tuple) *Conn {
	for _, coll := range []map[Tuple]*Conn{
		ts.SynSent, ts.SynRcvd, ts.Established, ts.CloseWait, ts.LastAck,
		ts.FinWait1, ts.FinWait2, ts.TimeWait,
	} {
		if conn, ok := coll[tuple]; ok {
			return conn
		}
	}
	return nil
}

// createSynRcvd creates a new connection in SYN_RCVD state.
func (ts *TCPState) createSynRcvd(seg *TCPSegment) {
	iss := ts.generateISN()
	tuple := seg.Tuple.Reverse()

	conn := NewConn(tuple, seg.Header.SeqNum, iss, seg.Header.WindowSize, ts.cfg.BufferSize)
	conn.LastActivityTick = ts.tick

	// Parse window scale from SYN options (RFC 1323)
	if ws := ParseWindowScale(seg.Raw); ws > 0 {
		conn.SndShift = ws
	}
	conn.RcvShift = ts.cfg.WindowScale

	// Schedule retransmit for SYN-ACK
		conn.RetransmitAt = ts.tick + ts.msToTicks(200)
	// Simplification: schedule retransmit after ~200ms (20 slots at 10ms)

	ts.SynRcvd[tuple] = conn
}

// ============================================================================
// Phase 3: Process application layer requests (writes, closes)
// ============================================================================

func (ts *TCPState) processAppRequests() {
	for tuple, data := range ts.appWrites {
		if conn := ts.findConnInState(tuple, ts.Established, ts.CloseWait, ts.FinWait1); conn != nil {
			conn.WriteSendBuf(data)
			conn.LastActivityTick = ts.tick
		}
	}
	for tuple := range ts.appCloses {
		if conn := ts.findConnInState(tuple, ts.Established); conn != nil {
			// Active close (we initiate): Established → FinWait1
			delete(ts.Established, tuple)
			ts.FinWait1[tuple] = conn
		} else if conn := ts.findConnInState(tuple, ts.CloseWait); conn != nil {
			// Passive close (peer FIN first, then app closes): CloseWait → LastAck
			delete(ts.CloseWait, tuple)
			ts.LastAck[tuple] = conn
		} else if conn := ts.findConnInState(tuple, ts.SynSent); conn != nil {
			// Host closed before handshake completed (e.g., ARP miss caused
			// SYN to be dropped and host gave up). Remove immediately since
			// no TCP connection was established to the peer.
			delete(ts.SynSent, tuple)
		} else if conn := ts.findConnInState(tuple, ts.SynRcvd); conn != nil {
			// External host closed before handshake completed. Clean up.
			delete(ts.SynRcvd, tuple)
		}
	}
	ts.appWrites = make(map[Tuple][]byte)
	ts.appCloses = make(map[Tuple]bool)
}

func (ts *TCPState) findConnInState(tuple Tuple, states ...map[Tuple]*Conn) *Conn {
	for _, s := range states {
		if conn, ok := s[tuple]; ok {
			return conn
		}
	}
	return nil
}

// ============================================================================
// Phase 4a: advanceSynSent
// SYN_SENT → ESTABLISHED (forward cascade when SYN-ACK received)
// ============================================================================

func (ts *TCPState) advanceSynSent() {
	for tuple, conn := range ts.SynSent {
		acked := false
		for _, seg := range conn.PendingSegs {
			if seg.Header.IsSYN() && seg.Header.IsACK() {
				// Validate SYN-ACK acknowledges our SYN (AckNum == ISS+1 per RFC 793)
				if seg.Header.AckNum != conn.ISS+1 {
					continue
				}
				// SYN-ACK received
				conn.IRS = seg.Header.SeqNum
				conn.RCV_NXT = seg.Header.SeqNum + 1
				conn.SND_UNA = seg.Header.AckNum
				conn.SND_NXT = conn.ISS + 1
				conn.SND_WND = uint32(seg.Header.WindowSize)
				acked = true
			}
		}

		if acked {
			// SYN_SENT → ESTABLISHED (forward cascade)
			delete(ts.SynSent, tuple)
			// Preserve data segments that arrived with/after SYN-ACK
			// for advanceEstablished to process. Only remove the SYN-ACK itself.
			remaining := conn.PendingSegs[:0]
			for _, seg := range conn.PendingSegs {
				if seg.Header.IsSYN() && seg.Header.IsACK() {
					continue // discard the SYN-ACK
				}
				remaining = append(remaining, seg)
			}
			conn.PendingSegs = remaining
			ts.Established[tuple] = conn
			// Send ACK for the SYN-ACK
			ts.sendACK(conn)
			continue
		}

		// Send or resend SYN
		if conn.SND_NXT == conn.ISS {
			ts.sendSYN(conn)
		}
		conn.PendingSegs = nil
	}
}

func (ts *TCPState) sendSYN(conn *Conn) {
	win := conn.scaledWindow(true)
	rawSeg := BuildSegmentWithWScale(conn.Tuple, conn.ISS, 0, FlagSYN, win, conn.RcvShift, nil)
	seg := &TCPSegment{
		Header: &TCPHeader{
			SrcPort: conn.Tuple.SrcPort, DstPort: conn.Tuple.DstPort,
			SeqNum: conn.ISS, AckNum: 0,
			Flags: FlagSYN, WindowSize: win,
		},
		Tuple: conn.Tuple,
		Raw:   rawSeg,
	}

	if ts.writeFunc != nil {
		if err := ts.writeFunc(seg); err != nil {
			return // write failed; retry next tick with same ISS
		}
	} else {
		ts.outputs = append(ts.outputs, seg)
	}

	conn.SND_NXT = conn.ISS + 1 // SYN consumes one sequence number
	conn.RetransmitAt = ts.tick + ts.msToTicks(200)
	ts.timerWheel.Schedule(conn.Tuple, conn.RetransmitAt)
}

// ============================================================================
// Phase 4b: advanceSynRcvd
// SYN_RCVD → ESTABLISHED (forward cascade when ACK received)
// ============================================================================

func (ts *TCPState) advanceSynRcvd() {
	for tuple, conn := range ts.SynRcvd {
		// Check for ACK confirming our SYN-ACK
		acked := false
		for _, seg := range conn.PendingSegs {
			if seg.Header.IsACK() && seg.Header.AckNum == conn.ISS+1 {
				conn.SND_UNA = seg.Header.AckNum
				conn.SND_NXT = conn.ISS + 1
				acked = true
			}
		}

		if acked {
			// SYN_RCVD → ESTABLISHED (forward cascade!)
			// Established is "later" in traversal → will be processed in this same round
			delete(ts.SynRcvd, tuple)
			// Preserve data segments (ACK may carry payload per RFC 793)
			remaining := conn.PendingSegs[:0]
			for _, seg := range conn.PendingSegs {
				if seg.Header.IsACK() && seg.Header.AckNum == conn.ISS+1 && len(seg.Payload) == 0 {
					continue // discard the pure ACK that completed handshake
				}
				remaining = append(remaining, seg)
			}
			conn.PendingSegs = remaining
			ts.Established[tuple] = conn

			if ts.listener != nil && ts.listener.OnAccept != nil {
				ts.listener.OnAccept(conn)
			}
			continue
		}

		// Send or resend SYN-ACK
		if conn.SND_NXT == conn.ISS {
			// SYN not yet sent (or needs retransmit)
			ts.sendSYNACK(conn)
		}
		conn.PendingSegs = nil
	}
}

func (ts *TCPState) sendSYNACK(conn *Conn) {
	win := conn.scaledWindow(true)
	rawSeg := BuildSegmentWithWScale(conn.Tuple, conn.ISS, conn.RCV_NXT,
		FlagSYN|FlagACK, win, conn.RcvShift, nil)
	seg := &TCPSegment{
		Header: &TCPHeader{
			SrcPort: conn.Tuple.SrcPort, DstPort: conn.Tuple.DstPort,
			SeqNum: conn.ISS, AckNum: conn.RCV_NXT,
			Flags: FlagSYN | FlagACK, WindowSize: win,
		},
		Tuple: conn.Tuple,
		Raw:   rawSeg,
	}

	if ts.writeFunc != nil {
		if err := ts.writeFunc(seg); err != nil {
			return // write failed; retry next tick with same ISS
		}
	} else {
		ts.outputs = append(ts.outputs, seg)
	}

	conn.SND_NXT = conn.ISS + 1 // the SYN in SYN-ACK consumes one sequence number
	conn.RetransmitAt = ts.tick + ts.msToTicks(200)
	ts.timerWheel.Schedule(conn.Tuple, conn.RetransmitAt)
}

// ============================================================================
// Phase 4b: advanceEstablished
// ESTABLISHED → FIN_WAIT1 (forward: received FIN or app close)
// ESTABLISHED → SYN_RCVD   (backward: retransmit timeout — deferred to next round)
// ============================================================================

func (ts *TCPState) advanceEstablished() {
	for tuple, conn := range ts.Established {
		forward := false
		var targetCollection map[Tuple]*Conn

		for _, seg := range conn.PendingSegs {
			// Process ACK
			if seg.Header.IsACK() {
				if seqGT(seg.Header.AckNum, conn.SND_UNA) {
					conn.AckSendBuf(seg.Header.AckNum)
					if seqGT(conn.SND_UNA, conn.SND_NXT) {
						conn.SND_NXT = conn.SND_UNA
					}
				}
				// Update window even for pure window updates (AckNum == SND_UNA)
				if seqGE(seg.Header.AckNum, conn.SND_UNA) {
					conn.SND_WND = uint32(seg.Header.WindowSize) << conn.SndShift
				}
			}

			// Process data
			if len(seg.Payload) > 0 && seg.Header.SeqNum == conn.RCV_NXT {
				n := conn.WriteRecvBuf(seg.Payload)
				if n > 0 {
					conn.RCV_NXT += uint32(n)
				}
			}

			// Process FIN: peer initiated close → CLOSE_WAIT (passive close)
			if seg.Header.IsFIN() {
				conn.FinReceived = true
				conn.FinSeq = seg.Header.SeqNum + uint32(len(seg.Payload))
				if conn.FinSeq == conn.RCV_NXT {
					conn.RCV_NXT = conn.FinSeq + 1
				}
				// ESTABLISHED → CLOSE_WAIT (forward cascade!)
				forward = true
				targetCollection = ts.CloseWait
			}
		}

		// Check for externally-set FinReceived (e.g., NAT host close signals
		// peer FIN without a segment on the wire). The external caller sets
		// FinReceived=true and FinSeq=RCV_NXT so RCV_NXT advances by 1.
		if conn.FinReceived && !forward {
			if conn.FinSeq == conn.RCV_NXT {
				conn.RCV_NXT = conn.FinSeq + 1
			}
			forward = true
			targetCollection = ts.CloseWait
		}

		if forward {
			delete(ts.Established, tuple)
			conn.PendingSegs = nil
			targetCollection[tuple] = conn
			continue
		}

		// Send any pending data and ACKs
		ts.sendDataAndAcks(conn)
		conn.PendingSegs = nil
	}
}

// ============================================================================
// Phase 4c: advanceCloseWait
// CLOSE_WAIT → LAST_ACK (forward: app close / forwarder AppClose)
// CLOSE_WAIT → CLOSE_WAIT (stay: waiting for app close)
// ============================================================================

func (ts *TCPState) advanceCloseWait() {
	for tuple, conn := range ts.CloseWait {
		// Process remaining data/ACKs from peer
		for _, seg := range conn.PendingSegs {
			if seg.Header.IsACK() {
				if seqGT(seg.Header.AckNum, conn.SND_UNA) {
					conn.AckSendBuf(seg.Header.AckNum)
						if seqGT(conn.SND_UNA, conn.SND_NXT) {
							conn.SND_NXT = conn.SND_UNA
						}
				}
				if seqGE(seg.Header.AckNum, conn.SND_UNA) {
					conn.SND_WND = uint32(seg.Header.WindowSize) << conn.SndShift
				}
			}
			if len(seg.Payload) > 0 && seg.Header.SeqNum == conn.RCV_NXT {
				n := conn.WriteRecvBuf(seg.Payload)
				if n > 0 {
					conn.RCV_NXT += uint32(n)
				}
			}
		}

		// Check if app has issued close (via processAppRequests which would
		// have moved it to LastAck already). If still in CloseWait, just
		// send pending ACKs.
		if _, stillInCloseWait := ts.CloseWait[tuple]; !stillInCloseWait {
			continue
		}

		ts.sendDataAndAcks(conn)
		conn.PendingSegs = nil
	}
}

// ============================================================================
// Phase 4d: advanceLastAck
// LAST_ACK → (reclaimed) when ACK of our FIN received
// ============================================================================

func (ts *TCPState) advanceLastAck() {
	for tuple, conn := range ts.LastAck {
		acked := false

		for _, seg := range conn.PendingSegs {
			if seg.Header.IsACK() && seqGT(seg.Header.AckNum, conn.SND_UNA) {
				conn.AckSendBuf(seg.Header.AckNum)
					if seqGT(conn.SND_UNA, conn.SND_NXT) {
						conn.SND_NXT = conn.SND_UNA
					}
				// Check if ACK covers our FIN
				if seqGE(seg.Header.AckNum, conn.SND_NXT) {
					acked = true
				}
			}
		}

		if acked {
			// LAST_ACK → cleanup (no TIME_WAIT for passive closer per RFC 793)
			delete(ts.LastAck, tuple)
			conn.PendingSegs = nil
			continue
		}

		// Send FIN (only first time; timer-based retransmit)
		if !conn.FinSent {
			ts.sendFIN(conn)
			conn.RetransmitAt = ts.tick + ts.msToTicks(200)
			ts.timerWheel.Schedule(conn.Tuple, conn.RetransmitAt)
		}
		conn.PendingSegs = nil
	}
}

// ============================================================================
// Phase 4e: advanceFinWait1
// FIN_WAIT1 → FIN_WAIT2 (forward: ACK of our FIN received)
// FIN_WAIT1 → TIME_WAIT (forward: FIN received + already ACKed by peer)
// ============================================================================

func (ts *TCPState) advanceFinWait1() {
	for tuple, conn := range ts.FinWait1 {
		hasAckOfFin := false
		hasPeerFin := false
		peerFinSeq := uint32(0)

		for _, seg := range conn.PendingSegs {
			if seg.Header.IsACK() {
				conn.AckSendBuf(seg.Header.AckNum)
					if seqGT(conn.SND_UNA, conn.SND_NXT) {
						conn.SND_NXT = conn.SND_UNA
					}
				// Our FIN was acked if the ACK covers our FIN seq = ISS+1+dataSent
				if conn.FinSent && seqGE(seg.Header.AckNum, conn.SND_NXT) {
					hasAckOfFin = true
				}
			}
			if seg.Header.IsFIN() {
				hasPeerFin = true
				peerFinSeq = seg.Header.SeqNum + uint32(len(seg.Payload))
				conn.FinReceived = true
				conn.FinSeq = peerFinSeq
				if conn.FinSeq == conn.RCV_NXT {
					conn.RCV_NXT = conn.FinSeq + 1
				}
			}
			// Process data from peer even in FIN_WAIT1
			if len(seg.Payload) > 0 && seg.Header.SeqNum == conn.RCV_NXT {
				n := conn.WriteRecvBuf(seg.Payload)
				if n > 0 {
					conn.RCV_NXT += uint32(n)
				}
			}
		}

		if hasPeerFin && hasAckOfFin {
			// Simultaneous close or FIN+ACK: FIN_WAIT1 → TIME_WAIT (forward!)
			delete(ts.FinWait1, tuple)
			conn.PendingSegs = nil
			conn.TimeWaitUntil = ts.tick + ts.msToTicks(60000)
			ts.timerWheel.Schedule(conn.Tuple, conn.TimeWaitUntil)
			ts.TimeWait[tuple] = conn
			ts.sendACK(conn)
			continue
		}

		if hasAckOfFin {
			// FIN_WAIT1 → FIN_WAIT2 (forward!)
			delete(ts.FinWait1, tuple)
			conn.PendingSegs = nil
			ts.FinWait2[tuple] = conn
			if hasPeerFin {
				// Send ACK for peer's FIN
				ts.sendACK(conn)
			}
			continue
		}

		// Drain send buffer before first FIN (safety net for premature AppClose)
		if !conn.FinSent {
			ts.sendDataAndAcks(conn)
		}
		// Send/Resend FIN
		ts.sendFIN(conn)
		conn.PendingSegs = nil
	}
}

// ============================================================================
// Phase 4d: advanceFinWait2
// FIN_WAIT2 → TIME_WAIT (forward: FIN from peer received)
// ============================================================================

func (ts *TCPState) advanceFinWait2() {
	for tuple, conn := range ts.FinWait2 {
		forward := false

		for _, seg := range conn.PendingSegs {
			if seg.Header.IsACK() {
				conn.AckSendBuf(seg.Header.AckNum)
					if seqGT(conn.SND_UNA, conn.SND_NXT) {
						conn.SND_NXT = conn.SND_UNA
					}
			}
			if seg.Header.IsFIN() {
				conn.FinReceived = true
				conn.FinSeq = seg.Header.SeqNum + uint32(len(seg.Payload))
				if conn.FinSeq == conn.RCV_NXT {
					conn.RCV_NXT = conn.FinSeq + 1
				}
				forward = true
			}
		}

		if forward {
			// FIN_WAIT2 → TIME_WAIT (forward!)
			delete(ts.FinWait2, tuple)
			conn.PendingSegs = nil
				conn.TimeWaitUntil = ts.tick + ts.msToTicks(60000)
			ts.timerWheel.Schedule(conn.Tuple, conn.TimeWaitUntil)
			ts.TimeWait[tuple] = conn
			ts.sendACK(conn)
			continue
		}

		conn.PendingSegs = nil
	}
}

// ============================================================================
// Phase 4e: advanceTimeWait
// TIME_WAIT entries are cleaned up by the timer wheel.
// ============================================================================

func (ts *TCPState) advanceTimeWait() {
	// Nothing to do here — TIME_WAIT entries auto-expire via timer wheel.
	// The processTimers() function removes expired entries.
}

// ============================================================================
// Phase 5: Reclaim idle and closed connections
// ============================================================================

func (ts *TCPState) reclaimClosed() {
	ts.reclaimIdle()
}

func (ts *TCPState) reclaimIdle() {
	if ts.cfg.IdleTimeout == 0 {
		return
	}
	idleTicks := int64(ts.cfg.IdleTimeout / ts.timerWheel.SlotDuration())
	if idleTicks <= 0 {
		return
	}

	allCollections := []map[Tuple]*Conn{
		ts.SynSent, ts.SynRcvd, ts.Established, ts.CloseWait,
		ts.FinWait1, ts.FinWait2,
	}
	for _, coll := range allCollections {
		for tuple, conn := range coll {
			if ts.tick-conn.LastActivityTick > idleTicks {
				delete(coll, tuple)
			}
		}
	}
}

// ============================================================================
// Output helpers
// ============================================================================

func (ts *TCPState) sendDataAndAcks(conn *Conn) {
	mss := ts.cfg.MTU - 20
	maxSegs := ts.cfg.MaxSegsPerTick
	if maxSegs <= 0 {
		maxSegs = 12 // safe: 12 × 1400 = 16.8KB per connection per tick
	}
	sentData := false
	segCount := 0

	for {
		if segCount >= maxSegs {
			break // per-tick budget exhausted; continue next tick
		}
		inFlight := conn.SND_NXT - conn.SND_UNA
		window := conn.SND_WND
		canSend := int(window) - int(inFlight)
		if canSend <= 0 {
			break // window full
		}
		if canSend > mss {
			canSend = mss
		}

		data := conn.PeekSendData(canSend)
		if len(data) == 0 {
			break // no more data to send
		}

		flags := uint8(FlagACK | FlagPSH)
		win := conn.scaledWindow(false)
		rawSeg := BuildSegment(conn.Tuple, conn.SND_NXT, conn.RCV_NXT,
			flags, win, data)

		seg := &TCPSegment{
			Header:  &TCPHeader{SrcPort: conn.Tuple.SrcPort, DstPort: conn.Tuple.DstPort, SeqNum: conn.SND_NXT, AckNum: conn.RCV_NXT, Flags: flags, WindowSize: win},
			Tuple:   conn.Tuple,
			Payload: data,
			Raw:     rawSeg,
		}

		// Write segment immediately if callback is set. Only advance
		// SND_NXT on success so that lost segments are retransmitted
		// with the same sequence numbers on the next tick.
		if ts.writeFunc != nil {
			if err := ts.writeFunc(seg); err != nil {
				break // write failed (e.g. ENOBUFS); retry next tick
			}
		} else {
			ts.outputs = append(ts.outputs, seg)
		}

		conn.SND_NXT += uint32(len(data))
		sentData = true
		segCount++
		debug.Global.TCPDataSegs.Add(1)
		debug.Global.TCPDataBytes.Add(int64(len(data)))
	}

	if sentData {
		conn.LastAckSent = conn.RCV_NXT
		conn.LastAckWin = conn.scaledWindow(false)
		// Exponential backoff: 200ms, 400ms, 800ms, ..., max 60s
		base := int64(200)
		for i := 0; i < conn.RetransmitCount && i < 10; i++ {
			base *= 2
		}
		if base > 60000 {
			base = 60000
		}
		conn.RetransmitAt = ts.tick + ts.msToTicks(base)
		ts.timerWheel.Schedule(conn.Tuple, conn.RetransmitAt)
		debug.Global.TCPInFlight.Store(int64(conn.SND_NXT - conn.SND_UNA))
		debug.Global.TCPCanSend.Store(int64(mss))
	} else if ts.needACK(conn) {
		debug.Global.TCPAckOnly.Add(1)
		ts.sendACK(conn)
	} else {
		debug.Global.TCPNoSend.Add(1)
	}
}

func (ts *TCPState) sendACK(conn *Conn) {
	win := conn.scaledWindow(false)
	rawSeg := BuildSegment(conn.Tuple, conn.SND_NXT, conn.RCV_NXT,
		FlagACK, win, nil)

	conn.LastAckSent = conn.RCV_NXT
	conn.LastAckTime = ts.tick
	conn.LastAckWin = conn.scaledWindow(false)

	seg := &TCPSegment{
		Header:  &TCPHeader{SrcPort: conn.Tuple.SrcPort, DstPort: conn.Tuple.DstPort, SeqNum: conn.SND_NXT, AckNum: conn.RCV_NXT, Flags: FlagACK, WindowSize: win},
		Tuple:   conn.Tuple,
		Raw:     rawSeg,
	}

	if ts.writeFunc != nil {
		ts.writeFunc(seg) // best-effort; ACKs don't advance SND_NXT
	} else {
		ts.outputs = append(ts.outputs, seg)
	}
}

func (ts *TCPState) sendFIN(conn *Conn) {
	win := conn.scaledWindow(false)
	rawSeg := BuildSegment(conn.Tuple, conn.SND_NXT, conn.RCV_NXT,
		FlagFIN|FlagACK, win, nil)

	seg := &TCPSegment{
		Header:  &TCPHeader{SrcPort: conn.Tuple.SrcPort, DstPort: conn.Tuple.DstPort, SeqNum: conn.SND_NXT, AckNum: conn.RCV_NXT, Flags: FlagFIN | FlagACK, WindowSize: win},
		Tuple:   conn.Tuple,
		Raw:     rawSeg,
	}

	if ts.writeFunc != nil {
		if err := ts.writeFunc(seg); err != nil {
			return // write failed; retry next tick
		}
	} else {
		ts.outputs = append(ts.outputs, seg)
	}

	if !conn.FinSent {
		conn.SND_NXT++
	}
	conn.FinSent = true
}

func (ts *TCPState) needACK(conn *Conn) bool {
	if conn.RCV_NXT != conn.LastAckSent {
		return true
	}
	// Window update: the last ACK advertised a window too small for the
	// peer to send (zero, or below 1 MSS). If the window has since opened
	// enough to receive at least one full segment, send an update so the
	// peer unblocks. Without this, upload stalls after RecvBuf fills up
	// because the peer never learns the buffer has been drained.
	mss := ts.cfg.MTU - 20
	if int(conn.LastAckWin) < mss && conn.RecvWritable() >= mss {
		return true
	}
	return false
}

func (ts *TCPState) generateISN() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

func (ts *TCPState) msToTicks(ms int64) int64 {
	return ms * int64(time.Millisecond) / int64(ts.timerWheel.SlotDuration())
}

// checkInvariants validates consistency across all connections.
// A correct implementation should never trip these. When one fires,
// panicking immediately prevents state corruption from cascading into
// confusing misbehavior many ticks later. The cost is a few integer
// comparisons per connection — negligible in batch traversal.
func (ts *TCPState) checkInvariants() {
	all := []map[Tuple]*Conn{
		ts.SynSent, ts.SynRcvd, ts.Established, ts.CloseWait, ts.LastAck,
		ts.FinWait1, ts.FinWait2, ts.TimeWait,
	}
	for _, coll := range all {
		for tuple, conn := range coll {
			if seqGT(conn.SND_UNA, conn.SND_NXT) {
				panic("SND_UNA > SND_NXT in " + tuple.String())
			}
			if int(conn.SND_NXT-conn.SND_UNA) > conn.sendSize+2 {
				panic("inflight exceeds sendSize+2 in " + tuple.String())
			}
			if conn.sendSize < 0 || conn.sendSize > len(conn.SendBuf) {
				panic("sendSize out of bounds in " + tuple.String())
			}
			if conn.recvSize < 0 || conn.recvSize > len(conn.RecvBuf) {
				panic("recvSize out of bounds in " + tuple.String())
			}
		}
	}
}
