package tcp

import (
	"time"
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
		if conn, ok := ts.Established[tuple]; ok {
			// Retransmit: resend last unacked data
			// For simplicity, re-trigger sending by generating an output
			conn.RetransmitAt = 0
			// Send pending data (will be handled by advanceEstablished)
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
			conn.FinSent = true
			ts.FinWait1[tuple] = conn
		} else if conn := ts.findConnInState(tuple, ts.CloseWait); conn != nil {
			// Passive close (peer FIN first, then app closes): CloseWait → LastAck
			delete(ts.CloseWait, tuple)
			conn.FinSent = true
			ts.LastAck[tuple] = conn
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
			conn.PendingSegs = nil
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
	conn.SND_NXT = conn.ISS + 1 // SYN consumes one sequence number
	conn.RetransmitAt = ts.tick + ts.msToTicks(200)

	rawSeg := BuildSegment(conn.Tuple, conn.ISS, 0, FlagSYN, uint16(conn.RecvWritable()), nil)
	ts.outputs = append(ts.outputs, &TCPSegment{
		Header: &TCPHeader{
			SrcPort: conn.Tuple.DstPort, DstPort: conn.Tuple.SrcPort,
			SeqNum: conn.ISS, AckNum: 0,
			Flags: FlagSYN, WindowSize: uint16(conn.RecvWritable()),
		},
		Tuple: conn.Tuple,
		Raw:   rawSeg,
	})
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
			conn.PendingSegs = nil // consumed
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
	conn.SND_NXT = conn.ISS + 1 // the SYN in SYN-ACK consumes one sequence number
		conn.RetransmitAt = ts.tick + ts.msToTicks(200)

	rawSeg := BuildSegment(conn.Tuple, conn.ISS, conn.RCV_NXT,
		FlagSYN|FlagACK, uint16(conn.RecvWritable()), nil)
	ts.outputs = append(ts.outputs, &TCPSegment{
		Header: &TCPHeader{
			SrcPort: conn.Tuple.DstPort, DstPort: conn.Tuple.SrcPort,
			SeqNum: conn.ISS, AckNum: conn.RCV_NXT,
			Flags: FlagSYN | FlagACK, WindowSize: uint16(conn.RecvWritable()),
		},
		Tuple: conn.Tuple,
		Raw:   rawSeg,
	})
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
			if seg.Header.IsACK() && seg.Header.AckNum > conn.SND_UNA {
				conn.AckSendBuf(seg.Header.AckNum)
				conn.SND_UNA = seg.Header.AckNum
				conn.SND_WND = uint32(seg.Header.WindowSize)
			}

			// Process data
			if len(seg.Payload) > 0 && seg.Header.SeqNum == conn.RCV_NXT {
				n := conn.WriteRecvBuf(seg.Payload)
				if n > 0 {
					conn.RCV_NXT += uint32(n)
					conn.DataRcvdThisRound = true
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
		conn.DataRcvdThisRound = false
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
			if seg.Header.IsACK() && seg.Header.AckNum > conn.SND_UNA {
				conn.AckSendBuf(seg.Header.AckNum)
				conn.SND_UNA = seg.Header.AckNum
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
		conn.DataRcvdThisRound = false
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
			if seg.Header.IsACK() && seg.Header.AckNum > conn.SND_UNA {
				conn.AckSendBuf(seg.Header.AckNum)
				conn.SND_UNA = seg.Header.AckNum
				// Check if ACK covers our FIN
				if conn.FinSent {
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

		// Resend FIN
		ts.sendFIN(conn)
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
				if seg.Header.AckNum > conn.SND_UNA {
					conn.SND_UNA = seg.Header.AckNum
				}
				// Our FIN was acked if the ACK covers our FIN seq = ISS+1+dataSent
				if conn.FinSent && seg.Header.AckNum > conn.ISS+1 {
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
					conn.DataRcvdThisRound = true
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
				conn.SND_UNA = seg.Header.AckNum
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
	// Calculate how much data we can send
	inFlight := conn.SND_NXT - conn.SND_UNA
	window := conn.SND_WND
	if window == 0 {
		window = 65535
	}
	canSend := int(window) - int(inFlight)
	if canSend < 0 {
		canSend = 0
	}
	if canSend > ts.cfg.MTU-20 {
		canSend = ts.cfg.MTU - 20
	}

	data := conn.PeekSendData(canSend)

	if len(data) > 0 {
		// Send data + ACK
		flags := uint8(FlagACK | FlagPSH)
		rawSeg := BuildSegment(conn.Tuple, conn.SND_NXT, conn.RCV_NXT,
			flags, uint16(conn.RecvWritable()), data)

		conn.SND_NXT += uint32(len(data))
		conn.RetransmitAt = ts.tick + ts.msToTicks(200)
		ts.timerWheel.Schedule(conn.Tuple, conn.RetransmitAt)

		ts.outputs = append(ts.outputs, &TCPSegment{
			Header:  &TCPHeader{SrcPort: conn.Tuple.DstPort, DstPort: conn.Tuple.SrcPort, SeqNum: conn.SND_NXT - uint32(len(data)), AckNum: conn.RCV_NXT, Flags: flags, WindowSize: uint16(conn.RecvWritable())},
			Tuple:   conn.Tuple,
			Payload: data,
			Raw:     rawSeg,
		})
	} else if ts.needACK(conn) {
		// Send pure ACK
		ts.sendACK(conn)
	}
}

func (ts *TCPState) sendACK(conn *Conn) {
	rawSeg := BuildSegment(conn.Tuple, conn.SND_NXT, conn.RCV_NXT,
		FlagACK, uint16(conn.RecvWritable()), nil)

	conn.LastAckSent = conn.RCV_NXT
	conn.LastAckTime = ts.tick

	ts.outputs = append(ts.outputs, &TCPSegment{
		Header:  &TCPHeader{SrcPort: conn.Tuple.DstPort, DstPort: conn.Tuple.SrcPort, SeqNum: conn.SND_NXT, AckNum: conn.RCV_NXT, Flags: FlagACK, WindowSize: uint16(conn.RecvWritable())},
		Tuple:   conn.Tuple,
		Raw:     rawSeg,
	})
}

func (ts *TCPState) sendFIN(conn *Conn) {
	rawSeg := BuildSegment(conn.Tuple, conn.SND_NXT, conn.RCV_NXT,
		FlagFIN|FlagACK, uint16(conn.RecvWritable()), nil)

	ts.outputs = append(ts.outputs, &TCPSegment{
		Header:  &TCPHeader{SrcPort: conn.Tuple.DstPort, DstPort: conn.Tuple.SrcPort, SeqNum: conn.SND_NXT, AckNum: conn.RCV_NXT, Flags: FlagFIN | FlagACK, WindowSize: uint16(conn.RecvWritable())},
		Tuple:   conn.Tuple,
		Raw:     rawSeg,
	})
	conn.SND_NXT++
	conn.FinSent = true
}

func (ts *TCPState) needACK(conn *Conn) bool {
	if conn.RCV_NXT == conn.LastAckSent {
		return false
	}
	// Delayed ACK: defer ACK by one round when new data arrived this round,
	// so multiple segments can be acknowledged in a single reply. This avoids
	// the "silly window syndrome" of tiny ACK segments.
	if conn.DataRcvdThisRound {
		return false
	}
	return true
}

func (ts *TCPState) generateISN() uint32 {
	return ts.rng.Uint32()
}

func (ts *TCPState) msToTicks(ms int64) int64 {
	return ms * int64(time.Millisecond) / int64(ts.timerWheel.SlotDuration())
}
