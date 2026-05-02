// Package debug provides lightweight periodic flow statistics for BDP
// throughput diagnosis. All counters use atomic operations so they can be
// incremented from the single deliberation goroutine without locks.
package debug

import (
	"log"
	"sync/atomic"
	"time"
)

// FlowStats tracks data flow through the BDP pipeline stages:
//
//	host socket → readHost → SendBuf → sendDataAndAcks → output → vfkit
//
// PrintIfDue() prints a 1-second summary and resets all counters.
type FlowStats struct {
	// Stage 1: readHost (forwarder / NAT)
	FwdReadCalls  atomic.Int64
	FwdReadBytes  atomic.Int64
	FwdReadEAGAIN atomic.Int64 // no data available
	FwdBufFull    atomic.Int64 // SendSpace == 0, skipped read
	FwdBufBytes   atomic.Int64 // bytes accepted by WriteSendBuf

	// Stage 2: sendDataAndAcks (TCP deliberation)
	TCPDataSegs  atomic.Int64 // data-carrying segments emitted
	TCPDataBytes atomic.Int64 // total payload bytes in those segments
	TCPAckOnly   atomic.Int64 // pure ACK segments
	TCPNoSend    atomic.Int64 // neither data nor ACK (idle or window-full)
	TCPInFlight  atomic.Int64 // snapshot of inFlight bytes (last call)
	TCPCanSend   atomic.Int64 // snapshot of canSend (last call)

	// Stage 3: output to vfkit (sendSegment)
	OutSegs    atomic.Int64
	OutBytes   atomic.Int64
	OutARPMiss atomic.Int64
	OutBufFull atomic.Int64 // ENOBUFS on vfkit socket write

	lastPrint time.Time
}

// Global is the singleton stats collector.
var Global = &FlowStats{lastPrint: time.Now()}

// PrintIfDue prints a summary if at least 1 second has passed since last print.
func (s *FlowStats) PrintIfDue() {
	if time.Since(s.lastPrint) >= time.Second {
		s.Print()
		s.lastPrint = time.Now()
	}
}

// Print logs the current 1-second window stats and resets counters.
func (s *FlowStats) Print() {
	log.Printf("DEBUG STATS (1s window): "+
		"read={calls:%d bytes:%d eagain:%d full:%d bufb:%d} "+
		"tcp={segs:%d bytes:%d ack:%d nosend:%d inflight:%d cansnd:%d} "+
		"out={segs:%d bytes:%d arpmiss:%d buffull:%d}",
		s.FwdReadCalls.Swap(0),
		s.FwdReadBytes.Swap(0),
		s.FwdReadEAGAIN.Swap(0),
		s.FwdBufFull.Swap(0),
		s.FwdBufBytes.Swap(0),
		s.TCPDataSegs.Swap(0),
		s.TCPDataBytes.Swap(0),
		s.TCPAckOnly.Swap(0),
		s.TCPNoSend.Swap(0),
		s.TCPInFlight.Swap(0),
		s.TCPCanSend.Swap(0),
		s.OutSegs.Swap(0),
		s.OutBytes.Swap(0),
		s.OutARPMiss.Swap(0),
		s.OutBufFull.Swap(0),
	)
}
