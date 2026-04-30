package tcp

import (
	"math/rand"
	"net"
	"time"
)

// ============================================================================
// TCPState: BDP state-indexed TCP engine.
// All connections are organized by their current TCP state into collections.
// A single Deliberate() call batch-processes all connections.
// ============================================================================

type Config struct {
	ListenPort  uint16
	GatewayIP   net.IP
	BPT         time.Duration // Business Planck Time — deliberation interval
	BufferSize  int           // per-connection buffer size
	MTU         int           // max TCP payload per segment
	IdleTimeout time.Duration // idle connection timeout (0 = no timeout)
}

func DefaultConfig() Config {
	return Config{
		BPT:        1 * time.Millisecond,
		BufferSize: 64 * 1024,
		MTU:        1400,         // 1500 - IP header - TCP header
		IdleTimeout: 30 * time.Minute,
	}
}

type TCPState struct {
	cfg Config

	// --- Connection state collections (state = set membership) ---
	// Topological order: SYN_SENT → SYN_RCVD → ESTABLISHED → CLOSE_WAIT → LAST_ACK
	//                      → FIN_WAIT1 → FIN_WAIT2 → TIME_WAIT → (reclaimed)

	SynSent     map[Tuple]*Conn // active open: sent SYN, waiting for SYN-ACK
	SynRcvd     map[Tuple]*Conn // passive open: received SYN, sent SYN-ACK, waiting for ACK
	Established map[Tuple]*Conn // connection established, data transfer
	CloseWait   map[Tuple]*Conn // received peer FIN, waiting for app to close
	LastAck     map[Tuple]*Conn // app closed, sent FIN, waiting for ACK
	FinWait1    map[Tuple]*Conn // sent FIN first (active close), waiting for ACK
	FinWait2    map[Tuple]*Conn // ACK of our FIN received, waiting for peer's FIN
	TimeWait    map[Tuple]*Conn // both FINs exchanged, waiting 2MSL

	// Listener: single passive open (for simplicity, one port)
	listenPort uint16
	listener   *Listener

	// --- Incoming segments (this round's batch) ---
	pending []*TCPSegment

	// --- Outgoing segments (delivered to IP layer after deliberation) ---
	outputs []*TCPSegment

	// --- Timer wheel (orthogonal index: time dimension) ---
	timerWheel *TimerWheel
	tick       int64 // current tick (monotonic, in wheel units)

	// --- App layer callbacks ---
	onAccept func(*Conn)
	appWrites map[Tuple][]byte  // data from app to send
	appCloses map[Tuple]bool    // app has closed

	// --- ISN generator ---
	rng *rand.Rand
}

func NewTCPState(cfg Config) *TCPState {
	tw := NewTimerWheel(10*time.Millisecond, 3000) // 10ms slots, 30s span
	return &TCPState{
		cfg:         cfg,
		SynSent:     make(map[Tuple]*Conn),
		SynRcvd:     make(map[Tuple]*Conn),
		Established: make(map[Tuple]*Conn),
		CloseWait:   make(map[Tuple]*Conn),
		LastAck:     make(map[Tuple]*Conn),
		FinWait1:    make(map[Tuple]*Conn),
		FinWait2:    make(map[Tuple]*Conn),
		TimeWait:    make(map[Tuple]*Conn),
		listenPort:  cfg.ListenPort,
		timerWheel:  tw,
		tick:        time.Now().UnixNano() / int64(tw.SlotDuration()),
		appWrites:   make(map[Tuple][]byte),
		appCloses:   make(map[Tuple]bool),
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (ts *TCPState) Listen(fn func(*Conn)) {
	ts.listener = &Listener{
		Port:     ts.listenPort,
		OnAccept: fn,
	}
}

func (ts *TCPState) SetGatewayIP(ip net.IP) {
	ts.cfg.GatewayIP = ip
}

// InjectSegment adds an incoming TCP segment to this round's batch.
// This is called from the IP layer after parsing.
func (ts *TCPState) InjectSegment(seg *TCPSegment) {
	ts.pending = append(ts.pending, seg)
}

// AppWrite queues data from the application to be sent on a connection.
func (ts *TCPState) AppWrite(tuple Tuple, data []byte) {
	ts.appWrites[tuple] = append(ts.appWrites[tuple], data...)
}

// AppClose queues a close request from the application.
func (ts *TCPState) AppClose(tuple Tuple) {
	ts.appCloses[tuple] = true
}

// ConsumeOutputs returns and clears the output segment queue.
func (ts *TCPState) ConsumeOutputs() []*TCPSegment {
	out := ts.outputs
	ts.outputs = nil
	return out
}

// RecvData reads received data from a connection's buffer.
func (ts *TCPState) RecvData(tuple Tuple, buf []byte) int {
	for _, coll := range []map[Tuple]*Conn{ts.SynSent, ts.Established, ts.CloseWait, ts.LastAck, ts.FinWait1, ts.FinWait2} {
		if conn, ok := coll[tuple]; ok {
			return conn.ReadRecvBuf(buf)
		}
	}
	return 0
}

// ConnectionCount returns the total number of connections across all states.
func (ts *TCPState) ConnectionCount() int {
	return len(ts.SynSent) + len(ts.SynRcvd) + len(ts.Established) +
		len(ts.CloseWait) + len(ts.LastAck) +
		len(ts.FinWait1) + len(ts.FinWait2) + len(ts.TimeWait)
}

// CreateExternalConn creates a TCP connection representing a remote endpoint.
// Used by NAT for outbound connections. The connection starts in SynRcvd state.
// tuple should already be in response direction (Ext_IP:Ext_Port → VM_IP:VM_Port)
// as the NAT module reverses the segment tuple before calling this.
// irs is the initial receive sequence (VM's SEQ from the intercepted SYN).
func (ts *TCPState) CreateExternalConn(tuple Tuple, irs uint32, window uint16) *Conn {
	iss := ts.generateISN()
	conn := NewConn(tuple, irs, iss, window, ts.cfg.BufferSize)
	conn.LastActivityTick = ts.tick
	conn.RetransmitAt = ts.tick + ts.msToTicks(200)
	ts.SynRcvd[tuple] = conn
	return conn
}

// ActiveOpen initiates a TCP connection to the VM (used by port forwarding).
// tuple must be in response direction: (GW_IP, VM_IP, GW_Port, VM_Port).
// Returns the connection, which starts in SynSent state.
func (ts *TCPState) ActiveOpen(tuple Tuple, vmWindow uint16) *Conn {
	iss := ts.generateISN()
	// IRS is unknown until we receive SYN-ACK; start as 0
	conn := NewConn(tuple, 0, iss, vmWindow, ts.cfg.BufferSize)
	conn.LastActivityTick = ts.tick
	conn.RetransmitAt = ts.tick + ts.msToTicks(200)
	ts.SynSent[tuple] = conn
	return conn
}

// ============================================================================
// Deliberate — the core BDP batch processing loop.
// Called once per BPT interval. Processes ALL connections.
// ============================================================================

func (ts *TCPState) Deliberate(now time.Time) {
	ts.tick = ts.timerWheel.Advance(now)

	// Phase 1: Process timers — may move connections backward
	ts.processTimers()

	// Phase 2: Dispatch pending segments to their target connections
	ts.dispatchSegments()

	// Phase 3: Process app-layer writes and closes
	ts.processAppRequests()

	// Phase 4: Advance connections in topological order
	// Forward transitions cascade (move to "later" collection → same-round processing)
	// Backward transitions delay (move to "earlier" collection → next round)
	ts.advanceSynSent()
	ts.advanceSynRcvd()
	ts.advanceEstablished()
	ts.advanceCloseWait()
	ts.advanceLastAck()
	ts.advanceFinWait1()
	ts.advanceFinWait2()
	ts.advanceTimeWait()

	// Phase 5: Cleanup closed connections
	ts.reclaimClosed()
}
