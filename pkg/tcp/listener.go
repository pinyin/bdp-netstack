package tcp

// Listener represents a TCP listening socket.
type Listener struct {
	Port     uint16
	OnAccept func(*Conn)
}
