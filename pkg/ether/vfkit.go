// Package ether: vfkit socket connection.
// Handles the unixgram socket that vfkit uses for raw L2 frame I/O.
package ether

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
)

// VFKitConn wraps a unixgram connection to a vfkit VM.
// Reads raw Ethernet frames, writes raw Ethernet frames.
type VFKitConn struct {
	conn       *net.UnixConn
	fd         int
	buf        []byte
	firstFrame *Frame // saved first frame from connection setup
}

// ListenVFKit creates a unixgram listener at the given path and accepts the first connection.
// The socket path must exist (vfkit creates it).
func ListenVFKit(socketPath string) (*VFKitConn, error) {
	// Remove existing socket if present
	os.Remove(socketPath)

	addr := &net.UnixAddr{Name: socketPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return nil, fmt.Errorf("listen unixgram %s: %w", socketPath, err)
	}

	// vfkit sends the first datagram; we need to discover its address.
	buf := make([]byte, 65536)
	n, remoteAddr, err := conn.ReadFromUnix(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read first datagram: %w", err)
	}
	log.Printf("VFKit first datagram: n=%d remote=%s data=%x", n, remoteAddr, buf[:min(n, 64)])

	// Check for legacy "VFKT" handshake
	// vfkit sends a 4-byte "VFKT" handshake before the first Ethernet frame
	firstFrame := true
	if n >= 4 && string(buf[:4]) == "VFKT" {
		// Read the next datagram (first actual Ethernet frame)
		n, _, err = conn.ReadFromUnix(buf)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("read after handshake: %w", err)
		}
		log.Printf("VFKit post-handshake datagram: n=%d data=%x", n, buf[:min(n, 64)])
	}

	// Connect the unixgram socket to the remote address for bidirectional datagram I/O.
	rawConn, err := conn.SyscallConn()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("syscall conn: %w", err)
	}

	var fd int
	var controlErr error
	rawConn.Control(func(f uintptr) {
		fd = int(f)
		// Set non-blocking before connect
		syscall.SetNonblock(fd, true)
		sa := unixAddrToSockaddr(remoteAddr)
		if sa != nil {
			controlErr = syscall.Connect(fd, sa)
		}
	})
	if controlErr != nil {
		conn.Close()
		return nil, fmt.Errorf("connect to vfkit: %w", controlErr)
	}
	log.Printf("VFKit fd=%d connected to %s (nonblocking)", fd, remoteAddr)

	var savedFrame *Frame
	if firstFrame {
		f, err := ParseFrame(buf[:n])
		if err != nil {
			log.Printf("VFKit parse first frame error: %v (n=%d)", err, n)
		} else {
			log.Printf("VFKit saved first frame: src=%s dst=%s type=%04x len=%d", f.SrcMAC, f.DstMAC, f.EtherType, len(f.Payload))
			savedFrame = f
		}
	}

	return &VFKitConn{
		conn:       conn,
		fd:         fd,
		buf:        make([]byte, 65536),
		firstFrame: savedFrame,
	}, nil
}

// ReadFrame reads one Ethernet frame (non-blocking).
// Returns nil, nil if no data is available.
func (v *VFKitConn) ReadFrame() (*Frame, error) {
	// Return saved first frame from connection setup
	if v.firstFrame != nil {
		f := v.firstFrame
		v.firstFrame = nil
		return f, nil
	}

	// Use raw syscall.Read for true non-blocking reads.
	// Go's net.UnixConn.ReadFromUnix handles EAGAIN internally and retries,
	// so we must bypass it for non-blocking semantics.
	n, err := syscall.Read(v.fd, v.buf)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return nil, nil
		}
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return ParseFrame(v.buf[:n])
}

// WriteFrame writes one Ethernet frame.
func (v *VFKitConn) WriteFrame(f *Frame) error {
	data := f.Serialize()
	_, err := syscall.Write(v.fd, data)
	return err
}

// SetNonBlocking sets the socket to non-blocking mode.
func (v *VFKitConn) SetNonBlocking() error {
	return syscall.SetNonblock(v.fd, true)
}

func (v *VFKitConn) Close() error {
	return v.conn.Close()
}

// ReadAllFrames reads all available frames from the socket (non-blocking).
func (v *VFKitConn) ReadAllFrames(ctx context.Context) ([]*Frame, error) {
	var frames []*Frame
	for {
		select {
		case <-ctx.Done():
			return frames, ctx.Err()
		default:
		}
		frame, err := v.ReadFrame()
		if err != nil {
			return frames, err
		}
		if frame == nil {
			break // no more data
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// unixAddrToSockaddr converts a net.UnixAddr to syscall.Sockaddr for use with Connect.
func unixAddrToSockaddr(addr *net.UnixAddr) syscall.Sockaddr {
	if addr == nil {
		return nil
	}
	sa := &syscall.SockaddrUnix{Name: addr.Name}
	return sa
}

func isEAGAIN(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		return opErr.Err == syscall.EAGAIN || opErr.Err == syscall.EWOULDBLOCK
	}
	return false
}

// NewLoopbackConn creates a pair of connected unixgram sockets for testing.
func NewLoopbackConn() (*VFKitConn, *VFKitConn, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}

	// Create net.UnixConn from fds
	f1 := os.NewFile(uintptr(fds[0]), "loopback0")
	defer f1.Close()
	conn1, err := net.FileConn(f1)
	if err != nil {
		return nil, nil, err
	}

	f2 := os.NewFile(uintptr(fds[1]), "loopback1")
	defer f2.Close()
	conn2, err := net.FileConn(f2)
	if err != nil {
		conn1.Close()
		return nil, nil, err
	}

	syscall.SetNonblock(fds[0], true)
	syscall.SetNonblock(fds[1], true)

	return &VFKitConn{
			conn: conn1.(*net.UnixConn),
			fd:   fds[0],
			buf:  make([]byte, 65536),
		}, &VFKitConn{
			conn: conn2.(*net.UnixConn),
			fd:   fds[1],
			buf:  make([]byte, 65536),
		}, nil
}
