//go:build unix

package core

import (
	"net"
	"sync"
	"syscall"
)

// udpReplyBufPool holds the 64 KiB buffers backend replies are read into.
var udpReplyBufPool = sync.Pool{New: func() any {
	b := make([]byte, udpMaxDatagram)
	return &b
}}

// udpBackendReader reads replies from a UDP session's connected backend
// socket. It borrows a 64 KiB buffer from udpReplyBufPool only once the socket
// is readable and returns it as soon as the datagram is relayed, so the many
// sessions waiting for their backend hold no buffer (measured: ~68 KiB per
// idle session before, ~7 KiB now — its goroutine, socket and conn state).
type udpBackendReader struct {
	rc syscall.RawConn
}

func newUDPBackendReader(c *net.UDPConn) (*udpBackendReader, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	return &udpBackendReader{rc: rc}, nil
}

// read waits for the next datagram (honouring the conn's read deadline) and
// passes it to deliver; the slice is valid only during the call.
func (r *udpBackendReader) read(deliver func([]byte)) error {
	var (
		bp   *[]byte
		n    int
		rerr error
	)
	err := r.rc.Read(func(fd uintptr) bool {
		b := udpReplyBufPool.Get().(*[]byte)
		for {
			n, rerr = syscall.Read(int(fd), *b)
			if rerr != syscall.EINTR {
				break
			}
		}
		if rerr == syscall.EAGAIN {
			udpReplyBufPool.Put(b)
			return false // not readable yet: wait (no buffer held meanwhile)
		}
		bp = b
		return true
	})
	if bp != nil {
		defer udpReplyBufPool.Put(bp)
	}
	if err != nil {
		return err
	}
	if rerr != nil {
		return rerr
	}
	deliver((*bp)[:n])
	return nil
}
