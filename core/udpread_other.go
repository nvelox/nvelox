//go:build !unix

package core

import "net"

// udpBackendReader reads replies from a UDP session's connected backend
// socket. Outside unix it keeps one 64 KiB buffer per session.
type udpBackendReader struct {
	c   *net.UDPConn
	buf []byte
}

func newUDPBackendReader(c *net.UDPConn) (*udpBackendReader, error) {
	return &udpBackendReader{c: c, buf: make([]byte, udpMaxDatagram)}, nil
}

// read waits for the next datagram (honouring the conn's read deadline) and
// passes it to deliver; the slice is valid only during the call.
func (r *udpBackendReader) read(deliver func([]byte)) error {
	n, err := r.c.Read(r.buf)
	if err != nil {
		return err
	}
	deliver(r.buf[:n])
	return nil
}
