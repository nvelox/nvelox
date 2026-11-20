//go:build !linux

package proxy

import (
	"net"
	"net/netip"
)

// DestReader reads the datagrams of a UDP socket with the address and port
// each was sent to. On this system a socket bound to every address is not
// told which one a datagram named: its address is then unspecified, and a
// signed header that came to it does not verify.
type DestReader struct {
	pc    *net.UDPConn
	local netip.AddrPort
}

// NewDestReader returns a reader of pc.
func NewDestReader(pc *net.UDPConn, dests bool) *DestReader {
	r := &DestReader{pc: pc}
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		r.local = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return r
}

// ReadFrom reads one datagram into b: its length, its sender, and the
// address and port it was sent to.
func (r *DestReader) ReadFrom(b []byte) (n int, from, to netip.AddrPort, err error) {
	n, from, err = r.pc.ReadFromUDPAddrPort(b)
	return n, from, r.local, err
}
