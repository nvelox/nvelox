//go:build linux

package proxy

import (
	"net"
	"net/netip"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"
)

// DestReader reads the datagrams of a UDP socket with the address and port
// each was sent to: the receiver's end of a relay's datagram (Ends). On a
// socket bound to every address the system tells it with each datagram
// (IP_PKTINFO, IPV6_PKTINFO), once asked to; on one bound to one address
// it is that address.
type DestReader struct {
	pc    *net.UDPConn
	local netip.AddrPort // the socket's address, IPv4 in its own form
	wild  bool           // bound to every address, and asked to tell
	oob   []byte
}

// NewDestReader returns a reader of pc. With dests false, or on a socket
// bound to one address, it reads as ReadFromUDPAddrPort does and asks the
// system for nothing more.
func NewDestReader(pc *net.UDPConn, dests bool) *DestReader {
	r := &DestReader{pc: pc}
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		ap := ua.AddrPort()
		r.local = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		r.wild = dests && (ua.IP == nil || ua.IP.IsUnspecified())
	}
	if r.wild {
		if rc, err := pc.SyscallConn(); err == nil {
			_ = rc.Control(func(fd uintptr) {
				// Either fails on a socket of the other family, which then
				// has no use for it.
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
			})
		}
		// An IPv4 datagram on a dual-stack socket comes with both messages.
		r.oob = make([]byte, 128)
	}
	return r
}

// ReadFrom reads one datagram into b: its length, its sender, and the
// address and port it was sent to (its address unspecified when that is
// not known).
func (r *DestReader) ReadFrom(b []byte) (n int, from, to netip.AddrPort, err error) {
	if !r.wild {
		n, from, err = r.pc.ReadFromUDPAddrPort(b)
		return n, from, r.local, err
	}
	n, oobn, flags, from, err := r.pc.ReadMsgUDPAddrPort(b, r.oob)
	to = r.local
	if err == nil && flags&unix.MSG_CTRUNC == 0 {
		if a, ok := ngx.PktinfoDst(r.oob[:oobn]); ok {
			to = netip.AddrPortFrom(a, r.local.Port())
		}
	}
	return n, from, to, err
}
