//go:build linux

package core

import (
	"net"
	"syscall"
)

// setUDPNoDF clears Don't Fragment on a backend UDP socket (IP_PMTUDISC_DONT,
// and IPV6_PMTUDISC_DONT for a v6 socket). Linux's default (PMTUDISC_WANT) sets
// DF on every datagram that fits the local link, so one that outgrows a smaller
// hop further on is dropped instead of fragmented: a 1,400 B payload plus the
// 28 B PROXY v2 header plus 28 B of IP/UDP is 1,456 B, over a 1,450 B VXLAN
// pod network. With DF off the hop fragments it. IPv6 routers never fragment,
// so the v6 option only keeps both families alike. Errors are ignored: the
// option for the other family fails on a single-family socket, and a socket
// that keeps the default still forwards everything that fits.
func setUDPNoDF(c *net.UDPConn) {
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DONT)
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_DONT)
	})
}
