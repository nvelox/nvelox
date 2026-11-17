//go:build linux

package core

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// listenUDPSocket opens a UDP socket that shares its port (SO_REUSEADDR) and,
// when dev is set, takes only packets that arrived on that interface
// (SO_BINDTODEVICE).
func listenUDPSocket(network string, laddr *net.UDPAddr, dev string) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if serr == nil && dev != "" {
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
				if serr != nil {
					serr = fmt.Errorf("bind to interface %s: %w", dev, serr)
				}
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
}
