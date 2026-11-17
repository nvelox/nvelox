//go:build !linux

package core

import (
	"errors"
	"net"
)

// listenUDPSocket: interface-bound UDP sockets need Linux (planUDPInterfaces
// refuses accept_proxy_interfaces elsewhere before this is reached).
func listenUDPSocket(network string, laddr *net.UDPAddr, dev string) (*net.UDPConn, error) {
	return nil, errors.New("accept_proxy_interfaces is supported on Linux only")
}
