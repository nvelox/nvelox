//go:build !linux

package core

import "net"

// setUDPNoDF is Linux-only (IP_MTU_DISCOVER); other platforms keep their default.
func setUDPNoDF(*net.UDPConn) {}
