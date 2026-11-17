//go:build !linux

package core

import (
	"errors"
	"net"
)

// udpFast is the event-loop UDP engine, which runs on Linux only
// (udpfast_linux.go); elsewhere the nbio engine serves UDP.
type udpFast struct{}

func (e *Engine) startUDPFast(*udpInterfacePlan, *ProxyEventHandler) error {
	return errors.New("UDP on the event loops is supported on Linux only")
}

func (u *udpFast) stop() {}

func (u *udpFast) closeSessionsOf(func(net.IP) bool) int { return 0 }
