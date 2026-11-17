//go:build !linux

package core

import "net"

// The event-loop L4 relay is Linux only (l4fast_linux.go).

type l4FastServer struct{}

func l4FastEnabled() bool { return false }

func (e *Engine) startL4Fast(net.Listener, *ListenerConfig, *ProxyEventHandler) error {
	panic("core: event-loop L4 relay not supported")
}

func (f *l4FastServer) stop() {}
