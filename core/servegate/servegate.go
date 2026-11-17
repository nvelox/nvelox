// Package servegate holds serving back until the process may serve: started
// as root, nvelox binds every socket, switches to server.user (core/privdrop)
// and only then answers anything, so no request is served with root rights.
package servegate

import "sync"

// Gate is shut until Open. A nil Gate is open.
type Gate struct {
	ch   chan struct{}
	once sync.Once
}

// New returns a shut gate.
func New() *Gate { return &Gate{ch: make(chan struct{})} }

// Open lets every waiter through, now and later. It may be called more than
// once.
func (g *Gate) Open() {
	if g != nil {
		g.once.Do(func() { close(g.ch) })
	}
}

// Wait blocks until the gate is open (true) or done is closed first (false:
// the caller is shutting down and serves nothing).
func (g *Gate) Wait(done <-chan struct{}) bool {
	if g == nil {
		return true
	}
	select {
	case <-g.ch:
		return true
	case <-done:
		select {
		case <-g.ch:
			return true
		default:
			return false
		}
	}
}
