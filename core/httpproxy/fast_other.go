//go:build !linux

package httpproxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"nvelox/config"
)

// The event-loop fast path is Linux only; elsewhere every connection is
// served by net/http.

type fastServer struct{}

func fastPathEnabled() bool { return false }

func (g *BindGroup) startFast(net.Listener, time.Duration, time.Duration) error {
	panic("httpproxy: fast path not supported")
}

func (fs *fastServer) shutdown(<-chan struct{}) bool { return true }

func (g *BindGroup) startFastTLS(net.Listener, time.Duration, time.Duration) {
	panic("httpproxy: fast path not supported")
}

func fastTLSState(*http.Request) *tls.ConnectionState { return nil }

// HTTP/3 on the event loops is Linux only too: the quic-go server serves
// it elsewhere.
type quicServer struct{}

func (g *BindGroup) bindH3Loops(*tls.Config, time.Duration) (bool, error) { return false, nil }

func (g *BindGroup) serveH3Loops() {}

func (g *BindGroup) stopH3Loops() {}

// The totals of server.http3 bound nvelox's own QUIC transport, which
// runs on the event loops.
func applyHTTP3Memory(*config.HTTP3Limits) {}
