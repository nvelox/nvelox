//go:build linux

package httpproxy

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"nvelox/config"
)

// hangingAddr returns the address of a TCP socket whose accept queue is
// full and never drained: Linux drops a further SYN, so a connect to it
// waits until the dialer gives up. It skips the test where that cannot be
// arranged.
func hangingAddr(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socket: %v", err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Skipf("bind: %v", err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Skipf("listen: %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Skipf("getsockname: %v", err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", sa.(*syscall.SockaddrInet4).Port)
	for i := 0; i < 8; i++ {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return addr // the queue is full: connects now hang
			}
			t.Skipf("dial: %v", err)
		}
		t.Cleanup(func() { c.Close() })
	}
	t.Skip("could not fill the accept queue")
	return ""
}

// TestProxy_BackendConnectTimeout: an HTTP backend's timeouts.connect bounds
// the dial (HTTP used a fixed 10 s), else the listener's timeouts.connect.
func TestProxy_BackendConnectTimeout(t *testing.T) {
	cases := []struct {
		name string
		l    *ListenerConfig
		be   *config.Backend
	}{
		{"backend", &ListenerConfig{}, &config.Backend{Timeouts: config.TimeoutConfig{Connect: "300ms"}}},
		{"listener", &ListenerConfig{Timeouts: config.TimeoutConfig{Connect: "300ms"}}, &config.Backend{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, addr := secSite(t, c.l, []string{hangingAddr(t)}, secOpts{backend: c.be})
			start := time.Now()
			resp, _ := secRaw(t, addr, secGet("/", ""), 5*time.Second)
			if !strings.HasPrefix(secStatus(resp), "HTTP/1.1 502") {
				t.Fatalf("unreachable backend -> %q, want 502", secStatus(resp))
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Fatalf("502 after %v, want about the 300ms connect timeout", took)
			}
		})
	}
}
