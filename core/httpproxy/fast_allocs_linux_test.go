//go:build linux

package httpproxy

import (
	"bytes"
	"net"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	"nvelox/config"
)

// A request answered on the event loops allocates nothing: the request
// logic, the backend connection and the client's side all work in buffers
// that are reused. (The backend and the client of this test use raw
// sockets, so that only the proxy could allocate.)
func TestFastPath_NoAllocationPerRequest(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates")
	}
	quietLog(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				raw, err := c.(*net.TCPConn).SyscallConn()
				if err != nil {
					return
				}
				buf := make([]byte, 4096)
				raw.Control(func(fd uintptr) { unix.SetNonblock(int(fd), false) })
				raw.Control(func(fd uintptr) {
					// One request per read: the proxy sends a head in one write.
					for {
						n, err := unix.Read(int(fd), buf)
						if err == unix.EINTR {
							continue
						}
						if n <= 0 || err != nil {
							return
						}
						if _, err := unix.Write(int(fd), resp); err != nil {
							return
						}
					}
				})
			}(c)
		}
	}()
	site := fastTestSite(&ListenerConfig{Name: "allocs", Addr: "127.0.0.1:0", Protocol: "http"},
		&config.Backend{Servers: []string{ln.Addr().String()}})
	g := startFastGroup(t, site)
	addr := g.BoundAddr().(*net.TCPAddr)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: addr.Port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	tv := unix.Timeval{Sec: 5}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	req := []byte("GET /x HTTP/1.1\r\nHost: allocs.test\r\nUser-Agent: t\r\n\r\n")
	in := make([]byte, 4096)
	requests := func(n int) {
		for i := 0; i < n; i++ {
			if _, err := unix.Write(fd, req); err != nil {
				t.Fatal(err)
			}
			got := 0
			for !bytes.HasSuffix(in[:got], []byte("hello")) {
				m, err := unix.Read(fd, in[got:])
				if err == unix.EINTR {
					continue
				}
				if m <= 0 || err != nil {
					t.Fatalf("request %d: read %d, %v (so far %q)", i, m, err, in[:got])
				}
				got += m
			}
		}
	}
	requests(2000) // connections, buffers, the loops' scratch
	const n = 20000
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	requests(n)
	runtime.ReadMemStats(&after)
	per := float64(after.Mallocs-before.Mallocs) / n
	t.Logf("%.3f allocations per request", per)
	if per > 0.05 {
		t.Fatalf("%.3f allocations per request (%d in %d), want none", per, after.Mallocs-before.Mallocs, n)
	}
}
