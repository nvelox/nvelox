//go:build linux

package httpproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
)

// How many idle backend connections a loop keeps: as many as were in use
// at the same time in the last seconds, never fewer than the fixed number
// of before.

// The peak of a pool's connections in use, period by period.
func TestUpPool_Peak(t *testing.T) {
	period := poolPeakPeriod
	at := func(periods float64) int64 { return int64(periods * float64(period)) }
	var p upPool
	var us [10]uconn
	const floor = 3
	if got := p.keep(at(0.1), floor); got != floor {
		t.Fatalf("an unused pool keeps %d, want the floor %d", got, floor)
	}
	// Ten in use at once.
	for i := range us {
		p.use(&us[i], at(0.2))
	}
	done := func(i int) { us[i].up.inUse--; us[i].up = nil }
	if p.inUse != 10 || p.keep(at(0.3), floor) != 10 {
		t.Fatalf("ten in use: inUse %d, keep %d", p.inUse, p.keep(at(0.3), floor))
	}
	// Eight of them finish: the peak stays for this period and the next.
	for i := 0; i < 8; i++ {
		done(i)
	}
	for _, when := range []float64{0.5, 1.0, 1.9} {
		if got := p.keep(at(when), floor); got != 10 {
			t.Errorf("at period %.1f the pool keeps %d, want 10", when, got)
		}
	}
	// Two periods on, only what is in use now counts, and below the floor
	// the floor.
	if got := p.keep(at(2.1), floor); got != floor {
		t.Errorf("two periods after the burst the pool keeps %d, want the floor %d (2 in use)", got, floor)
	}
	p.use(&us[0], at(2.2))
	p.use(&us[1], at(2.2))
	if got := p.keep(at(2.3), floor); got != 4 {
		t.Errorf("with 4 in use the pool keeps %d", got)
	}
	// A long silence forgets everything.
	for i := 0; i < 2; i++ {
		done(i)
	}
	done(8)
	done(9)
	if got := p.keep(at(50), floor); got != floor || p.inUse != 0 {
		t.Errorf("after a long silence: keep %d, inUse %d", got, p.inUse)
	}
}

// gateBackend is a keep-alive backend whose answers wait for a gate. It
// counts the connections it has accepted and the ones still open.
type gateBackend struct {
	ln       net.Listener
	accepted atomic.Int64
	open     atomic.Int64
	waiting  atomic.Int64 // requests read and not yet answered
	mu       sync.Mutex
	gate     chan struct{} // closed: answers go out
}

func newGateBackend(t *testing.T) *gateBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &gateBackend{ln: ln, gate: make(chan struct{})}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.accepted.Add(1)
			b.open.Add(1)
			go func() {
				defer b.open.Add(-1)
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					io.Copy(io.Discard, req.Body)
					b.waiting.Add(1)
					b.mu.Lock()
					gate := b.gate
					b.mu.Unlock()
					<-gate
					b.waiting.Add(-1)
					if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
						return
					}
				}
			}()
		}
	}()
	return b
}

// hold makes the next answers wait; release lets them go.
func (b *gateBackend) hold()    { b.mu.Lock(); b.gate = make(chan struct{}); b.mu.Unlock() }
func (b *gateBackend) release() { b.mu.Lock(); close(b.gate); b.mu.Unlock() }

// A load larger than the fixed number of before: every connection it used
// at once is kept, so the same load again opens none. Once the load is
// gone and the last seconds have passed, the pool needs no more than the
// floor, and a connection returned to it is closed.
func TestFastPath_IdlePoolFollowsUse(t *testing.T) {
	old := poolPeakPeriod
	poolPeakPeriod = int64(150 * time.Millisecond)
	t.Cleanup(func() { poolPeakPeriod = old })

	be := newGateBackend(t)
	l := &ListenerConfig{Name: "site", Addr: "127.0.0.1:0", Protocol: "http"}
	addr := startTestGroup(t, fastTestSite(l, &config.Backend{Servers: []string{be.ln.Addr().String()}}), true)

	// More requests at once than every loop's fixed share together (256
	// per backend server, or 16 per loop where that is more).
	const clients = 400
	conns := make([]net.Conn, clients)
	readers := make([]*bufio.Reader, clients)
	for i := range conns {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(30 * time.Second))
		conns[i], readers[i] = c, bufio.NewReader(c)
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s (accepted %d, open %d, waiting %d)", what, be.accepted.Load(), be.open.Load(), be.waiting.Load())
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	// round sends one request on each of the first n client connections,
	// waits until the backend holds them all, lets them go and reads the
	// answers.
	round := func(n int) {
		t.Helper()
		be.hold()
		for i := 0; i < n; i++ {
			if _, err := fmt.Fprintf(conns[i], "GET /%d HTTP/1.1\r\nHost: example.test\r\n\r\n", i); err != nil {
				t.Fatal(err)
			}
		}
		waitFor(fmt.Sprintf("%d requests at the backend at once", n), func() bool { return be.waiting.Load() == int64(n) })
		be.release()
		for i := 0; i < n; i++ {
			resp, err := http.ReadResponse(readers[i], nil)
			if err != nil {
				t.Fatalf("client %d: %v", i, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("client %d: status %d", i, resp.StatusCode)
			}
		}
	}

	round(clients)
	if got := be.accepted.Load(); got != clients {
		t.Fatalf("the first %d requests opened %d backend connections", clients, got)
	}
	// The same load again: every connection is there.
	round(clients)
	if got := be.accepted.Load(); got != clients {
		t.Errorf("the same load a second time opened %d more backend connections; want none", got-clients)
	}
	if got := be.open.Load(); got != clients {
		t.Errorf("%d backend connections open after the load, want the %d it used at once", got, clients)
	}

	// The load is gone. After the last seconds have passed, the pools need
	// only the floor: a request's connection, returned to a pool that
	// holds more than that, is closed, and no new one is opened for it.
	time.Sleep(time.Duration(3 * poolPeakPeriod))
	round(1)
	waitFor("a connection returned to a pool that holds too many to be closed", func() bool { return be.open.Load() == clients-1 })
	if got := be.accepted.Load(); got != clients {
		t.Errorf("a request after the load opened %d new backend connections", got-clients)
	}
}
