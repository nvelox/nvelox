package httpproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// h3StopSite is a site with HTTP/3 whose backend holds the answer to /slow
// until release is called (at the end of the test at the latest); arrived
// counts the requests it holds.
func h3StopSite(t *testing.T, pki *caPKI, answer string) (s *HTTPServer, arrived *atomic.Int32, release func()) {
	t.Helper()
	arrived = new(atomic.Int32)
	held := make(chan struct{})
	release = sync.OnceFunc(func() { close(held) })
	s = h3Site(t, pki, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			arrived.Add(1)
			<-held
		}
		_, _ = io.WriteString(w, answer)
	})
	t.Cleanup(release) // before the backend closes, which waits for its handlers
	return s, arrived, release
}

func h3StopGet(ctx context.Context, cc *http3.ClientConn, addr, path string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+path, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), err
}

// stopGroup stops g with a 10 s limit and reports on the channel when it
// has.
func stopGroup(g *BindGroup) <-chan error {
	stopped := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		stopped <- g.Stop(ctx)
	}()
	return stopped
}

// A request being answered when the group stops is answered in full, and
// the group has stopped only then, well before its limit.
func TestHTTP3_StopLetsRequestsFinish(t *testing.T) {
	quicGoPath(t) // the loops: TestH3Loops_StopLetsRequestsFinish
	pki := newCAPKI(t, "h3-stop-ca")
	answer := strings.Repeat("answered in full\n", 8192) // many packets
	site, arrived, release := h3StopSite(t, pki, answer)
	addr := freeAddr(t)
	g := startGroup(t, addr, site)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	cc := (&http3.Transport{}).NewClientConn(conn)
	if code, _, err := h3StopGet(ctx, cc, addr, "/warmup"); err != nil || code != http.StatusOK {
		t.Fatalf("warmup: status %d, err %v", code, err)
	}

	type result struct {
		code int
		body string
		err  error
	}
	inFlight := make(chan result, 1)
	go func() {
		code, body, err := h3StopGet(ctx, cc, addr, "/slow")
		inFlight <- result{code, body, err}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for arrived.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the request never reached the backend")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// The request takes longer than the time a stop gives the last answers
	// to be delivered: it is the request that is waited for.
	stopped := stopGroup(g)
	select {
	case err := <-stopped:
		t.Fatalf("the group stopped (%v) while a request was being answered", err)
	case <-time.After(h3StopLinger + 300*time.Millisecond):
	}
	began := time.Now()
	release()
	r := <-inFlight
	if r.err != nil || r.code != http.StatusOK || r.body != answer {
		t.Fatalf("the request in flight: status %d, %d of %d bytes, err %v", r.code, len(r.body), len(answer), r.err)
	}
	select {
	case <-stopped:
	case <-time.After(8 * time.Second):
		t.Fatal("the group did not stop within 8 s of its last request being answered")
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Errorf("the group stopped %v after its last request was answered: it waited for its limit", d)
	}
}

// A request that is not answered by the group's limit is closed then, and
// the group has stopped: it does not wait for the backend.
func TestHTTP3_StopClosesAtTheLimit(t *testing.T) { onBothH3Servers(t, stopClosesAtTheLimit) }

func stopClosesAtTheLimit(t *testing.T) {
	pki := newCAPKI(t, "h3-stop-ca")
	site, arrived, _ := h3StopSite(t, pki, "ok")
	addr := freeAddr(t)
	g := startGroup(t, addr, site)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, h3ClientTLS(pki), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	cc := (&http3.Transport{}).NewClientConn(conn)
	ended := make(chan error, 1)
	go func() {
		_, _, err := h3StopGet(ctx, cc, addr, "/slow")
		ended <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for arrived.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the request never reached the backend")
		}
		time.Sleep(5 * time.Millisecond)
	}

	const limit = time.Second
	sctx, scancel := context.WithTimeout(context.Background(), limit)
	defer scancel()
	began := time.Now()
	stopped := make(chan error, 1)
	go func() { stopped <- g.Stop(sctx) }()
	select {
	case <-stopped:
	case <-time.After(limit + 4*time.Second):
		t.Fatal("the group did not stop at its limit: it waits for the backend's answer")
	}
	if d := time.Since(began); d < limit-100*time.Millisecond {
		t.Errorf("the group stopped after %v with a request in flight, before its limit of %v", d, limit)
	}
	select {
	case err := <-ended:
		if err == nil {
			t.Error("the request the backend never answered succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Error("the client's request did not end when the group stopped")
	}
}

// silentConn is a client's UDP socket that can go silent: from then on
// nothing it is given is sent and nothing that arrives is delivered, as for
// a client that has left without a word.
type silentConn struct {
	net.PacketConn
	silent atomic.Bool
}

func (c *silentConn) WriteTo(p []byte, a net.Addr) (int, error) {
	if c.silent.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, a)
}

func (c *silentConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.PacketConn.ReadFrom(p)
		if err != nil || !c.silent.Load() {
			return n, a, err
		}
	}
}

// A client that is gone never closes its connection. The group does not
// wait for it until its limit: it stops once the time given to deliver the
// last answers has passed, and at once when the last answer is older than
// that.
func TestHTTP3_StopDoesNotWaitForIdleClients(t *testing.T) {
	quicGoPath(t) // its second after the last answer; the loops wait for the acknowledgement
	for _, tc := range []struct {
		name       string
		idleFor    time.Duration // between the client's last answer and the stop
		min, max   time.Duration // how long the stop may take
		whyTooLong string
	}{
		{"the last answer just went out", 0, h3StopLinger / 2, 4 * time.Second, "it waited for the client to close its connection"},
		{"the last answer is old", h3StopLinger + 200*time.Millisecond, 0, h3StopLinger / 2, "it waited although nothing was on its way"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pki := newCAPKI(t, "h3-stop-ca")
			site, _, _ := h3StopSite(t, pki, "ok")
			addr := freeAddr(t)
			g := startGroup(t, addr, site)

			udp, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			pc := &silentConn{PacketConn: udp}
			raddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := quic.Dial(ctx, pc, raddr, h3ClientTLS(pki), nil)
			if err != nil {
				t.Fatal(err)
			}
			cc := (&http3.Transport{}).NewClientConn(conn)
			if code, _, err := h3StopGet(ctx, cc, addr, "/"); err != nil || code != http.StatusOK {
				t.Fatalf("request: status %d, err %v", code, err)
			}
			pc.silent.Store(true)
			time.Sleep(tc.idleFor)

			began := time.Now()
			select {
			case <-stopGroup(g):
			case <-time.After(9 * time.Second):
				t.Fatal("the group waited for its limit")
			}
			d := time.Since(began)
			if d > tc.max {
				t.Errorf("the stop took %v: %s", d, tc.whyTooLong)
			}
			if d < tc.min {
				t.Errorf("the stop took %v: the connection was closed with its last answer %v old, sooner than %v", d, d, h3StopLinger)
			}
		})
	}
}
