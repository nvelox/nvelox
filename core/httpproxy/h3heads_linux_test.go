//go:build linux

package httpproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"nvelox/config"
)

// Heads over HTTP/3 that the tests of h3conn_linux_test.go do not ask for.
// Responses whose head is more than one field section a loop writes as it
// reads the backend's: interim responses (103 Early Hints), and heads past
// what a loop parses itself, which are parsed and encoded off the loop
// (bigHead.buildH3). And the number of fields a request head may have.

// h3Interim is an interim response as a client got it.
type h3Interim struct {
	status int
	header http.Header
}

// h3Reply is what an HTTP/3 client got for one request.
type h3Reply struct {
	status  int
	header  http.Header
	body    []byte
	interim []h3Interim // in the order they came
}

// h3Fields lists h's fields in the order of their names, without Date and
// without the names in skip.
func h3Fields(h http.Header, skip ...string) string {
	keys := make([]string, 0, len(h))
next:
	for k := range h {
		if k == "Date" {
			continue
		}
		for _, s := range skip {
			if k == s {
				continue next
			}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%q ", k, h[k])
	}
	return b.String()
}

// interims lists the interim responses of a reply, each "<status>
// <fields>", without the fields named in skip.
func (a *h3Reply) interims(skip ...string) string {
	var b strings.Builder
	for _, i := range a.interim {
		fmt.Fprintf(&b, "%d %s| ", i.status, h3Fields(i.header, skip...))
	}
	return b.String()
}

// What nvelox puts on every response. The quic-go server, like net/http,
// sends these with an interim response too; the loops pass an interim
// response on as the backend sent it, and put them on the answer.
var h3OwnFields = []string{"X-Content-Type-Options", "Alt-Svc", "X-Request-Id"}

// h3Ask asks for path over a connection of its own.
func h3Ask(t *testing.T, addr string, pki *caPKI, path string) (*h3Reply, error) {
	t.Helper()
	cc, conn := h3Client(t, addr, pki)
	defer conn.CloseWithError(0, "")
	var mu sync.Mutex
	var interim []h3Interim
	ctx := httptrace.WithClientTrace(testCtx(t), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			mu.Lock()
			interim = append(interim, h3Interim{code, http.Header(h).Clone()})
			mu.Unlock()
			return nil
		},
	})
	r, err := h3Do(ctx, cc, "GET", "https://localhost"+path, nil)
	if err != nil {
		return nil, err
	}
	mu.Lock()
	defer mu.Unlock()
	return &h3Reply{status: r.status, header: r.header, body: r.body, interim: interim}, nil
}

// A response head past what a loop parses itself, an interim response
// among them, reaches an HTTP/3 client from the loops as it does from the
// quic-go server: the same status, fields and body, with and without the
// site's header rules, and the same interim response but for the fields
// nvelox adds, which the loops put on the answer alone. A 204 is the one
// answer that differs: it has no Content-Length from the loops.
func TestH3Loops_BigResponseHead(t *testing.T) {
	quietLog(t)
	var many strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&many, "X-Field-%d: value %d\r\n", i, i)
	}
	long := strings.Repeat("v", 100<<10)
	const (
		ok    = "Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
		hints = "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n"
		hop   = "Keep-Alive: timeout=5\r\nConnection: X-Hop\r\nX-Hop: 1\r\n"
	)
	be := newScriptBackend(t, func(path string) (string, bool) {
		switch path {
		case "/many":
			return "HTTP/1.1 200 OK\r\n" + many.String() + ok, false
		case "/long":
			return "HTTP/1.1 200 OK\r\nX-Long: " + long + "\r\nContent-Length: 28\r\n\r\n<html><body>hi</body></html>", false
		case "/hints":
			return hints + "\r\nHTTP/1.1 200 OK\r\n" + ok, false
		case "/hints-many":
			return hints + many.String() + "\r\nHTTP/1.1 200 OK\r\n" + ok, false
		case "/hints-then-many":
			return hints + "\r\nHTTP/1.1 200 OK\r\n" + many.String() + ok, false
		case "/hints-hop":
			return hints + hop + "\r\nHTTP/1.1 200 OK\r\n" + ok, false
		case "/hints-many-hop":
			return hints + many.String() + hop + "\r\nHTTP/1.1 200 OK\r\n" + ok, false
		case "/no-content":
			return "HTTP/1.1 204 No Content\r\nX-Backend: b\r\n\r\n", false
		case "/many-no-content":
			return "HTTP/1.1 204 No Content\r\n" + many.String() + "\r\n", false
		}
		return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", false
	})
	paths := []string{"/many", "/long", "/hints", "/hints-many", "/hints-then-many", "/no-content", "/many-no-content"}
	// The hop-by-hop fields of an interim response: the quic-go server's
	// handler passes them on as they are (as net/http's ReverseProxy
	// does), the loops leave them out as for every response.
	loopsOnly := []string{"/hints-hop", "/hints-many-hop"}
	pki := newCAPKI(t, "h3-loops-ca")
	for _, rules := range []bool{false, true} {
		t.Run(map[bool]string{false: "a site without header rules", true: "a site with header rules"}[rules], func(t *testing.T) {
			got := map[bool]map[string]*h3Reply{}
			for _, loops := range []bool{false, true} {
				got[loops] = map[string]*h3Reply{}
				h3ServedBy(t, loops)
				l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", HTTP3: true,
					TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
				if rules {
					l.Headers = config.HeadersConfig{
						ResponseAdd:    map[string]string{"X-Resp-Add": "added by the site"},
						ResponseSet:    map[string]string{"X-Field-3": "set by the site"},
						ResponseRemove: []string{"X-Field-7"},
					}
				}
				addr := freeAddr(t)
				if g := startGroup(t, addr, fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})); (g.h3loops != nil) != loops {
					t.Fatalf("HTTP/3 on the loops: %v, want %v", g.h3loops != nil, loops)
				}
				ask := paths
				if loops {
					ask = append(append([]string(nil), paths...), loopsOnly...)
				}
				for _, p := range ask {
					a, err := h3Ask(t, addr, pki, p)
					if err != nil {
						t.Errorf("%s, HTTP/3 on the loops %v: %v", p, loops, err)
						continue
					}
					got[loops][p] = a
				}
			}
			for _, p := range paths {
				q, l := got[false][p], got[true][p]
				if q == nil || l == nil {
					continue // said above
				}
				if q.status != l.status || !bytes.Equal(q.body, l.body) {
					t.Errorf("%s: the quic-go server %d %q, the loops %d %q", p, q.status, trunc(string(q.body)), l.status, trunc(string(l.body)))
				}
				var but []string
				if q.status == http.StatusNoContent {
					// A 204 has no Content-Length (RFC 9110, section 8.6);
					// the quic-go server sends one of 0, the loops none.
					but = []string{"Content-Length"}
					if cl, has := l.header["Content-Length"]; has {
						t.Errorf("%s: a 204 from the loops with Content-Length %q", p, cl)
					}
				}
				if qf, lf := h3Fields(q.header, but...), h3Fields(l.header); qf != lf {
					t.Errorf("%s: the answer's fields differ:\n the quic-go server %s\n the loops          %s", p, trunc(qf), trunc(lf))
				}
				if qi, li := q.interims(h3OwnFields...), l.interims(); qi != li {
					t.Errorf("%s: the interim responses differ:\n the quic-go server %d: %s\n the loops          %d: %s", p, len(q.interim), trunc(qi), len(l.interim), trunc(li))
				}
			}
			// What the loops gave, by itself.
			lp := got[true]
			if a := lp["/many"]; a != nil {
				want3, want7 := "value 3", "value 7"
				if rules {
					want3, want7 = "set by the site", ""
				}
				if a.status != 200 || string(a.body) != "ok" || a.header.Get("X-Field-0") != "value 0" || a.header.Get("X-Field-299") != "value 299" ||
					a.header.Get("X-Field-3") != want3 || a.header.Get("X-Field-7") != want7 || (a.header.Get("X-Resp-Add") != "") != rules {
					t.Errorf("/many from the loops: status %d, body %q, fields %s", a.status, a.body, h3Fields(a.header))
				}
			}
			if a := lp["/long"]; a != nil && a.header.Get("X-Long") != long {
				t.Errorf("/long from the loops: a field of %d bytes, want the backend's %d", len(a.header.Get("X-Long")), len(long))
			}
			const link = `103 Link=["</a.css>; rel=preload"] | `
			for _, p := range []string{"/hints", "/hints-then-many", "/hints-hop"} {
				if a := lp[p]; a != nil && a.interims() != link {
					t.Errorf("%s from the loops: interim responses %q, want the backend's 103 with its Link alone", p, a.interims())
				}
			}
			for _, p := range []string{"/hints-many", "/hints-many-hop"} {
				a := lp[p]
				if a == nil {
					continue
				}
				if len(a.interim) != 1 || a.interim[0].status != http.StatusEarlyHints || len(a.interim[0].header) != 301 ||
					a.interim[0].header.Get("X-Field-299") != "value 299" || a.interim[0].header.Get("Link") == "" {
					t.Errorf("%s from the loops: interim responses %s, want one 103 with the backend's Link and 300 fields and no others", p, trunc(a.interims()))
				}
			}
			for _, p := range []string{"/hints", "/hints-many", "/hints-then-many", "/hints-hop", "/hints-many-hop"} {
				if a := lp[p]; a != nil && (a.status != 200 || string(a.body) != "ok" || a.header.Get("X-Content-Type-Options") != "nosniff" || a.header.Get("Alt-Svc") == "") {
					t.Errorf("%s from the loops: the answer after the hints: status %d, body %q, fields %s", p, a.status, a.body, trunc(h3Fields(a.header)))
				}
			}
		})
	}
}

// A backend's early hints are the client's as soon as the backend has sent
// them, while the answer does not exist yet.
func TestH3Loops_EarlyHintsArriveBeforeTheAnswer(t *testing.T) {
	answer := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(answer) }) }
	addr, _, pki := startH3Loops(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</a.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		<-answer
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "after the hints")
	})
	t.Cleanup(release) // before the backend is closed, which waits for its handler
	cc, _ := h3Client(t, addr, pki)
	hints := make(chan string, 4)
	ctx := httptrace.WithClientTrace(testCtx(t), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			hints <- fmt.Sprintf("%d %s", code, h3Fields(http.Header(h)))
			return nil
		},
	})
	type result struct {
		r   *h3Result
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := h3Do(ctx, cc, "GET", "https://localhost/hints", nil)
		done <- result{r, err}
	}()
	select {
	case got := <-hints:
		if want := `103 Link=["</a.css>; rel=preload"] `; got != want {
			t.Errorf("the hints: %q, want %q", got, want)
		}
	case res := <-done:
		t.Fatalf("an answer before the backend gave one: %+v, %v", res.r, res.err)
	case <-time.After(10 * time.Second):
		t.Fatal("no hints while the backend holds its answer back")
	}
	release()
	res := <-done
	if res.err != nil {
		t.Fatal(res.err)
	}
	if r := res.r; r.status != 200 || string(r.body) != "after the hints" || r.header.Get("X-Content-Type-Options") != "nosniff" || r.header.Get("Link") != "</a.css>; rel=preload" {
		t.Errorf("the answer after the hints: status %d, body %q, fields %s", r.status, r.body, h3Fields(r.header))
	}
	select {
	case more := <-hints:
		t.Errorf("a second interim response: %s", more)
	default:
	}
}

// The quic-go server, which serves HTTP/3 where there are no event loops,
// counts a head's bytes alone: 501 fields are passed on.
func TestHTTP3_QuicGoFieldCount(t *testing.T) {
	quietLog(t)
	h3ServedBy(t, false)
	pki := newCAPKI(t, "h3-loops-ca")
	l := &ListenerConfig{Name: "h3", Addr: ":0", Protocol: "https", HTTP3: true,
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
	addr := freeAddr(t)
	if g := startGroup(t, addr, fastTestSite(l, &config.Backend{Servers: []string{linesBackend(t)}})); g.h3loops != nil {
		t.Fatal("HTTP/3 is on the loops")
	}
	conn := rawH3(t, addr, pki)
	for _, n := range []int{500, 501} {
		status, body, err := rawExchange(t, conn, fieldsHead(n))
		if err != nil || status != "200" || !strings.HasPrefix(string(body), "a request of ") {
			t.Errorf("a head of %d fields: status %q, body %q, err %v; want 200", n, status, trunc(string(body)), err)
		}
	}
}

// linesBackend is a backend that takes any number of header lines (Go's
// own server refuses the 501st by itself) and answers with their count.
func linesBackend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					lines := 0
					for {
						line, err := br.ReadString('\n')
						if err != nil {
							return
						}
						if line == "\r\n" {
							break
						}
						lines++
					}
					body := fmt.Sprintf("a request of %d lines", lines)
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// fieldsHead is the HEADERS frame of a GET with n fields in all.
func fieldsHead(n int) []byte {
	fields := append([]string{}, h3GetFields...)
	for i := len(fields) / 2; i < n; i++ {
		fields = append(fields, fmt.Sprintf("x-f-%03d", i), "v")
	}
	return h3HeadersFrame(fields...)
}
