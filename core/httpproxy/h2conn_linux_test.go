//go:build linux

package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"nvelox/config"
	"nvelox/core/logging"
)

// h2Client is a test client that speaks HTTP/2 frame by frame (with
// golang.org/x/net's framer and HPACK), so that a test decides every byte a
// request is made of and sees every frame of the answer.
type h2Client struct {
	t    *testing.T
	c    *tls.Conn
	fr   *http2.Framer
	enc  *hpack.Encoder
	hbuf bytes.Buffer
	next uint32

	// What the server said about itself and the connection.
	settings map[http2.SettingID]uint32
	goAway   *http2.GoAwayFrame
	acks     int
	closed   bool // the server closed the connection
	// autoWindow: DATA frames are answered with their credit at once.
	autoWindow bool
	resp       map[uint32]*h2Response
	// The server's windows for what this client sends, and the updates it
	// sent.
	connWin   int64
	streamWin map[uint32]int64
	updates   int
}

// h2Response is what one stream brought.
type h2Response struct {
	interim []http.Header
	status  int
	header  http.Header
	body    []byte
	trailer http.Header
	ended   bool          // END_STREAM
	reset   bool          // RST_STREAM
	code    http2.ErrCode // of that reset
	frames  []string      // the frame types, in order
}

// h2DialRcvBuf, when set, is the size of the socket receive buffer of the
// connections dialH2 opens: a client with a small one stops the server's
// writes soon after it stops reading, whatever the machine's TCP buffers.
var h2DialRcvBuf int

// dialH2 connects, sends the client's preface and settings (extra: more
// settings), and reads the server's.
func dialH2(t *testing.T, addr string, extra ...http2.Setting) *h2Client {
	t.Helper()
	d := &net.Dialer{}
	if n := h2DialRcvBuf; n > 0 {
		d.Control = func(_, _ string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, n) })
		}
	}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true, ServerName: "example.test", NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if p := c.ConnectionState().NegotiatedProtocol; p != "h2" {
		t.Fatalf("negotiated %q, want h2", p)
	}
	hc := &h2Client{t: t, c: c, next: 1, autoWindow: true, settings: map[http2.SettingID]uint32{}, resp: map[uint32]*h2Response{},
		connWin: 65535, streamWin: map[uint32]int64{}}
	hc.fr = http2.NewFramer(c, c)
	hc.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	hc.fr.MaxHeaderListSize = 16 << 20
	hc.enc = hpack.NewEncoder(&hc.hbuf)
	c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := io.WriteString(c, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	if err := hc.fr.WriteSettings(extra...); err != nil {
		t.Fatal(err)
	}
	// The server's SETTINGS and its acknowledgement of ours.
	for len(hc.settings) == 0 || hc.acks == 0 {
		if !hc.readFrame() {
			t.Fatalf("connection ended before the server's settings")
		}
	}
	return hc
}

// block encodes a header block.
func (hc *h2Client) block(fields [][2]string) []byte {
	hc.hbuf.Reset()
	for _, f := range fields {
		if err := hc.enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}); err != nil {
			hc.t.Fatal(err)
		}
	}
	return append([]byte(nil), hc.hbuf.Bytes()...)
}

// get builds the fields of a request without a body.
func h2Fields(method, path string, extra ...[2]string) [][2]string {
	return append([][2]string{{":method", method}, {":scheme", "https"}, {":authority", "example.test"}, {":path", path}}, extra...)
}

// start sends a request's HEADERS frame on a new stream.
func (hc *h2Client) start(fields [][2]string, endStream bool) uint32 {
	hc.t.Helper()
	id := hc.next
	hc.next += 2
	// In frames of at most the size every server takes.
	b := hc.block(fields)
	first := b[:min(len(b), 16384)]
	b = b[len(first):]
	if err := hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: first, EndStream: endStream, EndHeaders: len(b) == 0}); err != nil {
		hc.t.Fatal(err)
	}
	for len(b) > 0 {
		next := b[:min(len(b), 16384)]
		b = b[len(next):]
		if err := hc.fr.WriteContinuation(id, len(b) == 0, next); err != nil {
			return id // the server gave the connection up in the middle of the block
		}
	}
	return id
}

// data sends body bytes in frames of at most 16 KiB.
func (hc *h2Client) data(id uint32, p []byte, endStream bool) {
	hc.t.Helper()
	for {
		n := min(len(p), 16384)
		last := n == len(p)
		if err := hc.fr.WriteData(id, endStream && last, p[:n]); err != nil {
			hc.t.Fatal(err)
		}
		p = p[n:]
		if last {
			return
		}
	}
}

func (hc *h2Client) stream(id uint32) *h2Response {
	r := hc.resp[id]
	if r == nil {
		r = &h2Response{}
		hc.resp[id] = r
	}
	return r
}

// readFrame reads one frame and records it; false when the connection
// ended.
func (hc *h2Client) readFrame() bool {
	f, err := hc.fr.ReadFrame()
	if err != nil {
		hc.closed = true
		return false
	}
	hc.record(f)
	return true
}

// record notes what a frame of the server says.
func (hc *h2Client) record(f http2.Frame) {
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if f.IsAck() {
			hc.acks++
			break
		}
		f.ForeachSetting(func(s http2.Setting) error { hc.settings[s.ID] = s.Val; return nil })
		if len(hc.settings) == 0 {
			hc.settings[0] = 0
		}
		hc.fr.WriteSettingsAck()
	case *http2.PingFrame:
		if !f.IsAck() {
			hc.fr.WritePing(true, f.Data)
		}
	case *http2.GoAwayFrame:
		hc.goAway = f
	case *http2.MetaHeadersFrame:
		r := hc.stream(f.StreamID)
		r.frames = append(r.frames, "HEADERS")
		h := http.Header{}
		status := 0
		for _, hf := range f.Fields {
			if hf.Name == ":status" {
				fmt.Sscan(hf.Value, &status)
				continue
			}
			h[hf.Name] = append(h[hf.Name], hf.Value)
		}
		switch {
		case r.header != nil:
			r.trailer = h
		case status >= 100 && status < 200:
			r.interim = append(r.interim, h)
		default:
			r.status, r.header = status, h
		}
		if f.StreamEnded() {
			r.ended = true
		}
	case *http2.DataFrame:
		r := hc.stream(f.StreamID)
		r.frames = append(r.frames, "DATA")
		r.body = append(r.body, f.Data()...)
		if f.StreamEnded() {
			r.ended = true
		}
		if n := uint32(f.Length); n > 0 && hc.autoWindow {
			hc.fr.WriteWindowUpdate(0, n)
			if !f.StreamEnded() {
				hc.fr.WriteWindowUpdate(f.StreamID, n)
			}
		}
	case *http2.RSTStreamFrame:
		r := hc.stream(f.StreamID)
		r.frames = append(r.frames, "RST_STREAM")
		r.reset, r.code = true, f.ErrCode
	case *http2.WindowUpdateFrame:
		hc.updates++
		if f.StreamID == 0 {
			hc.connWin += int64(f.Increment)
		} else {
			hc.streamWin[f.StreamID] += int64(f.Increment)
		}
	}
}

// upload sends a request body within the server's windows, reading the
// server's frames while it has to wait for credit.
func (hc *h2Client) upload(id uint32, p []byte) {
	hc.t.Helper()
	initial := int64(65535)
	if v, ok := hc.settings[http2.SettingInitialWindowSize]; ok {
		initial = int64(v)
	}
	for len(p) > 0 {
		win := min(hc.connWin, initial+hc.streamWin[id])
		if win <= 0 {
			if r := hc.resp[id]; r != nil && (r.ended || r.reset) {
				return // answered before the body was out
			}
			if !hc.readFrame() {
				hc.t.Fatalf("connection ended in the middle of an upload")
			}
			continue
		}
		n := int(min(int64(len(p)), win, 16384))
		if err := hc.fr.WriteData(id, n == len(p), p[:n]); err != nil {
			hc.t.Fatal(err)
		}
		p = p[n:]
		hc.connWin -= int64(n)
		hc.streamWin[id] -= int64(n)
	}
}

// wait reads until every one of the streams ended or was reset.
func (hc *h2Client) wait(ids ...uint32) {
	hc.t.Helper()
	for {
		done := true
		for _, id := range ids {
			if r := hc.resp[id]; r == nil || !(r.ended || r.reset) {
				done = false
			}
		}
		if done {
			return
		}
		if !hc.readFrame() {
			hc.t.Fatalf("connection ended while waiting for streams %v (GOAWAY: %+v)", ids, hc.goAway)
		}
	}
}

// bodyOf waits until stream id has brought at least n body bytes, then for
// whatever else the server had already sent, and returns how many it
// brought.
func (hc *h2Client) bodyOf(id uint32, n int) int {
	hc.t.Helper()
	for len(hc.stream(id).body) < n {
		if !hc.readFrame() {
			hc.t.Fatalf("connection ended with %d of %d body bytes of stream %d", len(hc.stream(id).body), n, id)
		}
	}
	hc.settle()
	return len(hc.stream(id).body)
}

// do sends a request (with a body when body is not nil) and returns its
// response.
func (hc *h2Client) do(fields [][2]string, body []byte) *h2Response {
	hc.t.Helper()
	id := hc.start(fields, body == nil)
	if body != nil {
		hc.data(id, body, true)
	}
	hc.wait(id)
	return hc.resp[id]
}

type h2Case struct {
	name   string
	fields [][2]string
	body   []byte
}

func h2Cases() []h2Case {
	big := bytes.Repeat([]byte("0123456789abcdef"), 300<<10/16)
	post := func(path string, n int, extra ...[2]string) [][2]string {
		return append([][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", path},
			{"content-length", fmt.Sprint(n)}, {"content-type", "application/octet-stream"}}, extra...)
	}
	return []h2Case{
		{"plain", h2Fields("GET", "/ok"), nil},
		{"query", h2Fields("GET", "/q?a=1&b=%20x&c"), nil},
		{"empty query", h2Fields("GET", "/q?"), nil},
		{"encoded path", h2Fields("GET", "/a%2Fb/c%20d"), nil},
		{"dot segments", h2Fields("GET", "/a/./b/../c"), nil},
		{"double slash", h2Fields("GET", "//admin//x"), nil},
		{"sub-delims", h2Fields("GET", "/a!b$c&d'e(f)g*h+i,j;k=l:m@n"), nil},
		{"head", h2Fields("HEAD", "/ok"), nil},
		{"delete", h2Fields("DELETE", "/ok"), nil},
		{"options", h2Fields("OPTIONS", "/ok"), nil},
		{"custom method", h2Fields("PURGE", "/ok"), nil},
		{"chunked", h2Fields("GET", "/chunked"), nil},
		{"trailer", h2Fields("GET", "/trailer", [2]string{"te", "trailers"}), nil},
		{"close delimited", h2Fields("GET", "/close"), nil},
		{"sniff", h2Fields("GET", "/sniff"), nil},
		{"no sniff with encoding", h2Fields("GET", "/sniff-gz"), nil},
		{"304", h2Fields("GET", "/304"), nil},
		{"204", h2Fields("GET", "/204"), nil},
		{"103", h2Fields("GET", "/103"), nil},
		{"hop by hop", h2Fields("GET", "/hop"), nil},
		{"big", h2Fields("GET", "/big"), nil},
		{"big chunked", h2Fields("GET", "/bigchunked"), nil},
		{"backend headers", h2Fields("GET", "/headers"), nil},
		{"502 passthrough", h2Fields("GET", "/502"), nil},
		{"101 refused", h2Fields("GET", "/101"), nil},
		{"malformed backend", h2Fields("GET", "/malformed"), nil},
		{"backend reset", h2Fields("GET", "/reset"), nil},
		{"http/1.0 backend", h2Fields("GET", "/http10"), nil},
		{"empty body", h2Fields("GET", "/empty"), nil},
		{"head of empty", h2Fields("HEAD", "/empty"), nil},
		{"forged forwarding", h2Fields("GET", "/ok", [2]string{"x-forwarded-for", "1.2.3.4"}, [2]string{"x-real-ip", "1.2.3.4"},
			[2]string{"x-forwarded-proto", "http"}, [2]string{"forwarded", "for=1.2.3.4"}, [2]string{"x-forwarded-host", "evil"},
			[2]string{"true-client-ip", "1.2.3.4"}, [2]string{"cf-connecting-ip", "1.2.3.4"}), nil},
		{"user agents", h2Fields("GET", "/ok", [2]string{"user-agent", "first"}, [2]string{"user-agent", "second"}), nil},
		{"cookie crumbs", h2Fields("GET", "/ok", [2]string{"cookie", "a=1"}, [2]string{"accept", "*/*"}, [2]string{"cookie", "b=2"}, [2]string{"cookie", "c=3"}), nil},
		{"one cookie", h2Fields("GET", "/ok", [2]string{"cookie", "a=1; b=2"}), nil},
		{"many fields", h2Fields("GET", "/ok", [2]string{"accept", "text/html"}, [2]string{"accept-language", "en"}, [2]string{"accept-encoding", "gzip, br"},
			[2]string{"x-custom-header", "v"}, [2]string{"authorization", "Bearer x"}, [2]string{"etag", "\"e\""}, [2]string{"www-authenticate", "x"}), nil},
		{"obs-text value", h2Fields("GET", "/ok", [2]string{"x-utf8", "caf\xc3\xa9"}), nil},
		{"cl zero get", h2Fields("GET", "/ok", [2]string{"content-length", "0"}), nil},
		{"idempotency", [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/ok"}, {"content-length", "0"}, {"idempotency-key", "k"}}, nil},
		{"post without a body", [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/ok"}}, nil},
		{"post", post("/post", 11), []byte("hello world")},
		{"post big", post("/postbig", len(big)), big},
		{"put", [][2]string{{":method", "PUT"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/put"}, {"content-length", "3"}}, []byte("abc")},
		{"host field", [][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/ok"}, {"host", "example.test"}}, nil},
		{"http scheme", [][2]string{{":method", "GET"}, {":scheme", "http"}, {":authority", "example.test"}, {":path", "/ok"}}, nil},
	}
}

// h2Run sends the cases, each on its own connection, to a TLS bind group
// served by the event loops (fast) or by net/http.
func h2Run(t *testing.T, be *rawBackend, fast bool, cases []h2Case) (map[string]*h2Response, map[string]*http.Request) {
	t.Helper()
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, fast)
	resps := map[string]*h2Response{}
	reqs := map[string]*http.Request{}
	for _, c := range cases {
		before := be.count()
		hc := dialH2(t, addr)
		resps[c.name] = hc.do(c.fields, c.body)
		hc.c.Close()
		if be.count() > before {
			reqs[c.name] = be.last()
		}
	}
	return resps, reqs
}

func sortedHeader(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		if k != "date" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%q ", k, h[k])
	}
	return b.String()
}

// TestH2_MatchesNetHTTP sends the same HTTP/2 requests to the event loops
// and to net/http's HTTP/2 server and compares what the client gets and
// what the backend gets.
func TestH2_MatchesNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	cases := h2Cases()
	slowResps, slowReqs := h2Run(t, be, false, cases)
	fastResps, fastReqs := h2Run(t, be, true, cases)
	for _, c := range cases {
		s, f := slowResps[c.name], fastResps[c.name]
		if s.reset != f.reset || s.code != f.code {
			t.Errorf("%s: reset: net/http %v (%v), loops %v (%v)", c.name, s.reset, s.code, f.reset, f.code)
			continue
		}
		if s.status != f.status {
			t.Errorf("%s: status: net/http %d, loops %d", c.name, s.status, f.status)
			continue
		}
		if !bytes.Equal(s.body, f.body) {
			t.Errorf("%s: body differs:\n net/http %q\n loops    %q", c.name, trunc(string(s.body)), trunc(string(f.body)))
		}
		if sh, fh := sortedHeader(s.header), sortedHeader(f.header); sh != fh {
			t.Errorf("%s: headers differ:\n net/http %s\n loops    %s", c.name, sh, fh)
		}
		if st, ft := sortedHeader(s.trailer), sortedHeader(f.trailer); st != ft {
			t.Errorf("%s: trailers differ:\n net/http %s\n loops    %s", c.name, st, ft)
		}
		if len(s.interim) != len(f.interim) {
			t.Errorf("%s: interim responses: net/http %d, loops %d", c.name, len(s.interim), len(f.interim))
		}
		if s.ended != f.ended {
			t.Errorf("%s: END_STREAM: net/http %v, loops %v", c.name, s.ended, f.ended)
		}
		sr, fr := slowReqs[c.name], fastReqs[c.name]
		if (sr == nil) != (fr == nil) {
			t.Errorf("%s: backend saw the request: net/http %v, loops %v", c.name, sr != nil, fr != nil)
			continue
		}
		if sr == nil {
			continue
		}
		if sr.Method != fr.Method || sr.RequestURI != fr.RequestURI || sr.Host != fr.Host || sr.Proto != fr.Proto {
			t.Errorf("%s: backend request line differs: net/http %s %s %s host %s, loops %s %s %s host %s", c.name,
				sr.Method, sr.RequestURI, sr.Proto, sr.Host, fr.Method, fr.RequestURI, fr.Proto, fr.Host)
		}
		if !reflect.DeepEqual(sr.Header, fr.Header) {
			t.Errorf("%s: backend headers differ:\n net/http %v\n loops    %v", c.name, sr.Header, fr.Header)
		}
		if !reflect.DeepEqual(sr.TransferEncoding, fr.TransferEncoding) || sr.ContentLength != fr.ContentLength {
			t.Errorf("%s: backend framing differs: net/http %v/%d, loops %v/%d", c.name, sr.TransferEncoding, sr.ContentLength, fr.TransferEncoding, fr.ContentLength)
		}
	}
}

// TestH2_ManyStreams: a hundred requests at once on one connection.
func TestH2_ManyStreams(t *testing.T) {
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	hc := dialH2(t, addr)
	var ids []uint32
	for i := 0; i < 100; i++ {
		ids = append(ids, hc.start(h2Fields("GET", fmt.Sprintf("/n%d", i)), true))
	}
	hc.wait(ids...)
	for i, id := range ids {
		r := hc.resp[id]
		if want := fmt.Sprintf("hello GET /n%d", i); r.status != 200 || string(r.body) != want {
			t.Errorf("stream %d: %d %q, want 200 %q", id, r.status, r.body, want)
		}
	}
	// And the connection goes on.
	if r := hc.do(h2Fields("GET", "/after"), nil); r.status != 200 || string(r.body) != "hello GET /after" {
		t.Errorf("after: %d %q", r.status, r.body)
	}
}

// settle sends a PING and reads until its answer, a GOAWAY or the end of
// the connection: everything the server had to say about the frames sent
// before is then in. It returns that as text: every stream's status or
// reset, then the GOAWAY's code.
func (hc *h2Client) settle() string {
	hc.t.Helper()
	ping := [8]byte{'s', 'e', 't', 't', 'l', 'e', byte(hc.next), byte(len(hc.resp))}
	hc.fr.WritePing(false, ping)
	for hc.goAway == nil {
		f, err := hc.fr.ReadFrame()
		if err != nil {
			hc.closed = true
			break
		}
		if p, ok := f.(*http2.PingFrame); ok && p.IsAck() && p.Data == ping {
			break
		}
		hc.record(f)
	}
	var ids []int
	for id := range hc.resp {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	var b strings.Builder
	for _, id := range ids {
		r := hc.resp[uint32(id)]
		switch {
		case r.reset:
			fmt.Fprintf(&b, "%d:RST(%v) ", id, r.code)
		case r.header != nil:
			fmt.Fprintf(&b, "%d:%d ", id, r.status)
		}
	}
	switch {
	case hc.goAway != nil:
		fmt.Fprintf(&b, "GOAWAY(%v)", hc.goAway.ErrCode)
	case hc.closed:
		b.WriteString("closed")
	default:
		b.WriteString("open")
	}
	return b.String()
}

// TestH2_ProtocolErrorsMatchNetHTTP sends frames that break a rule of
// HTTP/2 to the event loops and to net/http's HTTP/2 server: both answer
// with the same resets and the same GOAWAY.
func TestH2_ProtocolErrorsMatchNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	get := h2Fields("GET", "/ok")
	raw := func(hc *h2Client, typ http2.FrameType, flags http2.Flags, id uint32, payload []byte) {
		if err := hc.fr.WriteRawFrame(typ, flags, id, payload); err != nil {
			hc.t.Fatal(err)
		}
	}
	u32 := func(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }
	setting := func(id http2.SettingID, v uint32) []byte { return append([]byte{byte(id >> 8), byte(id)}, u32(v)...) }
	// open starts a request that stays open (its body never ends).
	open := func(hc *h2Client) uint32 {
		return hc.start([][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/post"}, {"content-length", "10"}}, false)
	}
	cases := []struct {
		name string
		do   func(hc *h2Client)
	}{
		{"a request, then nothing wrong", func(hc *h2Client) { hc.wait(hc.start(get, true)) }},
		{"DATA on a stream never opened", func(hc *h2Client) { hc.fr.WriteData(1, true, []byte("x")) }},
		{"DATA on stream 0", func(hc *h2Client) { raw(hc, http2.FrameData, 0, 0, []byte("x")) }},
		{"HEADERS on an even stream", func(hc *h2Client) {
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 2, BlockFragment: hc.block(get), EndStream: true, EndHeaders: true})
		}},
		{"HEADERS on stream 0", func(hc *h2Client) { raw(hc, http2.FrameHeaders, http2.FlagHeadersEndHeaders, 0, hc.block(get)) }},
		{"stream ids going down", func(hc *h2Client) {
			hc.next = 5
			hc.wait(hc.start(get, true))
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, BlockFragment: hc.block(get), EndStream: true, EndHeaders: true})
		}},
		{"a closed stream opened again", func(hc *h2Client) {
			hc.wait(hc.start(get, true))
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hc.block(get), EndStream: true, EndHeaders: true})
		}},
		{"WINDOW_UPDATE of 0 on the connection", func(hc *h2Client) { raw(hc, http2.FrameWindowUpdate, 0, 0, u32(0)) }},
		{"WINDOW_UPDATE of 0 on a stream", func(hc *h2Client) { raw(hc, http2.FrameWindowUpdate, 0, open(hc), u32(0)) }},
		{"WINDOW_UPDATE past the largest window, connection", func(hc *h2Client) { raw(hc, http2.FrameWindowUpdate, 0, 0, u32(1<<31-1)) }},
		{"WINDOW_UPDATE past the largest window, stream", func(hc *h2Client) { raw(hc, http2.FrameWindowUpdate, 0, open(hc), u32(1<<31-1)) }},
		{"WINDOW_UPDATE on a stream never opened", func(hc *h2Client) { raw(hc, http2.FrameWindowUpdate, 0, 9, u32(5)) }},
		{"WINDOW_UPDATE on a closed stream", func(hc *h2Client) {
			id := hc.start(get, true)
			hc.wait(id)
			raw(hc, http2.FrameWindowUpdate, 0, id, u32(5))
		}},
		{"WINDOW_UPDATE of 3 bytes", func(hc *h2Client) { raw(hc, http2.FrameWindowUpdate, 0, 0, []byte{0, 0, 1}) }},
		{"RST_STREAM on a stream never opened", func(hc *h2Client) { hc.fr.WriteRSTStream(7, http2.ErrCodeCancel) }},
		{"RST_STREAM on stream 0", func(hc *h2Client) { raw(hc, http2.FrameRSTStream, 0, 0, u32(8)) }},
		{"RST_STREAM of 5 bytes", func(hc *h2Client) { raw(hc, http2.FrameRSTStream, 0, open(hc), []byte{0, 0, 0, 8, 0}) }},
		{"RST_STREAM on a closed stream", func(hc *h2Client) {
			id := hc.start(get, true)
			hc.wait(id)
			hc.fr.WriteRSTStream(id, http2.ErrCodeCancel)
		}},
		{"PING on a stream", func(hc *h2Client) { raw(hc, http2.FramePing, 0, 1, make([]byte, 8)) }},
		{"PING of 7 bytes", func(hc *h2Client) { raw(hc, http2.FramePing, 0, 0, make([]byte, 7)) }},
		{"SETTINGS acknowledgement with a payload", func(hc *h2Client) { raw(hc, http2.FrameSettings, http2.FlagSettingsAck, 0, setting(1, 1)) }},
		{"SETTINGS of 5 bytes", func(hc *h2Client) { raw(hc, http2.FrameSettings, 0, 0, make([]byte, 5)) }},
		{"SETTINGS on a stream", func(hc *h2Client) { raw(hc, http2.FrameSettings, 0, 1, nil) }},
		{"SETTINGS: ENABLE_PUSH 2", func(hc *h2Client) { raw(hc, http2.FrameSettings, 0, 0, setting(http2.SettingEnablePush, 2)) }},
		{"SETTINGS: a window of 2^31", func(hc *h2Client) { raw(hc, http2.FrameSettings, 0, 0, setting(http2.SettingInitialWindowSize, 1<<31)) }},
		{"SETTINGS: a frame size of 100", func(hc *h2Client) { raw(hc, http2.FrameSettings, 0, 0, setting(http2.SettingMaxFrameSize, 100)) }},
		{"SETTINGS: a frame size of 2^24", func(hc *h2Client) { raw(hc, http2.FrameSettings, 0, 0, setting(http2.SettingMaxFrameSize, 1<<24)) }},
		{"SETTINGS: one parameter twice", func(hc *h2Client) {
			raw(hc, http2.FrameSettings, 0, 0, append(setting(http2.SettingMaxConcurrentStreams, 5), setting(http2.SettingMaxConcurrentStreams, 6)...))
		}},
		{"SETTINGS: an unknown parameter", func(hc *h2Client) { raw(hc, http2.FrameSettings, 0, 0, setting(0x99, 6)) }},
		{"SETTINGS: 101 parameters", func(hc *h2Client) {
			var p []byte
			for i := 0; i < 101; i++ {
				p = append(p, setting(http2.SettingID(0x100+i), 1)...)
			}
			raw(hc, http2.FrameSettings, 0, 0, p)
		}},
		{"an acknowledgement of no SETTINGS", func(hc *h2Client) { hc.fr.WriteSettingsAck() }},
		{"CONTINUATION with no HEADERS before it", func(hc *h2Client) { hc.fr.WriteContinuation(1, true, hc.block(get)) }},
		{"HEADERS without END_HEADERS, then DATA", func(hc *h2Client) {
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hc.block(get), EndStream: false, EndHeaders: false})
			hc.fr.WriteData(1, true, []byte("x"))
		}},
		{"HEADERS without END_HEADERS, then CONTINUATION of another stream", func(hc *h2Client) {
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hc.block(get), EndStream: true, EndHeaders: false})
			hc.fr.WriteContinuation(3, true, nil)
		}},
		{"a header block in three frames", func(hc *h2Client) {
			b := hc.block(h2Fields("GET", "/ok", [2]string{"x-a", strings.Repeat("a", 300)}))
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: b[:10], EndStream: true, EndHeaders: false})
			hc.fr.WriteContinuation(1, false, b[10:200])
			hc.fr.WriteContinuation(1, true, b[200:])
			hc.next = 3
			hc.wait(1)
		}},
		{"PUSH_PROMISE", func(hc *h2Client) {
			raw(hc, http2.FramePushPromise, http2.FlagPushPromiseEndHeaders, 1, append(u32(2), hc.block(get)...))
		}},
		{"PRIORITY of 4 bytes", func(hc *h2Client) { raw(hc, http2.FramePriority, 0, 1, make([]byte, 4)) }},
		{"PRIORITY on stream 0", func(hc *h2Client) { raw(hc, http2.FramePriority, 0, 0, make([]byte, 5)) }},
		{"PRIORITY: a stream that depends on itself", func(hc *h2Client) { raw(hc, http2.FramePriority, 0, 3, append(u32(3), 16)) }},
		{"PRIORITY for a stream never opened", func(hc *h2Client) { raw(hc, http2.FramePriority, 0, 3, append(u32(1), 16)) }},
		{"HEADERS: a stream that depends on itself", func(hc *h2Client) {
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hc.block(get), EndStream: true, EndHeaders: true,
				Priority: http2.PriorityParam{StreamDep: 1, Weight: 5}})
		}},
		{"HEADERS with a priority and padding", func(hc *h2Client) {
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hc.block(get), EndStream: true, EndHeaders: true,
				PadLength: 7, Priority: http2.PriorityParam{StreamDep: 0, Weight: 5, Exclusive: true}})
			hc.next = 3
			hc.wait(1)
		}},
		{"a field name in upper case", func(hc *h2Client) { hc.start(h2Fields("GET", "/ok", [2]string{"X-Upper", "v"}), true) }},
		{"a field name with a space", func(hc *h2Client) { hc.start(h2Fields("GET", "/ok", [2]string{"x bad", "v"}), true) }},
		{"an empty field name", func(hc *h2Client) { hc.start(h2Fields("GET", "/ok", [2]string{"", "v"}), true) }},
		{"a value with a control byte", func(hc *h2Client) { hc.start(h2Fields("GET", "/ok", [2]string{"x-a", "a\x01b"}), true) }},
		{"a value with a line feed", func(hc *h2Client) { hc.start(h2Fields("GET", "/ok", [2]string{"x-a", "a\nb"}), true) }},
		{"a pseudo-header after a field", func(hc *h2Client) {
			hc.start([][2]string{{":method", "GET"}, {":scheme", "https"}, {"x-a", "b"}, {":authority", "example.test"}, {":path", "/ok"}}, true)
		}},
		{"an unknown pseudo-header", func(hc *h2Client) { hc.start(h2Fields("GET", "/ok", [2]string{":wat", "v"}), true) }},
		{"a pseudo-header that is not a request's", func(hc *h2Client) {
			hc.start([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/ok"}, {":status", "200"}}, true)
		}},
		{"one pseudo-header twice", func(hc *h2Client) {
			hc.start([][2]string{{":method", "GET"}, {":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/ok"}}, true)
		}},
		{"a header block that cannot be decoded", func(hc *h2Client) {
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: []byte{0xff, 0xff, 0xff, 0x7f}, EndStream: true, EndHeaders: true})
		}},
		{"a header block cut in the middle of a field", func(hc *h2Client) {
			b := hc.block(get)
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: b[:len(b)-3], EndStream: true, EndHeaders: true})
		}},
		{"DATA after the request ended", func(hc *h2Client) {
			id := hc.start(get, true)
			hc.fr.WriteData(id, true, []byte("x"))
			hc.wait(id)
		}},
		{"DATA on a closed stream", func(hc *h2Client) {
			id := hc.start(get, true)
			hc.wait(id)
			hc.fr.WriteData(id, true, []byte("x"))
		}},
		{"more DATA than the Content-Length", func(hc *h2Client) {
			id := open(hc)
			hc.fr.WriteData(id, true, []byte("0123456789ab"))
		}},
		{"less DATA than the Content-Length", func(hc *h2Client) {
			id := open(hc)
			hc.fr.WriteData(id, true, []byte("0123"))
			hc.wait(id)
		}},
		{"DATA with more padding than payload", func(hc *h2Client) {
			id := open(hc)
			raw(hc, http2.FrameData, http2.FlagDataPadded, id, []byte{9, 'a', 'b'})
		}},
		{"padded DATA", func(hc *h2Client) {
			id := open(hc)
			hc.fr.WriteDataPadded(id, false, []byte("01234"), make([]byte, 20))
			hc.fr.WriteDataPadded(id, true, []byte("56789"), make([]byte, 3))
			hc.wait(id)
		}},
		{"trailers", func(hc *h2Client) {
			id := open(hc)
			hc.fr.WriteData(id, false, []byte("0123456789"))
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hc.block([][2]string{{"x-sum", "1"}}), EndStream: true, EndHeaders: true})
			hc.wait(id)
		}},
		{"trailers without END_STREAM", func(hc *h2Client) {
			id := open(hc)
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hc.block([][2]string{{"x-sum", "1"}}), EndStream: false, EndHeaders: true})
		}},
		{"trailers with a pseudo-header", func(hc *h2Client) {
			id := open(hc)
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hc.block([][2]string{{":path", "/x"}}), EndStream: true, EndHeaders: true})
		}},
		{"HEADERS after the request ended", func(hc *h2Client) {
			id := hc.start(h2Fields("GET", "/sleep/300ms"), true)
			hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hc.block([][2]string{{"x-sum", "1"}}), EndStream: true, EndHeaders: true})
		}},
		{"a frame of an unknown type", func(hc *h2Client) {
			raw(hc, http2.FrameType(0x42), 0x5, 0, []byte("whatever"))
			raw(hc, http2.FrameType(0x42), 0x5, 9, []byte("whatever"))
			hc.wait(hc.start(get, true))
		}},
		{"the client's GOAWAY", func(hc *h2Client) {
			hc.wait(hc.start(get, true))
			hc.fr.WriteGoAway(0, http2.ErrCodeNo, nil)
		}},
		{"a reset, then the stream's frames", func(hc *h2Client) {
			id := open(hc)
			hc.fr.WriteRSTStream(id, http2.ErrCodeCancel)
			hc.fr.WriteData(id, true, []byte("0123456789"))
		}},
	}
	run := func(fast bool) map[string]string {
		s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
		addr := startTLSGroup(t, s, fast)
		out := map[string]string{}
		for _, c := range cases {
			hc := dialH2(t, addr)
			c.do(hc)
			out[c.name] = hc.settle()
			hc.c.Close()
		}
		return out
	}
	slow, fast := run(false), run(true)
	for _, c := range cases {
		if slow[c.name] != fast[c.name] {
			t.Errorf("%s:\n net/http %s\n loops    %s", c.name, slow[c.name], fast[c.name])
		} else {
			t.Logf("%s: %s", c.name, fast[c.name])
		}
	}

	// Where the loops differ from Go's server, on purpose.
	own := []struct {
		name string
		do   func(hc *h2Client)
		want string
	}{
		// Go detects this the next time the stream's window is used; RFC
		// 9113 6.9.2 makes it an error of the SETTINGS frame.
		{"SETTINGS: a window that pushes a stream's past the largest", func(hc *h2Client) {
			id := open(hc)
			raw(hc, http2.FrameWindowUpdate, 0, id, u32(1<<30))
			raw(hc, http2.FrameSettings, 0, 0, setting(http2.SettingInitialWindowSize, 1<<31-1))
		}, "GOAWAY(FLOW_CONTROL_ERROR)"},
		// Go resets the stream and goes on with a header table that missed
		// the block; RFC 9113 6.2 ends the connection.
		{"HEADERS with more padding than payload", func(hc *h2Client) {
			raw(hc, http2.FrameHeaders, http2.FlagHeadersEndHeaders|http2.FlagHeadersEndStream|http2.FlagHeadersPadded, 1, []byte{200, 0x82})
		}, "GOAWAY(PROTOCOL_ERROR)"},
		// The loops announce the protocol's default frame size; Go
		// announces 1 MiB.
		{"a frame larger than the announced size", func(hc *h2Client) {
			id := open(hc)
			raw(hc, http2.FrameData, 0, id, make([]byte, 16385))
		}, "GOAWAY(FRAME_SIZE_ERROR)"},
	}
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	for _, c := range own {
		hc := dialH2(t, addr)
		c.do(hc)
		if got := hc.settle(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		hc.c.Close()
	}
}

// TestH2_ResponseFlowControl: a response body goes out only as far as the
// client's windows allow, and goes on when they open.
func TestH2_ResponseFlowControl(t *testing.T) {
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	want := strings.Repeat("0123456789abcdef", 200<<10/16)

	t.Run("stream window", func(t *testing.T) {
		hc := dialH2(t, addr, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1000})
		hc.autoWindow = false
		id := hc.start(h2Fields("GET", "/big"), true)
		if n := hc.bodyOf(id, 1000); n != 1000 || hc.resp[id].status != 200 {
			t.Fatalf("with a window of 1000: %d bytes, status %d", n, hc.resp[id].status)
		}
		hc.fr.WriteWindowUpdate(id, 5000)
		if n := hc.bodyOf(id, 6000); n != 6000 {
			t.Fatalf("after 5000 more: %d bytes", n)
		}
		// A SETTINGS change moves the window of the open stream too.
		hc.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 11000})
		if n := hc.bodyOf(id, 16000); n != 16000 {
			t.Fatalf("after the window setting grew by 10000: %d bytes", n)
		}
		hc.fr.WriteWindowUpdate(id, 1<<20)
		hc.fr.WriteWindowUpdate(0, 1<<20)
		hc.wait(id)
		if got := string(hc.resp[id].body); got != want {
			t.Fatalf("body: %d bytes, want %d", len(got), len(want))
		}
		if !hc.resp[id].ended {
			t.Error("no END_STREAM")
		}
	})

	t.Run("connection window, streams in turn", func(t *testing.T) {
		hc := dialH2(t, addr, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		hc.autoWindow = false
		a := hc.start(h2Fields("GET", "/big"), true)
		b := hc.start(h2Fields("GET", "/big"), true)
		both := func() int { return len(hc.stream(a).body) + len(hc.stream(b).body) }
		for both() < 65535 {
			if !hc.readFrame() {
				t.Fatalf("connection ended at %d bytes", both())
			}
		}
		// Both responses are waiting for the connection's window by now.
		time.Sleep(100 * time.Millisecond)
		hc.settle()
		if n := both(); n != 65535 {
			t.Fatalf("with the connection's first window: %d bytes, want 65535", n)
		}
		// More window for the connection: the two waiting streams share it,
		// a frame at a time in turn.
		before := [2]int{len(hc.resp[a].body), len(hc.resp[b].body)}
		const more = 8 * 16384
		hc.fr.WriteWindowUpdate(0, more)
		for both() < 65535+more {
			if !hc.readFrame() {
				t.Fatalf("connection ended at %d bytes", both())
			}
		}
		hc.settle()
		got := [2]int{len(hc.resp[a].body) - before[0], len(hc.resp[b].body) - before[1]}
		if d := got[0] - got[1]; got[0]+got[1] != more || d > 2*16384 || d < -2*16384 {
			t.Fatalf("%d bytes more for two waiting streams: %v, want about half each", more, got)
		}
		hc.autoWindow = true
		hc.fr.WriteWindowUpdate(0, 1<<20)
		hc.wait(a, b)
		for _, id := range []uint32{a, b} {
			if got := string(hc.resp[id].body); got != want {
				t.Fatalf("stream %d: %d bytes, want %d", id, len(got), len(want))
			}
		}
	})

	t.Run("no window at first", func(t *testing.T) {
		hc := dialH2(t, addr, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})
		id := hc.start(h2Fields("GET", "/ok"), true)
		for hc.stream(id).header == nil {
			if !hc.readFrame() {
				t.Fatal("connection ended before the response head")
			}
		}
		hc.settle()
		if r := hc.resp[id]; r.status != 200 || len(r.body) != 0 || r.ended {
			t.Fatalf("with no window: %+v", r)
		}
		hc.fr.WriteWindowUpdate(id, 100)
		hc.wait(id)
		if got := string(hc.resp[id].body); got != "hello GET /ok" {
			t.Fatalf("body %q", got)
		}
	})
}

// TestH2_ResetAndTimers: a client's reset cancels its request and is logged
// 499; the connection goes on; an idle connection gets GOAWAY and is
// closed; a stop sends GOAWAY and lets the open request finish.
func TestH2_ResetAndTimers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := logging.Init("warning", path, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logging.Init("warning", "", "") })
	be := newRawBackend(t)
	cert, key := genCertWithCN(t, t.TempDir(), "example.test")
	l := &ListenerConfig{Name: "tls-site", Addr: "127.0.0.1:0", Protocol: "https",
		TLS: &config.TLSConfig{Cert: cert, Key: key}, Timeouts: config.TimeoutConfig{Idle: "400ms"}}
	s := fastTestSite(l, &config.Backend{Servers: []string{be.addr()}})
	fastPathOff.Store(false)
	g := NewBindGroup("127.0.0.1:0", "https")
	g.AddSite(s)
	if err := g.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			g.Stop(ctx)
		}
	})
	addr := g.BoundAddr().String()

	hc := dialH2(t, addr)
	id := hc.start(h2Fields("GET", "/sleep/2s"), true)
	hc.settle()
	hc.fr.WriteRSTStream(id, http2.ErrCodeCancel)
	if r := hc.do(h2Fields("GET", "/next"), nil); r.status != 200 || string(r.body) != "hello GET /next" {
		t.Fatalf("after a reset: %d %q", r.status, r.body)
	}
	lines := secLogLines(t, path, 2)
	if len(lines) != 2 || !strings.Contains(lines[0], `"GET /sleep/2s HTTP/2.0" 499 `) || !strings.Contains(lines[1], `"GET /next HTTP/2.0" 200 `) {
		t.Errorf("access log:\n%s", strings.Join(lines, "\n"))
	}

	// Idle: GOAWAY without an error after the idle timeout, then the close.
	start := time.Now()
	for hc.readFrame() {
	}
	if hc.goAway == nil || hc.goAway.ErrCode != http2.ErrCodeNo || hc.goAway.LastStreamID != 3 {
		t.Fatalf("idle connection: GOAWAY %+v", hc.goAway)
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 3*time.Second {
		t.Errorf("idle connection closed after %v", d)
	}

	// Stop: GOAWAY, the request in progress is answered, then the close.
	hc = dialH2(t, addr)
	id = hc.start(h2Fields("GET", "/sleep/300ms"), true)
	hc.settle()
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		g.Stop(ctx)
		close(done)
	}()
	stopped = true
	hc.wait(id)
	if r := hc.resp[id]; r.status != 200 || string(r.body) != "slept" {
		t.Errorf("request in progress at the stop: %d %q", r.status, r.body)
	}
	for hc.readFrame() {
	}
	if hc.goAway == nil || hc.goAway.ErrCode != http2.ErrCodeNo {
		t.Errorf("stop: GOAWAY %+v", hc.goAway)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the stop did not finish")
	}
}

// h2Interim is an informational response as net/http's path sent it,
// without nvelox's own fields: that path repeats them on an informational
// response, the loops do not (on HTTP/1.1 either).
func h2Interim(h http.Header) http.Header {
	out := h.Clone()
	delete(out, "x-content-type-options")
	delete(out, "alt-svc")
	delete(out, "x-request-id")
	return out
}

// h2Site is tlsSite with a listener and backend a test shapes.
func h2Site(t *testing.T, be string, setup func(l *ListenerConfig, b *config.Backend)) *HTTPServer {
	t.Helper()
	cert, key := genCertWithCN(t, t.TempDir(), "example.test")
	l := &ListenerConfig{Name: "tls-site", Addr: "127.0.0.1:0", Protocol: "https", TLS: &config.TLSConfig{Cert: cert, Key: key}}
	b := &config.Backend{Servers: []string{be}}
	if setup != nil {
		setup(l, b)
	}
	return fastTestSite(l, b)
}

func h2Same(t *testing.T, name string, s, f *h2Response) {
	t.Helper()
	if s.reset != f.reset || s.code != f.code || s.status != f.status {
		t.Errorf("%s: net/http %d reset=%v (%v), loops %d reset=%v (%v)", name, s.status, s.reset, s.code, f.status, f.reset, f.code)
		return
	}
	if !bytes.Equal(s.body, f.body) {
		t.Errorf("%s: body differs:\n net/http %q\n loops    %q", name, trunc(string(s.body)), trunc(string(f.body)))
	}
	if sh, fh := sortedHeader(s.header), sortedHeader(f.header); sh != fh {
		t.Errorf("%s: headers differ:\n net/http %s\n loops    %s", name, trunc(sh), trunc(fh))
	}
	if st, ft := sortedHeader(s.trailer), sortedHeader(f.trailer); st != ft {
		t.Errorf("%s: trailers differ:\n net/http %s\n loops    %s", name, st, ft)
	}
}

// TestH2_GatesAndErrorsMatchNetHTTP: what nvelox answers by itself (the
// access gates, a backend that is down, slow or missing, header rules) is
// the same on the loops as through net/http's HTTP/2 server.
func TestH2_GatesAndErrorsMatchNetHTTP(t *testing.T) {
	be := newRawBackend(t)
	deadAddr := deadTCPAddr(t)
	type gate struct {
		name   string
		be     string
		setup  func(l *ListenerConfig, b *config.Backend)
		after  func(s *HTTPServer)
		fields [][2]string
	}
	x := h2Fields("GET", "/x;a=1", [2]string{"x-token", "bad"})
	gates := []gate{
		{"denylist", "", func(l *ListenerConfig, b *config.Backend) { l.IPDenylist = []string{"127.0.0.0/8"} }, nil, x},
		{"allowlist", "", func(l *ListenerConfig, b *config.Backend) { l.IPAllowlist = []string{"10.0.0.0/8"} }, nil, x},
		{"no backend", "", nil, func(s *HTTPServer) { s.router.defaultBackend = "" }, x},
		{"unknown backend", "", nil, func(s *HTTPServer) { s.router.defaultBackend = "nope" }, x},
		{"rate limited", "", nil, func(s *HTTPServer) { s.RateLimiter = denyAll{} }, x},
		{"rate limited, HEAD", "", nil, func(s *HTTPServer) { s.RateLimiter = denyAll{} }, h2Fields("HEAD", "/x")},
		{"acl deny with status", "", func(l *ListenerConfig, b *config.Backend) {
			l.ACL = []config.ACLRule{{Match: config.ACLMatch{PathPrefix: "/x"}, Action: "deny", Status: 404}}
		}, nil, x},
		{"acl header and method", "", func(l *ListenerConfig, b *config.Backend) {
			l.ACL = []config.ACLRule{{Match: config.ACLMatch{Method: []string{"get"}, Headers: map[string]string{"X-Token": "bad"}}, Action: "deny"}}
		}, nil, x},
		{"error page", "", func(l *ListenerConfig, b *config.Backend) {
			p := filepath.Join(t.TempDir(), "403.html")
			os.WriteFile(p, []byte("<p>custom</p>"), 0o644)
			l.IPDenylist = []string{"127.0.0.0/8"}
			l.ErrorPages = map[int]string{403: p}
		}, nil, x},
		{"backend down", deadAddr, nil, nil, x},
		{"backend too slow", "", func(l *ListenerConfig, b *config.Backend) { b.Timeouts = config.TimeoutConfig{ResponseHeader: "200ms"} }, nil,
			h2Fields("GET", "/sleep/1s")},
		{"request id", "", func(l *ListenerConfig, b *config.Backend) {
			l.RequestID.Enabled = true
			l.RequestID.TrustInbound = true
		}, nil,
			h2Fields("GET", "/ok", [2]string{"x-request-id", "0123456789abcdef0123456789abcdef"})},
		{"header rules", "", func(l *ListenerConfig, b *config.Backend) {
			l.Headers = config.HeadersConfig{
				RequestAdd:     map[string]string{"X-Added": "a"},
				RequestSet:     map[string]string{"X-Set": "s", "user-agent": "rule-ua"},
				RequestRemove:  []string{"X-Token"},
				ResponseAdd:    map[string]string{"X-Resp-Added": "r"},
				ResponseSet:    map[string]string{"Server": "nvelox-test"},
				ResponseRemove: []string{"X-Remove-Me"},
			}
		}, nil, h2Fields("GET", "/headers", [2]string{"x-token", "bad"})},
	}
	for _, g := range gates {
		var got [2]*h2Response
		var reqs [2]*http.Request
		for i, fast := range []bool{false, true} {
			addr := g.be
			if addr == "" {
				addr = be.addr()
			}
			s := h2Site(t, addr, g.setup)
			if g.after != nil {
				g.after(s)
			}
			before := be.count()
			hc := dialH2(t, startTLSGroup(t, s, fast))
			got[i] = hc.do(g.fields, nil)
			hc.c.Close()
			if be.count() > before {
				reqs[i] = be.last()
			}
		}
		h2Same(t, g.name, got[0], got[1])
		if (reqs[0] == nil) != (reqs[1] == nil) {
			t.Errorf("%s: backend saw the request: net/http %v, loops %v", g.name, reqs[0] != nil, reqs[1] != nil)
		} else if reqs[0] != nil && !reflect.DeepEqual(reqs[0].Header, reqs[1].Header) {
			t.Errorf("%s: backend headers differ:\n net/http %v\n loops    %v", g.name, reqs[0].Header, reqs[1].Header)
		}
	}
}

// TestH2_BigResponseHead: a response head past what a loop parses itself
// (parsed and encoded off the loop) reaches an HTTP/2 client as through
// net/http.
func TestH2_BigResponseHead(t *testing.T) {
	var many strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&many, "X-Field-%d: value %d\r\n", i, i)
	}
	long := strings.Repeat("v", 100<<10)
	be := newScriptBackend(t, func(path string) (string, bool) {
		switch path {
		case "/many":
			return "HTTP/1.1 200 OK\r\n" + many.String() + "Content-Type: text/plain\r\nContent-Length: 2\r\n\r\nok", false
		case "/long":
			return "HTTP/1.1 200 OK\r\nX-Long: " + long + "\r\nContent-Length: 28\r\n\r\n<html><body>hi</body></html>", false
		case "/early":
			return "HTTP/1.1 103 Early Hints\r\n" + many.String() + "\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok", false
		case "/manyhead":
			return "HTTP/1.1 204 No Content\r\n" + many.String() + "\r\n", false
		}
		return "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", false
	})
	paths := []string{"/many", "/long", "/early", "/manyhead"}
	var got [2]map[string]*h2Response
	for i, fast := range []bool{false, true} {
		s := h2Site(t, be.ln.Addr().String(), nil)
		addr := startTLSGroup(t, s, fast)
		got[i] = map[string]*h2Response{}
		for _, p := range paths {
			hc := dialH2(t, addr)
			got[i][p] = hc.do(h2Fields("GET", p), nil)
			hc.c.Close()
		}
	}
	for _, p := range paths {
		h2Same(t, p, got[0][p], got[1][p])
		if len(got[0][p].interim) != len(got[1][p].interim) {
			t.Errorf("%s: interim responses: net/http %d, loops %d", p, len(got[0][p].interim), len(got[1][p].interim))
		} else if len(got[0][p].interim) == 1 && sortedHeader(h2Interim(got[0][p].interim[0])) != sortedHeader(got[1][p].interim[0]) {
			t.Errorf("%s: the interim response's fields differ:\n net/http %d fields %s\n loops    %d fields %s", p,
				len(got[0][p].interim[0]), trunc(sortedHeader(got[0][p].interim[0])), len(got[1][p].interim[0]), trunc(sortedHeader(got[1][p].interim[0])))
		}
	}
	if v := got[1]["/many"].header["x-field-299"]; len(v) != 1 || v[0] != "value 299" {
		t.Errorf("/many: fields missing: %v", v)
	}
}

// TestH2_SplitInput: frames that arrive in pieces (a header block over
// several events, a frame header cut in two, a body a byte at a time).
func TestH2_SplitInput(t *testing.T) {
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	hc := dialH2(t, addr)
	pause := func() { time.Sleep(30 * time.Millisecond) }

	// A header block in three frames, with other connections' requests
	// decoded by the same loops in between.
	b := hc.block(h2Fields("GET", "/split", [2]string{"x-a", strings.Repeat("a", 300)}, [2]string{"cookie", "a=1"}, [2]string{"cookie", "b=2"}))
	hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: b[:7], EndStream: true, EndHeaders: false})
	pause()
	for i := 0; i < 8; i++ {
		other := dialH2(t, addr)
		if r := other.do(h2Fields("GET", fmt.Sprintf("/other%d", i), [2]string{"x-b", strings.Repeat("b", 500)}), nil); r.status != 200 {
			t.Fatalf("another connection: %d", r.status)
		}
		other.c.Close()
	}
	hc.fr.WriteContinuation(1, false, b[7:150])
	pause()
	hc.fr.WriteContinuation(1, true, b[150:])
	hc.next = 3
	hc.wait(1)
	if r := hc.resp[1]; r.status != 200 || string(r.body) != "hello GET /split" {
		t.Fatalf("split header block: %d %q", r.status, r.body)
	}
	if req := be.last(); req.Header.Get("X-A") != strings.Repeat("a", 300) || req.Header.Get("Cookie") != "a=1; b=2" {
		t.Errorf("split header block: the backend got %v", req.Header)
	}

	// Raw bytes of frames, written a few at a time.
	var buf bytes.Buffer
	fr := http2.NewFramer(&buf, nil)
	body := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 3, EndHeaders: true, BlockFragment: hc.block([][2]string{
		{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/bytes"}, {"content-length", fmt.Sprint(len(body))}})})
	fr.WritePing(false, [8]byte{1})
	fr.WriteDataPadded(3, false, body[:20], make([]byte, 9))
	fr.WriteData(3, true, body[20:])
	raw := buf.Bytes()
	for i := 0; i < len(raw); i += 3 {
		if _, err := hc.c.Write(raw[i:min(i+3, len(raw))]); err != nil {
			t.Fatal(err)
		}
		if i%15 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	hc.next = 5
	hc.wait(3)
	if r := hc.resp[3]; r.status != 200 || string(r.body) != "hello POST /bytes" {
		t.Fatalf("frames in pieces: %d %q", r.status, r.body)
	}
	if req := be.last(); req.Header.Get("X-Test-Body-Sum") != fmt.Sprintf("%x", crc32.ChecksumIEEE(body)) {
		t.Errorf("frames in pieces: the backend's body differs")
	}
}

// TestH2_PingFlood: answers to a client's frames never pile up without
// bound: with output waiting, its frames are not read.
func TestH2_PingFlood(t *testing.T) {
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	hc := dialH2(t, addr)
	const pings = 200000
	done := make(chan error, 1)
	go func() {
		var buf bytes.Buffer
		fr := http2.NewFramer(&buf, nil)
		for i := 0; i < 1000; i++ {
			fr.WritePing(false, [8]byte{'f', 'l', 'o', 'o', 'd'})
		}
		for i := 0; i < pings/1000; i++ {
			if _, err := hc.c.Write(buf.Bytes()); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	// The writer blocks once the server stops reading; reading the answers
	// lets it go on.
	time.Sleep(300 * time.Millisecond)
	acks := 0
	for acks < pings {
		f, err := hc.fr.ReadFrame()
		if err != nil {
			t.Fatalf("after %d answers: %v", acks, err)
		}
		if p, ok := f.(*http2.PingFrame); ok && p.IsAck() {
			acks++
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if r := hc.do(h2Fields("GET", "/ok"), nil); r.status != 200 {
		t.Errorf("after the flood: %d", r.status)
	}
}

// TestH2_BodyTimeouts: a client that stops in the middle of its request
// body is answered 408 after the read limit, like through net/http.
func TestH2_BodyTimeouts(t *testing.T) {
	be := newRawBackend(t)
	var got [2]*h2Response
	for i, fast := range []bool{false, true} {
		s := h2Site(t, be.addr(), func(l *ListenerConfig, b *config.Backend) { l.Timeouts = config.TimeoutConfig{Read: "300ms"} })
		hc := dialH2(t, startTLSGroup(t, s, fast))
		id := hc.start([][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/stall"}, {"content-length", "100"}}, false)
		hc.fr.WriteData(id, false, []byte("only this"))
		start := time.Now()
		hc.wait(id)
		if d := time.Since(start); d < 200*time.Millisecond || d > 3*time.Second {
			t.Errorf("fast=%v: answered after %v", fast, d)
		}
		got[i] = hc.resp[id]
		hc.c.Close()
	}
	h2Same(t, "stalled body", got[0], got[1])
	if got[1].status != http.StatusRequestTimeout {
		t.Errorf("stalled body: %d, want 408", got[1].status)
	}
}

// TestH2_ConnectionFieldsNotSent: fields that belong to an HTTP/1.1
// connection never reach an HTTP/2 client, also when a header rule adds
// them. (Go's server sends a rule's Keep-Alive or Upgrade as it is; clients
// that check their input refuse such a response.)
func TestH2_ConnectionFieldsNotSent(t *testing.T) {
	be := newRawBackend(t)
	s := h2Site(t, be.addr(), func(l *ListenerConfig, b *config.Backend) {
		l.Headers = config.HeadersConfig{ResponseAdd: map[string]string{
			"Keep-Alive": "timeout=5", "Upgrade": "h2c", "Proxy-Connection": "keep-alive", "Transfer-Encoding": "chunked", "X-Kept": "1"}}
	})
	hc := dialH2(t, startTLSGroup(t, s, true))
	r := hc.do(h2Fields("GET", "/ok"), nil)
	if r.status != 200 || string(r.body) != "hello GET /ok" || r.header["x-kept"] == nil {
		t.Fatalf("response: %d %q %v", r.status, r.body, r.header)
	}
	for _, name := range []string{"keep-alive", "upgrade", "proxy-connection", "transfer-encoding", "connection"} {
		if v, ok := r.header[name]; ok {
			t.Errorf("%s: %v reached the client", name, v)
		}
	}
}

// TestH2_BackendRefusesBody: a backend that answers before it has read the
// request's body (and closes): its answer reaches the client, and a client
// still sending is told to stop. (Through net/http the same request is
// answered with the backend's 413 or with a 502, by a race between the
// transport's body writer and its response reader.)
func TestH2_BackendRefusesBody(t *testing.T) {
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	body := bytes.Repeat([]byte("0123456789abcdef"), 300<<10/16)
	fields := [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/early"}, {"content-length", fmt.Sprint(len(body))}}

	// The whole body sent before the answer is read.
	hc := dialH2(t, addr)
	if r := hc.do(fields, body); r.status != 413 || string(r.body) != "nope" || !r.ended {
		t.Errorf("body sent first: %d %q ended=%v reset=%v", r.status, r.body, r.ended, r.reset)
	}
	hc.c.Close()

	// The body still on its way when the answer comes: END_STREAM, then a
	// reset that is no error.
	hc = dialH2(t, addr)
	id := hc.start(fields, false)
	hc.fr.WriteData(id, false, body[:1000])
	for hc.stream(id).header == nil || !hc.stream(id).ended {
		if !hc.readFrame() {
			t.Fatal("connection ended before the answer")
		}
	}
	hc.settle()
	if r := hc.resp[id]; r.status != 413 || string(r.body) != "nope" || !r.reset || r.code != http2.ErrCodeNo {
		t.Errorf("body unfinished: %d %q reset=%v (%v)", r.status, r.body, r.reset, r.code)
	}
	// What the client still sends for that stream is refused, and the
	// connection goes on.
	hc.fr.WriteData(id, true, body[1000:2000])
	if r := hc.do(h2Fields("GET", "/ok"), nil); r.status != 200 {
		t.Errorf("after it: %d", r.status)
	}
}

// TestH2_FramesBehindAWindowUpdate: frames that arrive in one read are all
// served, also when the first of them makes a backend be read again (which
// reads into a buffer of the loop).
func TestH2_FramesBehindAWindowUpdate(t *testing.T) {
	be := newRawBackend(t)
	s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
	addr := startTLSGroup(t, s, true)
	want := strings.Repeat("0123456789abcdef", 200<<10/16)
	for round := 0; round < 20; round++ {
		hc := dialH2(t, addr, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1000})
		hc.autoWindow = false
		id := hc.start(h2Fields("GET", "/big"), true)
		if n := hc.bodyOf(id, 1000); n != 1000 {
			t.Fatalf("with a window of 1000: %d bytes", n)
		}
		// One write, so one read on the server: the stream's window opens
		// (its backend is read again at once), then more frames follow.
		var buf bytes.Buffer
		fr := http2.NewFramer(&buf, nil)
		fr.WriteWindowUpdate(id, 1<<20)
		fr.WriteWindowUpdate(0, 1<<20)
		for i := 0; i < 50; i++ {
			fr.WritePing(false, [8]byte{'p', byte(i)})
		}
		fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id + 2, BlockFragment: hc.block(h2Fields("GET", "/second")), EndStream: true, EndHeaders: true})
		hc.next = id + 4
		if _, err := hc.c.Write(buf.Bytes()); err != nil {
			t.Fatal(err)
		}
		hc.wait(id, id+2)
		if hc.goAway != nil {
			t.Fatalf("round %d: GOAWAY %v", round, hc.goAway.ErrCode)
		}
		if got := string(hc.resp[id].body); got != want {
			t.Fatalf("round %d: first response: %d bytes, want %d", round, len(got), len(want))
		}
		if r := hc.resp[id+2]; r.status != 200 || string(r.body) != "hello GET /second" {
			t.Fatalf("round %d: second response: %d %q", round, r.status, r.body)
		}
		hc.c.Close()
	}
}

// TestH2_HandlersMatchNetHTTP: requests the loops do not serve themselves
// reach net/http's handlers through the bridge and are answered as by Go's
// HTTP/2 server: a whole site that is not the loops' (compression on), and
// single requests of a site that is (a body without a length, trailers,
// Expect, a field HTTP/2 does not allow, a header list that is too long,
// CONNECT, "OPTIONS *").
func TestH2_HandlersMatchNetHTTP(t *testing.T) {
	be := newRawBackend(t)

	t.Run("a site with compression", func(t *testing.T) {
		cases := h2Cases()
		var resps [2]map[string]*h2Response
		var reqs [2]map[string]*http.Request
		for i, fast := range []bool{false, true} {
			s := h2Site(t, be.addr(), func(l *ListenerConfig, b *config.Backend) { l.Compression.Enabled = true })
			addr := startTLSGroup(t, s, fast)
			resps[i], reqs[i] = map[string]*h2Response{}, map[string]*http.Request{}
			for _, c := range cases {
				before := be.count()
				hc := dialH2(t, addr)
				resps[i][c.name] = hc.do(c.fields, c.body)
				hc.c.Close()
				if be.count() > before {
					reqs[i][c.name] = be.last()
				}
			}
		}
		for _, c := range cases {
			h2Same(t, c.name, resps[0][c.name], resps[1][c.name])
			sr, fr := reqs[0][c.name], reqs[1][c.name]
			if (sr == nil) != (fr == nil) {
				t.Errorf("%s: backend saw the request: net/http %v, loops %v", c.name, sr != nil, fr != nil)
			} else if sr != nil && (!reflect.DeepEqual(sr.Header, fr.Header) || sr.RequestURI != fr.RequestURI || sr.Host != fr.Host || sr.ContentLength != fr.ContentLength) {
				t.Errorf("%s: backend request differs:\n net/http %s %s %d %v\n loops    %s %s %d %v", c.name,
					sr.Host, sr.RequestURI, sr.ContentLength, sr.Header, fr.Host, fr.RequestURI, fr.ContentLength, fr.Header)
			}
		}
	})

	t.Run("requests of a site the loops serve", func(t *testing.T) {
		big := bytes.Repeat([]byte("0123456789abcdef"), 3<<20/16)
		var many [][2]string
		for i := 0; i < 600; i++ {
			many = append(many, [2]string{fmt.Sprintf("x-f-%d", i), "v"})
		}
		req := func(method, path string, extra ...[2]string) [][2]string {
			return append([][2]string{{":method", method}, {":scheme", "https"}, {":authority", "example.test"}, {":path", path}}, extra...)
		}
		type bcase struct {
			name string
			do   func(hc *h2Client) uint32
		}
		simple := func(fields [][2]string) func(hc *h2Client) uint32 {
			return func(hc *h2Client) uint32 { return hc.start(fields, true) }
		}
		cases := []bcase{
			{"a body without a length", func(hc *h2Client) uint32 {
				id := hc.start(req("POST", "/nolen"), false)
				hc.data(id, []byte("hello "), false)
				hc.data(id, []byte("world"), true)
				return id
			}},
			{"a large body without a length", func(hc *h2Client) uint32 {
				id := hc.start(req("PUT", "/nolen-big"), false)
				hc.upload(id, big)
				return id
			}},
			{"a body that never comes without a length", func(hc *h2Client) uint32 {
				id := hc.start(req("POST", "/nolen-empty"), false)
				hc.fr.WriteData(id, true, nil)
				return id
			}},
			{"announced trailers", func(hc *h2Client) uint32 {
				id := hc.start(req("POST", "/trailers", [2]string{"trailer", "X-Sum, Content-Length"}, [2]string{"content-length", "3"}), false)
				hc.data(id, []byte("abc"), false)
				hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hc.block([][2]string{{"x-sum", "6"}, {"x-other", "1"}}), EndStream: true, EndHeaders: true})
				return id
			}},
			{"a trailer that may not be one", func(hc *h2Client) uint32 {
				id := hc.start(req("POST", "/trailers", [2]string{"trailer", "X-Sum"}), false)
				hc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: hc.block([][2]string{{"content-length", "6"}}), EndStream: true, EndHeaders: true})
				return id
			}},
			{"Expect: 100-continue", func(hc *h2Client) uint32 {
				id := hc.start(req("POST", "/expect", [2]string{"expect", "100-continue"}, [2]string{"content-length", "5"}), false)
				for len(hc.stream(id).interim) == 0 {
					if !hc.readFrame() {
						hc.t.Fatal("connection ended before 100 Continue")
					}
				}
				hc.data(id, []byte("hello"), true)
				return id
			}},
			{"connection field", simple(req("GET", "/ok", [2]string{"connection", "close"}))},
			{"keep-alive field", simple(req("GET", "/ok", [2]string{"keep-alive", "300"}))},
			{"upgrade field", simple(req("GET", "/ok", [2]string{"upgrade", "websocket"}))},
			{"transfer-encoding field", simple(req("GET", "/ok", [2]string{"transfer-encoding", "chunked"}))},
			{"te other than trailers", simple(req("GET", "/ok", [2]string{"te", "gzip"}))},
			{"two te fields", simple(req("GET", "/ok", [2]string{"te", "trailers"}, [2]string{"te", "trailers"}))},
			{"a header list that is too long", simple(req("GET", "/ok", many...))},
			{"a field of 1.1 MiB", simple(req("GET", "/ok", [2]string{"x-big", strings.Repeat("v", 1100<<10)}))},
			{"CONNECT", func(hc *h2Client) uint32 {
				return hc.start([][2]string{{":method", "CONNECT"}, {":authority", "example.test:443"}}, true)
			}},
			{"OPTIONS *", simple(req("OPTIONS", "*"))},
			{"GET *", simple(req("GET", "*"))},
			{":authority and host", simple(req("GET", "/ok", [2]string{"host", "other.test"}))},
			{"a value with spaces around it", simple(req("GET", "/ok", [2]string{"x-pad", "  v  "}))},
			{"a path with a space", simple(req("GET", "/a b"))},
			{"a path net/url refuses", simple(req("GET", "/%zz"))},
			{"an absolute path with a fragment", simple(req("GET", "/ok#frag"))},
			{"no :method", simple([][2]string{{":scheme", "https"}, {":authority", "example.test"}, {":path", "/ok"}})},
			{"no :path", simple([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}})},
			{"an empty :path", simple(req("GET", ""))},
			{"a :path without a slash", simple(req("GET", "ok"))},
			{"a scheme that is not the web's", simple([][2]string{{":method", "GET"}, {":scheme", "ftp"}, {":authority", "example.test"}, {":path", "/ok"}})},
			{":protocol", simple(req("GET", "/ok", [2]string{":protocol", "websocket"})[:0:0])},
			{"CONNECT with a path", simple([][2]string{{":method", "CONNECT"}, {":authority", "example.test:443"}, {":path", "/x"}})},
			{"userinfo in :authority", simple([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "user@example.test"}, {":path", "/ok"}})},
			{"userinfo in host", simple([][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/ok"}, {"host", "user@example.test"}})},
			{"no host at all", simple([][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/ok"}})},
			{"a Content-Length and no body", simple(req("POST", "/ok", [2]string{"content-length", "5"}))},
			{"two different Content-Lengths", func(hc *h2Client) uint32 {
				return hc.start(req("POST", "/ok", [2]string{"content-length", "3"}, [2]string{"content-length", "4"}), false)
			}},
			{"the same Content-Length twice", func(hc *h2Client) uint32 {
				id := hc.start(req("POST", "/ok", [2]string{"content-length", "3"}, [2]string{"content-length", "3"}), false)
				hc.data(id, []byte("abc"), true)
				return id
			}},
			{"a Content-Length that is no number", simple(req("GET", "/ok", [2]string{"content-length", "abc"}))},
			{"a Content-Length that is no number, with a body", func(hc *h2Client) uint32 {
				id := hc.start(req("POST", "/ok", [2]string{"content-length", "abc"}), false)
				hc.data(id, []byte("abc"), true)
				return id
			}},
			{"a zero Content-Length, with an empty body", func(hc *h2Client) uint32 {
				id := hc.start(req("POST", "/ok", [2]string{"content-length", "0"}), false)
				hc.fr.WriteData(id, true, nil)
				return id
			}},
			{"more than 96 fields", simple(req("GET", "/ok", many[:150]...))},
		}
		cases[27].do = simple([][2]string{{":method", "GET"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/ok"}, {":protocol", "websocket"}})
		var out [2]map[string]string
		var resps [2]map[string]*h2Response
		var reqs [2]map[string]*http.Request
		for i, fast := range []bool{false, true} {
			s := tlsSite(t, &config.Backend{Servers: []string{be.addr()}})
			addr := startTLSGroup(t, s, fast)
			out[i], resps[i], reqs[i] = map[string]string{}, map[string]*h2Response{}, map[string]*http.Request{}
			for _, c := range cases {
				before := be.count()
				hc := dialH2(t, addr)
				id := c.do(hc)
				for r := hc.stream(id); !(r.ended || r.reset) && hc.goAway == nil; {
					if !hc.readFrame() {
						break
					}
				}
				out[i][c.name] = hc.settle()
				resps[i][c.name] = hc.stream(id)
				hc.c.Close()
				if be.count() > before {
					reqs[i][c.name] = be.last()
				}
			}
		}
		for _, c := range cases {
			if out[0][c.name] != out[1][c.name] {
				t.Errorf("%s:\n net/http %s\n loops    %s", c.name, out[0][c.name], out[1][c.name])
				continue
			}
			t.Logf("%s: %s", c.name, out[1][c.name])
			h2Same(t, c.name, resps[0][c.name], resps[1][c.name])
			sr, fr := reqs[0][c.name], reqs[1][c.name]
			if resps[1][c.name].reset {
				// Whether a request that is reset reached the backend before
				// the reset is a matter of timing, on either path.
				continue
			}
			if (sr == nil) != (fr == nil) {
				t.Errorf("%s: backend saw the request: net/http %v, loops %v", c.name, sr != nil, fr != nil)
			} else if sr != nil {
				if !reflect.DeepEqual(sr.Header, fr.Header) || sr.RequestURI != fr.RequestURI || sr.Host != fr.Host || sr.Method != fr.Method {
					t.Errorf("%s: backend request differs:\n net/http %s %s %s %v\n loops    %s %s %s %v", c.name,
						sr.Method, sr.Host, sr.RequestURI, sr.Header, fr.Method, fr.Host, fr.RequestURI, fr.Header)
				}
				if !reflect.DeepEqual(sr.TransferEncoding, fr.TransferEncoding) || sr.ContentLength != fr.ContentLength {
					t.Errorf("%s: backend framing differs: net/http %v/%d, loops %v/%d", c.name, sr.TransferEncoding, sr.ContentLength, fr.TransferEncoding, fr.ContentLength)
				}
			}
		}
	})
}

// TestH2_HandlerEdges: a handler's stream under the client's flow control,
// a response that breaks off (the stream is reset, as Go's server resets
// one whose handler gave up), a client that resets a request a handler is
// serving, and a body that stalls.
func TestH2_HandlerEdges(t *testing.T) {
	want := strings.Repeat("0123456789abcdef", 200<<10/16)
	be := newRawBackend(t)
	cut := newScriptBackend(t, func(path string) (string, bool) {
		return "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100\r\n\r\npartial", true
	})
	handlers := func(l *ListenerConfig, b *config.Backend) { l.Compression.Enabled = true }

	t.Run("flow control", func(t *testing.T) {
		s := h2Site(t, be.addr(), handlers)
		hc := dialH2(t, startTLSGroup(t, s, true), http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1000})
		hc.autoWindow = false
		id := hc.start(h2Fields("GET", "/big"), true)
		if n := hc.bodyOf(id, 1000); n != 1000 {
			t.Fatalf("with a window of 1000: %d bytes", n)
		}
		hc.fr.WriteWindowUpdate(id, 30000)
		if n := hc.bodyOf(id, 31000); n != 31000 {
			t.Fatalf("after 30000 more: %d bytes", n)
		}
		// Other requests are served while that handler waits.
		hc.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 1 << 20})
		hc.autoWindow = true
		other := hc.start(h2Fields("GET", "/ok"), true)
		hc.fr.WriteWindowUpdate(0, 1<<20)
		hc.wait(id, other)
		if got := string(hc.resp[id].body); got != want {
			t.Fatalf("body: %d bytes, want %d", len(got), len(want))
		}
		if r := hc.resp[other]; r.status != 200 || string(r.body) != "hello GET /ok" {
			t.Fatalf("the other request: %d %q", r.status, r.body)
		}
	})

	t.Run("a response that breaks off", func(t *testing.T) {
		var got [3]string
		for i, mode := range []string{"net/http", "handlers", "loops"} {
			var setup func(l *ListenerConfig, b *config.Backend)
			if mode == "handlers" {
				setup = handlers
			}
			s := h2Site(t, cut.ln.Addr().String(), setup)
			hc := dialH2(t, startTLSGroup(t, s, mode != "net/http"))
			id := hc.start(h2Fields("GET", "/cut"), true)
			hc.wait(id)
			r := hc.resp[id]
			got[i] = fmt.Sprintf("%d %q reset=%v (%v) ended=%v", r.status, r.body, r.reset, r.code, r.ended)
			// The connection goes on.
			if !r.reset || r.code != http2.ErrCodeInternal || r.ended || hc.goAway != nil {
				t.Errorf("%s: %s, GOAWAY %v", mode, got[i], hc.goAway)
			}
			if rr := hc.do(h2Fields("GET", "/again"), nil); !rr.reset {
				t.Errorf("%s: the next request on the connection: %d reset=%v", mode, rr.status, rr.reset)
			}
			hc.c.Close()
		}
		// A handler's 4 KiB buffer still held the head and these few bytes
		// when it gave up; the loops had passed them on already.
		if got[0] != got[1] {
			t.Errorf("net/http %s\nhandlers %s", got[0], got[1])
		}
		if !strings.HasPrefix(got[2], `200 "partial" reset=true`) {
			t.Errorf("loops: %s", got[2])
		}
	})

	t.Run("a reset while a handler serves", func(t *testing.T) {
		s := h2Site(t, be.addr(), handlers)
		hc := dialH2(t, startTLSGroup(t, s, true))
		for i := 0; i < 20; i++ {
			id := hc.start(h2Fields("GET", "/sleep/5s"), true)
			hc.fr.WriteRSTStream(id, http2.ErrCodeCancel)
		}
		start := time.Now()
		if r := hc.do(h2Fields("GET", "/ok"), nil); r.status != 200 {
			t.Fatalf("after the resets: %d", r.status)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("a request after 20 resets took %v", d)
		}
	})

	t.Run("a body that stalls", func(t *testing.T) {
		var got [2]*h2Response
		for i, fast := range []bool{false, true} {
			s := h2Site(t, be.addr(), func(l *ListenerConfig, b *config.Backend) {
				l.Compression.Enabled = true
				l.Timeouts = config.TimeoutConfig{Read: "300ms"}
			})
			hc := dialH2(t, startTLSGroup(t, s, fast))
			id := hc.start([][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/stall"}, {"content-length", "100"}}, false)
			hc.fr.WriteData(id, false, []byte("only this"))
			hc.wait(id)
			got[i] = hc.resp[id]
			hc.c.Close()
		}
		h2Same(t, "stalled body", got[0], got[1])
	})
}
