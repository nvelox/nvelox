package httpproxy

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

// TestParseResponseAgreesWithNetHTTP: the fast path's backend response
// parser and net/http's (what the net/http path relays) agree on what they
// accept, the status, the framing and the header fields passed on.
func TestParseResponseAgreesWithNetHTTP(t *testing.T) {
	many := strings.Repeat("X-N: n\r\n", 200)
	big := strings.Repeat("X-Big: "+strings.Repeat("v", 1000)+"\r\n", 1024) // ~1 MiB
	for _, raw := range []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
		"HTTP/1.1 200 OK\r\nA: b\nContent-Length: 2\r\n\nok",
		"HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n2\r\nok\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\n" + many + "Content-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\n" + big + "Content-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nBad@Name: x\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nConnection: a, b, c, d, e, f, g, h, i, j\r\nA: 1\r\nJ: 2\r\nK: 3\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\n X: y\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\nok",
		"HTTP/1.1 204\r\n\r\n",
		"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nbody",
		"HTTP/1.1 304 Not Modified\nETag: \"x\"\n\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nX-Utf8: caf\xc3\xa9\r\nContent-Length: 0\r\n\r\n",
		// The status line.
		"HTTP/1.1  200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1   200\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1\t200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/2.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/0.9 200 OK\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.2 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"HTTP/11.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/0.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"HTTP/0.0 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"HTTP/0.9 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\nraw",
		"HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n",
		// Folded lines: joined with one space each; the name is on the
		// first line; a value net/http checks as read keeps what a fold
		// leaves behind it.
		"HTTP/1.1 200 OK\r\nX-Fold: a\r\n b\r\n\t c \r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Fold: a\r\n \r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nA\r\n : b\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\nA\n :\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n \r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n \r\n\r\nok",
		// Transfer-Encoding and Content-Length.
		"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n",
		"HTTP/1.0 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775807\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775808\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 02\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length:   2  \r\n\r\nok",
		"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\nok",
		"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n",
		// Trailer announcements with a chunked body.
		"HTTP/1.1 200 OK\r\nTrailer: X-A, Content-Length\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTrailer: Transfer-Encoding\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTrailer: trailer\r\nTrailer: X-A\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nTrailer: X-A, Content-Length\r\nContent-Length: 0\r\n\r\n",
		// Pragma: no-cache without Cache-Control.
		"HTTP/1.1 200 OK\r\nPragma: no-cache\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nPragma: no-cache\r\nCache-Control: max-age=5\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nPragma: no-cache\r\nCache-Control:\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nPragma: No-Cache\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nPragma: x\r\nPragma: no-cache\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nPragma: no-cache\r\n \r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 103 Early Hints\r\nPragma: no-cache\r\n\r\n",
	} {
		var h respHead
		buf := []byte(raw)
		ok, err := parseResponse(buf, &h, false)
		if err == errRespBig {
			// Past what a loop parses: parsed again as off the loop.
			h.big = true
			ok, err = parseResponse(buf, &h, false)
		}
		resp, gerr := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), &http.Request{Method: "GET"})
		name := raw
		if len(name) > 60 {
			name = name[:60]
		}
		if (err == nil && ok) != (gerr == nil) {
			t.Errorf("%q: fast path ok=%v err=%v, net/http err=%v", name, ok, err, gerr)
			continue
		}
		if gerr != nil {
			continue
		}
		if h.status != resp.StatusCode {
			t.Errorf("%q: status %d, net/http %d", name, h.status, resp.StatusCode)
		}
		chunked := len(resp.TransferEncoding) > 0
		switch {
		case chunked && h.framing != bodyChunked,
			!chunked && resp.ContentLength >= 0 && (h.framing != bodyLength || h.contentLength != resp.ContentLength) && h.framing != bodyNone,
			!chunked && resp.ContentLength < 0 && h.framing != bodyClose && h.framing != bodyNone:
			t.Errorf("%q: framing %d cl %d, net/http te %v cl %d", name, h.framing, h.contentLength, resp.TransferEncoding, resp.ContentLength)
		}
		// The fields relayed: net/http's, minus names net/http's server
		// never writes (a space in the name).
		var want, got []string
		// A body that ends with the connection closes it too.
		if got := h.connClose || h.framing == bodyClose; got != resp.Close {
			t.Errorf("%q: close %v, net/http %v", name, got, resp.Close)
		}
		for k, vs := range resp.Header {
			if strings.ContainsAny(k, " ") || k == "Content-Length" || k == "Transfer-Encoding" || k == "Connection" || k == "Trailer" {
				continue // framing is compared above; the Transport removes the others in some cases (other tests)
			}
			for _, v := range vs {
				// net/http writes a value on without the white space
				// an empty continuation line left after it.
				want = append(want, strings.ToLower(k)+": "+strings.TrimRight(v, " \t"))
			}
		}
		for i := 0; i < h.n; i++ {
			hd := h.headers[i]
			if hd.kind == hkContentLength || hd.kind == hkTransferEncoding || hd.kind == hkConnection || hd.kind == hkTrailer || bytes.EqualFold(hd.name, []byte("Trailer")) {
				continue
			}
			got = append(got, strings.ToLower(string(hd.name))+": "+string(hd.value))
		}
		if a, b := sortedJoin(want), sortedJoin(got); a != b {
			t.Errorf("%q: headers differ:\n net/http %.300s\n fast     %.300s", name, a, b)
		}
		// The parse changes folded lines in place; the same bytes parsed
		// again (as a head past a loop's limits is) give the same result.
		var h2 respHead
		h2.big = h.big
		ok2, err2 := parseResponse(buf, &h2, false)
		if !ok2 || err2 != nil || respHeadDump(&h2) != respHeadDump(&h) {
			t.Errorf("%q: parsed again: ok=%v err=%v\n first  %.300s\n second %.300s", name, ok2, err2, respHeadDump(&h), respHeadDump(&h2))
		}
	}
}

// respHeadDump is everything a parse decided, as text.
func respHeadDump(h *respHead) string {
	var b strings.Builder
	fmt.Fprintf(&b, "status=%d headLen=%d framing=%d cl=%d close=%v chunked=%v names=%q;", h.status, h.headLen, h.framing, h.contentLength, h.connClose, h.chunked, h.connNames)
	for i := range h.headers {
		hd := &h.headers[i]
		fmt.Fprintf(&b, " %q=%q/%d/%v", hd.name, hd.value, hd.kind, hd.drop)
	}
	return b.String()
}

// A head past a loop's limits is parsed twice: on the loop up to the limit
// it breaks (errRespBig), then in full. Folded lines before that point were
// already joined by the first parse; the result must be that of parsing the
// untouched bytes in full.
func TestRespHeadParsedTwiceAfterFolds(t *testing.T) {
	var fields strings.Builder
	for i := 0; i < maxFastHeaders+5; i++ {
		fmt.Fprintf(&fields, "X-%d: v\r\n", i)
	}
	for _, folded := range []string{
		"Pragma: n\n\to-cache\r\n",
		"Pragma: no-cache\r\n \r\n",
		"Pragma:\r\n no-cache\r\n",
		"X-Fold: a\r\n \r\n\t\r\n  b \r\n \r\n",
		"X-Fold: a\n\t\n c\n",
		"Set-Cookie: a=1;\r\n\tPath=/;\r\n\t\tHttpOnly\r\n",
	} {
		raw := "HTTP/1.1 200 OK\r\n" + folded + fields.String() + "Content-Length: 0\r\n\r\n"
		pristine := &respHead{big: true}
		if ok, err := parseResponse([]byte(raw), pristine, false); !ok || err != nil {
			t.Fatalf("%q: ok=%v err=%v", folded, ok, err)
		}
		buf := []byte(raw)
		var h respHead
		if _, err := parseResponse(buf, &h, false); err != errRespBig {
			t.Fatalf("%q: on a loop err=%v, want past the limits", folded, err)
		}
		again := &respHead{big: true}
		if ok, err := parseResponse(buf, again, false); !ok || err != nil {
			t.Fatalf("%q: second parse ok=%v err=%v", folded, ok, err)
		}
		if a, b := respHeadDump(pristine), respHeadDump(again); a != b {
			t.Errorf("%q: parsed twice differs from parsed once:\n once  %.200s\n twice %.200s", folded, a, b)
		}
	}
}

func sortedJoin(s []string) string {
	c := append([]string(nil), s...)
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j] < c[j-1]; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
	return strings.Join(c, "\n")
}

// A head that arrives in many small reads is found once it is complete,
// whatever the read boundaries (the end search resumes where it stopped).
func TestParseResponseIncremental(t *testing.T) {
	for _, raw := range []string{
		"HTTP/1.1 200 OK\r\nA: b\r\nContent-Length: 2\r\n\r\nok",
		"HTTP/1.1 200 OK\nA: b\nContent-Length: 2\n\nok",
		"HTTP/1.1 200 OK\r\nA: b\nContent-Length: 2\n\r\nok",
	} {
		end := strings.Index(raw, "ok")
		for step := 1; step <= 7; step++ {
			scanned := 0
			found := -1
			for n := step; ; n += step {
				if n > len(raw) {
					n = len(raw)
				}
				if e := respHeadEnd([]byte(raw[:n]), scanned); e >= 0 {
					found = e
					break
				}
				scanned = n
				if n == len(raw) {
					break
				}
			}
			if found != end {
				t.Fatalf("%q step %d: head end %d, want %d", raw, step, found, end)
			}
		}
	}
}

// A loop parses a head up to maxLoopResponseHead bytes, maxFastHeaders
// fields and 8 Connection names; one past any of them is reported
// errRespBig and parses in full with big set.
func TestRespHeadLoopLimits(t *testing.T) {
	fields := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "X-%d: v\r\n", i)
		}
		return b.String()
	}
	names := func(n int) string {
		var s []string
		for i := 0; i < n; i++ {
			s = append(s, fmt.Sprintf("X-%d", i))
		}
		return strings.Join(s, ", ")
	}
	sized := func(n int) string { // a head of exactly n bytes
		const fixed = "HTTP/1.1 200 OK\r\nX-Pad: \r\n\r\n"
		return "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("p", n-len(fixed)) + "\r\n\r\n"
	}
	for _, tc := range []struct {
		name   string
		raw    string
		big    bool
		fields int
	}{
		{"fields at the limit", "HTTP/1.1 200 OK\r\n" + fields(maxFastHeaders) + "\r\n", false, maxFastHeaders},
		{"one field more", "HTTP/1.1 200 OK\r\n" + fields(maxFastHeaders+1) + "\r\n", true, maxFastHeaders + 1},
		{"names at the limit", "HTTP/1.1 200 OK\r\nConnection: " + names(8) + "\r\n\r\n", false, 1},
		{"one name more", "HTTP/1.1 200 OK\r\nConnection: " + names(9) + "\r\n\r\n", true, 1},
		{"names over two fields", "HTTP/1.1 200 OK\r\nConnection: " + names(5) + "\r\nConnection: " + names(4) + "\r\n\r\n", true, 2},
		{"size at the limit", sized(maxLoopResponseHead), false, 1},
		{"one byte more", sized(maxLoopResponseHead + 1), true, 1},
		{"dropped names do not count", "HTTP/1.1 200 OK\r\n" + strings.Repeat("Bad Name: x\r\n", 200) + fields(3) + "\r\n", false, 3},
	} {
		var h respHead
		buf := []byte(tc.raw)
		ok, err := parseResponse(buf, &h, false)
		if tc.big != (err == errRespBig) || (!tc.big && (err != nil || !ok)) {
			t.Errorf("%s: on a loop ok=%v err=%v, want past the limits = %v", tc.name, ok, err, tc.big)
			continue
		}
		if tc.big {
			h.big = true
			if ok, err = parseResponse(buf, &h, false); err != nil || !ok {
				t.Errorf("%s: off the loop ok=%v err=%v", tc.name, ok, err)
				continue
			}
		}
		if h.n != tc.fields || len(h.headers) != tc.fields || h.headLen != len(tc.raw) {
			t.Errorf("%s: %d fields (want %d), head %d bytes (want %d)", tc.name, h.n, tc.fields, h.headLen, len(tc.raw))
		}
	}
	// A head that is not complete is never past the limits: the loop goes
	// on reading it, whatever its size so far.
	var h respHead
	if ok, err := parseResponse([]byte("HTTP/1.1 200 OK\r\nX-Big: "+strings.Repeat("v", 2*maxLoopResponseHead)), &h, false); ok || err != nil {
		t.Errorf("incomplete large head: ok=%v err=%v", ok, err)
	}
}

// The fields a Connection header names are dropped as net/http's
// ReverseProxy drops them (Header.Del of each name: the case of ASCII
// letters is ignored, nothing else), for a few names and for many.
func TestRespConnectionNamesDroppedAsNetHTTP(t *testing.T) {
	many := func(n int) (names, fields string) {
		var ns []string
		var b strings.Builder
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("X-Hop-%d", i)
			switch i % 3 {
			case 1:
				ns = append(ns, strings.ToUpper(name))
			case 2:
				ns = append(ns, strings.ToLower(name))
			default:
				ns = append(ns, name)
			}
			fmt.Fprintf(&b, "%s: %d\r\n", name, i)
		}
		return strings.Join(ns, " ,\t"), b.String()
	}
	n40, f40 := many(40)
	for _, raw := range []string{
		"HTTP/1.1 200 OK\r\nConnection: x-a, X-B\r\nX-A: 1\r\nx-b: 2\r\nX-C: 3\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-A: 1\r\nConnection: close, x-a\r\nX-C: 3\r\nConnection: x-c\r\nContent-Length: 0\r\n\r\n",
		// Not ASCII: U+212A (Kelvin sign) folds to k, U+017F (long s) to s
		// in Unicode, but these name no header.
		"HTTP/1.1 200 OK\r\nConnection: \u212aeep-me, \u017fet-cookie\r\nKeep-Me: 1\r\nSet-Cookie: a=b\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nConnection: x a, x-a x-b, ,x-c\r\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nConnection: " + n40 + "\r\n" + f40 + "X-Keep: 1\r\nContent-Length: 0\r\n\r\n",
		// The same names again, with non-ASCII ones among many.
		"HTTP/1.1 200 OK\r\nConnection: " + n40 + ", \u212aeep-me\r\n" + f40 + "Keep-Me: 1\r\nX-Keep: 1\r\nContent-Length: 0\r\n\r\n",
	} {
		var h respHead
		buf := []byte(raw)
		ok, err := parseResponse(buf, &h, false)
		if err == errRespBig {
			h.big = true
			ok, err = parseResponse(buf, &h, false)
		}
		if err != nil || !ok {
			t.Errorf("%.60q: ok=%v err=%v", raw, ok, err)
			continue
		}
		// net/http's header reader, then ReverseProxy's
		// removeHopByHopHeaders for the Connection names.
		tp := textproto.NewReader(bufio.NewReader(strings.NewReader(raw)))
		if _, gerr := tp.ReadLine(); gerr != nil {
			t.Fatal(gerr)
		}
		mh, gerr := tp.ReadMIMEHeader()
		if gerr != nil {
			t.Fatalf("%.60q: net/http: %v", raw, gerr)
		}
		hdr := http.Header(mh)
		for _, f := range hdr["Connection"] {
			for _, sf := range strings.Split(f, ",") {
				if sf = textproto.TrimString(sf); sf != "" {
					hdr.Del(sf)
				}
			}
		}
		var want, got []string
		for k := range hdr {
			if k != "Connection" && k != "Content-Length" {
				want = append(want, strings.ToLower(k))
			}
		}
		for i := range h.headers {
			if hd := h.headers[i]; !hd.drop && hd.kind != hkContentLength {
				got = append(got, strings.ToLower(string(hd.name)))
			}
		}
		if a, b := sortedJoin(want), sortedJoin(got); a != b {
			t.Errorf("%.60q: fields kept differ:\n net/http %.300q\n fast     %.300q", raw, a, b)
		}
	}
}

// One case where the fast path does not do as the net/http path: an
// HTTP/1.1 response whose Connection header says close and also names
// fields. net/http's Transport deletes that Connection header before
// ReverseProxy looks for names in it, so the net/http path relays the named
// fields. The fast path drops them, as RFC 9110 section 7.6.1 requires of
// an intermediary. This test states both, so that a change on either side
// shows.
func TestRespConnectionCloseWithNames(t *testing.T) {
	const raw = "HTTP/1.1 200 OK\r\nConnection: close, X-Hop\r\nX-Hop: 1\r\nX-Keep: 1\r\nContent-Length: 0\r\n\r\n"
	var h respHead
	if ok, err := parseResponse([]byte(raw), &h, false); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	for i := range h.headers {
		hd := h.headers[i]
		if name := string(hd.name); (name == "X-Hop") != hd.drop && name != "Connection" && name != "Content-Length" {
			t.Errorf("fast path: %s dropped = %v", name, hd.drop)
		}
	}
	if !h.connClose {
		t.Error("fast path: close not seen")
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Close || len(resp.Header["Connection"]) != 0 || resp.Header.Get("X-Hop") != "1" {
		t.Errorf("net/http: Close=%v Connection=%q X-Hop=%q: its handling of close with names changed; align the comment above and the fast path's choice",
			resp.Close, resp.Header["Connection"], resp.Header.Get("X-Hop"))
	}
}

// Dropping the fields Connection names takes time in proportion to the
// head, not to names × fields: 60,000 names against 60,000 fields.
func TestRespManyConnectionNamesLinear(t *testing.T) {
	const n = 60000
	var names, fields strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			names.WriteByte(',')
		}
		fmt.Fprintf(&names, "x-%d", i)
		fmt.Fprintf(&fields, "X-%d: v\r\n", i)
	}
	raw := []byte("HTTP/1.1 200 OK\r\nConnection: " + names.String() + "\r\n" + fields.String() + "X-Keep: 1\r\nContent-Length: 0\r\n\r\n")
	h := &respHead{big: true}
	start := time.Now()
	ok, err := parseResponse(raw, h, false)
	took := time.Since(start)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	kept := 0
	for i := range h.headers {
		if !h.headers[i].drop {
			kept++
		}
	}
	if kept != 2 { // X-Keep and Content-Length
		t.Fatalf("%d fields kept, want 2", kept)
	}
	// 3.6e9 name comparisons take over half a minute; one pass takes
	// milliseconds (more under the race detector, far from the bound).
	if took > 10*time.Second {
		t.Fatalf("parsing took %v", took)
	}
}

// Where the fast path reads a response head differently from the net/http
// path on purpose. Each is stated here so that a change on either side
// shows.
func TestRespHeadKnownDifferences(t *testing.T) {
	// A status code below 100. net/http's Transport returns the response,
	// but its server cannot write such a code: it ends the client's
	// connection without an answer. The fast path answers 502.
	raw := "HTTP/1.1 099 Odd\r\nContent-Length: 0\r\n\r\n"
	var h respHead
	if ok, err := parseResponse([]byte(raw), &h, false); ok || err == nil {
		t.Errorf("status 099: fast path ok=%v err=%v, want refused", ok, err)
	}
	if resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), &http.Request{Method: "GET"}); err != nil || resp.StatusCode != 99 {
		t.Errorf("status 099: net/http now refuses it (%v): the fast path's 502 is then the same", err)
	}

	// The hop-by-hop fields of an informational response. ReverseProxy
	// copies a 1xx response's fields to the client as they are; the fast
	// path leaves the hop-by-hop ones out, as for every response.
	raw = "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\nKeep-Alive: timeout=5\r\nConnection: X-Hop\r\nX-Hop: 1\r\n\r\n"
	h = respHead{}
	if ok, err := parseResponse([]byte(raw), &h, false); !ok || err != nil {
		t.Fatalf("103: ok=%v err=%v", ok, err)
	}
	for i := range h.headers {
		hd := h.headers[i]
		if name := string(hd.name); (name != "Link") != hd.drop {
			t.Errorf("103: %s dropped = %v", name, hd.drop)
		}
	}

	// An HTTP/1.0 response that says "Connection: close" and has a field
	// named Close: ReverseProxy takes "close" for a field name there and
	// drops that field (from HTTP/1.1 on the Transport removes the
	// Connection header first). The fast path keeps the field.
	raw = "HTTP/1.0 200 OK\r\nConnection: close\r\nClose: 1\r\nContent-Length: 0\r\n\r\n"
	h = respHead{}
	if ok, err := parseResponse([]byte(raw), &h, false); !ok || err != nil {
		t.Fatalf("1.0 close: ok=%v err=%v", ok, err)
	}
	for i := range h.headers {
		if hd := h.headers[i]; string(hd.name) == "Close" && hd.drop {
			t.Error("1.0 close: the field named Close is dropped")
		}
	}
}

// The chunked reader refuses what net/http's refuses, with the same data
// before it: framing bytes that carry next to no data (long chunk
// extensions), bare LF, bad sizes.
func TestChunkReaderAgreesWithNetHTTP(t *testing.T) {
	ext := func(n int) string { return ";" + strings.Repeat("e", n) }
	many := func(n int, chunk string) string { return strings.Repeat(chunk, n) }
	for _, raw := range []string{
		"5\r\nhello\r\n0\r\n\r\n",
		many(5000, "1\r\nx\r\n") + "0\r\n\r\n",
		many(40, "1"+ext(500)+"\r\nx\r\n") + "0\r\n\r\n",
		many(3, "1"+ext(4000)+"\r\nx\r\n") + "0\r\n\r\n",
		many(6, "1"+ext(4000)+"\r\nx\r\n") + "0\r\n\r\n",
		many(3, "1"+ext(4000)+"\r\nx\r\n") + "ffff\r\n" + strings.Repeat("d", 0xffff) + "\r\n" + many(4, "1"+ext(4000)+"\r\nx\r\n") + "0\r\n\r\n",
		"1" + ext(5000) + "\r\nx\r\n0\r\n\r\n",
		"5\nhello\n0\n\n",
		"5 \r\nhello\r\n0\r\n\r\n",
		"g\r\nhello\r\n0\r\n\r\n",
	} {
		var c chunkReader
		c.reset()
		var got bytes.Buffer
		var gerr error
		for p := []byte(raw); len(p) > 0; {
			off, n, used, done, err := c.next(p)
			if err != nil {
				gerr = err
				break
			}
			got.Write(p[off : off+n])
			p = p[used:]
			if done {
				break
			}
		}
		want, werr := io.ReadAll(httputil.NewChunkedReader(strings.NewReader(raw)))
		name := raw
		if len(name) > 40 {
			name = name[:40]
		}
		if (gerr == nil) != (werr == nil) {
			t.Errorf("%q: fast path err=%v, net/http err=%v", name, gerr, werr)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Errorf("%q: %d bytes of data, net/http %d", name, got.Len(), len(want))
		}
		if gerr == errChunkExcess && werr.Error() != gerr.Error() {
			t.Errorf("%q: error %q, net/http %q", name, gerr, werr)
		}
	}
}
