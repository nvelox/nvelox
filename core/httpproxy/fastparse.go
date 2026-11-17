package httpproxy

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"strings"
	"unsafe"
)

// The fast path's HTTP/1.1 parsers. They allocate nothing: every field is a
// slice of the buffer that was parsed. The request parser accepts a strict
// subset of HTTP/1.1; anything outside it (obs-fold, a bare LF, an unusual
// byte, a body, an upgrade, ...) makes it report parseHandoff and the
// connection is handed, with every byte read so far, to net/http, which then
// answers exactly as it always has. The fast path therefore never decides
// anything net/http would decide differently on input it does not fully
// understand.

// parseResult is what the request parser reports.
type parseResult int

const (
	parseOK      parseResult = iota // a complete request head of the fast-path subset
	parseMore                       // incomplete: read more
	parseHandoff                    // outside the subset: hand the connection to net/http
)

// maxFastHeaders bounds the header lines of a fast-path request or response.
const maxFastHeaders = 96

// maxFastRequestHead is the largest request head the fast path buffers;
// larger ones go to net/http (whose limit is MaxHeaderBytes).
const maxFastRequestHead = 32 << 10

// maxFastResponseHead is the largest backend response head the fast path
// accepts: the limit of net/http's Transport, which nvelox does not change
// (MaxResponseHeaderBytes' default, 10 MiB).
const maxFastResponseHead = 10 << 20

// maxLoopResponseHead is the largest backend response head an event loop
// parses itself. Parsing a head and building the client's from it take time
// in proportion to what the backend sent, and on a loop every other
// connection of that loop waits meanwhile. So a head larger than this, or
// with more fields than maxFastHeaders, or naming more headers in Connection
// than a loop's list holds, is parsed on a goroutine instead (errRespBig),
// as net/http parses every head.
const maxLoopResponseHead = 64 << 10

// header kinds the fast path acts on.
const (
	hkOther uint8 = iota
	hkHost
	hkContentLength
	hkTransferEncoding
	hkConnection
	hkUpgrade
	hkExpect
	hkKeepAlive
	hkProxyConnection
	hkTE
	hkTrailer
	hkProxyAuthenticate
	hkProxyAuthorization
	hkForwarded
	hkXForwardedFor
	hkXForwardedHost
	hkXForwardedProto
	hkXRealIP
	hkXRequestID
	hkUserAgent
	hkSecFetchSite
	hkSecFetchDest
	hkContentType
	hkContentEncoding
	hkDate
	hkUntrustedFwd // the rest of untrustedForwardingHeaders
	hkCookie
	hkAuthorization
	hkIdempotencyKey
)

type fastHeader struct {
	name, value []byte
	kind        uint8
	drop        bool // removed from what is forwarded
}

type reqHead struct {
	method, target, path, query []byte
	hasQuery                    bool
	pathHasPct                  bool
	headers                     [maxFastHeaders]fastHeader
	n                           int
	headLen                     int // bytes of the head, final CRLF included

	host            int // index of the Host header
	connClose       bool
	teTrailers      bool
	contentLength   int64     // -1: none
	connNames       [8][]byte // header names the Connection header lists
	nConnNames      int
	userAgent       int // first User-Agent, -1 if none
	xRequestID      int // first X-Request-ID, -1 if none
	secFetchSite    int
	secFetchDest    int
	xRealIP         int
	xForwardedProto int
	idempotencyKey  bool
}

// tchar per RFC 9110 5.6.2.
var isTchar = func() (t [256]bool) {
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for _, c := range "!#$%&'*+-.^_`|~" {
		t[c] = true
	}
	return
}()

// isPathChar: the bytes a fast-path request path may contain verbatim —
// the ones net/url keeps as the client wrote them (unreserved, sub-delims,
// ':', '@', '/'; '%' is checked separately). Any other byte would be
// re-encoded by net/url on the way to the backend, so the request goes to
// net/http instead.
var isPathChar = func() (t [256]bool) {
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for _, c := range "-._~!$&'()*+,;=:@/" {
		t[c] = true
	}
	return
}()

// isQueryChar: bytes a query may carry (forwarded verbatim, as net/http
// does): anything visible, and obs-text.
var isQueryChar = func() (t [256]bool) {
	for c := 0x21; c <= 0xff; c++ {
		t[c] = c != 0x7f
	}
	return
}()

// isHostChar: what a fast-path Host header may contain.
var isHostChar = func() (t [256]bool) {
	for c := '0'; c <= '9'; c++ {
		t[c] = true
	}
	for c := 'a'; c <= 'z'; c++ {
		t[c] = true
	}
	for c := 'A'; c <= 'Z'; c++ {
		t[c] = true
	}
	for _, c := range "-._:[]" {
		t[c] = true
	}
	return
}()

// isValueChar: field-value bytes (VCHAR, obs-text, SP, HTAB).
var isValueChar = func() (t [256]bool) {
	t['\t'] = true
	for c := 0x20; c <= 0xff; c++ {
		t[c] = c != 0x7f
	}
	return
}()

var crlfcrlf = []byte("\r\n\r\n")

// equalFoldLower compares b, case-insensitively, with lower, an ASCII
// lower-case string.
func equalFoldLower(b []byte, lower string) bool {
	if len(b) != len(lower) {
		return false
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != lower[i] {
			return false
		}
	}
	return true
}

// headerKind classifies a header name.
func headerKind(name []byte) uint8 {
	switch len(name) {
	case 2:
		if equalFoldLower(name, "te") {
			return hkTE
		}
	case 4:
		if equalFoldLower(name, "host") {
			return hkHost
		}
		if equalFoldLower(name, "date") {
			return hkDate
		}
	case 6:
		if equalFoldLower(name, "expect") {
			return hkExpect
		}
		if equalFoldLower(name, "cookie") {
			return hkCookie
		}
	case 7:
		if equalFoldLower(name, "upgrade") {
			return hkUpgrade
		}
		if equalFoldLower(name, "trailer") {
			return hkTrailer
		}
	case 9:
		if equalFoldLower(name, "forwarded") {
			return hkForwarded
		}
		if equalFoldLower(name, "x-real-ip") {
			return hkXRealIP
		}
	case 10:
		if equalFoldLower(name, "connection") {
			return hkConnection
		}
		if equalFoldLower(name, "keep-alive") {
			return hkKeepAlive
		}
		if equalFoldLower(name, "user-agent") {
			return hkUserAgent
		}
	case 11:
		if equalFoldLower(name, "x-client-ip") {
			return hkUntrustedFwd
		}
	case 12:
		if equalFoldLower(name, "x-request-id") {
			return hkXRequestID
		}
		if equalFoldLower(name, "content-type") {
			return hkContentType
		}
	case 13:
		if equalFoldLower(name, "x-rewrite-url") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "authorization") {
			return hkAuthorization
		}
	case 14:
		if equalFoldLower(name, "content-length") {
			return hkContentLength
		}
		if equalFoldLower(name, "x-original-url") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "sec-fetch-site") {
			return hkSecFetchSite
		}
		if equalFoldLower(name, "sec-fetch-dest") {
			return hkSecFetchDest
		}
		if equalFoldLower(name, "true-client-ip") {
			return hkUntrustedFwd
		}
	case 15:
		if equalFoldLower(name, "x-forwarded-for") {
			return hkXForwardedFor
		}
		if equalFoldLower(name, "idempotency-key") {
			return hkIdempotencyKey
		}
		if equalFoldLower(name, "x-forwarded-ssl") {
			return hkUntrustedFwd
		}
	case 16:
		if equalFoldLower(name, "x-forwarded-host") {
			return hkXForwardedHost
		}
		if equalFoldLower(name, "x-forwarded-port") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "proxy-connection") {
			return hkProxyConnection
		}
		if equalFoldLower(name, "fastly-client-ip") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "cf-connecting-ip") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "content-encoding") {
			return hkContentEncoding
		}
	case 17:
		if equalFoldLower(name, "transfer-encoding") {
			return hkTransferEncoding
		}
		if equalFoldLower(name, "x-idempotency-key") {
			return hkIdempotencyKey
		}
		if equalFoldLower(name, "x-forwarded-proto") {
			return hkXForwardedProto
		}
	case 18:
		if equalFoldLower(name, "x-forwarded-server") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "x-forwarded-prefix") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "x-forwarded-scheme") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "proxy-authenticate") {
			return hkProxyAuthenticate
		}
	case 19:
		if equalFoldLower(name, "x-cluster-client-ip") {
			return hkUntrustedFwd
		}
		if equalFoldLower(name, "proxy-authorization") {
			return hkProxyAuthorization
		}
	}
	return hkOther
}

// hopByHop reports whether a header of kind k is never forwarded (RFC 9110
// 7.6.1 and the list net/http/httputil removes).
func hopByHop(k uint8) bool {
	switch k {
	case hkConnection, hkProxyConnection, hkKeepAlive, hkProxyAuthenticate, hkProxyAuthorization,
		hkTE, hkTrailer, hkTransferEncoding, hkUpgrade:
		return true
	}
	return false
}

// lineEnd returns the index of the CRLF ending the line that starts at p,
// or -1. A bare LF or CR inside the line makes it return -2.
func lineEnd(b []byte, p int) int {
	i := bytes.IndexByte(b[p:], '\n')
	if i < 0 {
		return -1
	}
	i += p
	if i == p || b[i-1] != '\r' {
		return -2
	}
	return i - 1
}

// parseRequest parses the request head at the start of b.
func parseRequest(b []byte, h *reqHead) parseResult {
	end := bytes.Index(b, crlfcrlf)
	if end < 0 {
		// A bare LF anywhere means a line ending the fast path does not
		// accept: let net/http read it.
		if i := bytes.IndexByte(b, '\n'); i >= 0 && (i == 0 || b[i-1] != '\r') {
			return parseHandoff
		}
		if len(b) >= maxFastRequestHead {
			return parseHandoff
		}
		return parseMore
	}
	h.headLen = end + 4
	if h.headLen > maxFastRequestHead {
		return parseHandoff
	}
	head := b[:end+2] // through the last header line's CRLF

	// Request line: method SP request-target SP HTTP/1.1 CRLF
	le := lineEnd(head, 0)
	if le < 0 {
		return parseHandoff
	}
	line := head[:le]
	sp1 := bytes.IndexByte(line, ' ')
	if sp1 <= 0 {
		return parseHandoff
	}
	h.method = line[:sp1]
	for _, c := range h.method {
		if !isTchar[c] {
			return parseHandoff
		}
	}
	rest := line[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	if sp2 <= 0 {
		return parseHandoff
	}
	h.target = rest[:sp2]
	if string(rest[sp2+1:]) != "HTTP/1.1" {
		return parseHandoff
	}
	if h.target[0] != '/' {
		return parseHandoff // absolute-form, authority-form, asterisk-form
	}
	if !splitTarget(h) {
		return parseHandoff
	}
	switch string(h.method) {
	case "CONNECT", "PRI":
		return parseHandoff
	}

	// Header lines.
	h.resetFields()
	p := le + 2
	for p < len(head) {
		le := lineEnd(head, p)
		if le < 0 {
			return parseHandoff
		}
		line := head[p:le]
		p = le + 2
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return parseHandoff // includes obs-fold (a line starting with SP/HTAB)
		}
		name := line[:colon]
		for _, c := range name {
			if !isTchar[c] {
				return parseHandoff
			}
		}
		v := line[colon+1:]
		for _, c := range v {
			if !isValueChar[c] {
				return parseHandoff
			}
		}
		v = trimOWS(v)
		if !h.addField(name, v) {
			return parseHandoff
		}
	}
	if !h.endFields() {
		return parseHandoff
	}
	return parseOK
}

// resetFields empties the head's field list.
func (h *reqHead) resetFields() {
	h.n = 0
	h.host = -1
	h.connClose = false
	h.teTrailers = false
	h.contentLength = -1
	h.nConnNames = 0
	h.userAgent, h.xRequestID, h.secFetchSite, h.secFetchDest, h.xRealIP, h.xForwardedProto = -1, -1, -1, -1, -1, -1
	h.idempotencyKey = false
}

// addField appends a header field (its value without the spaces around
// it) and notes what the fast path acts on. It reports false when the
// field puts the request outside the fast path's subset: too many fields,
// a second Host or Content-Length, a Host or Content-Length that is not
// what it should be, Transfer-Encoding, Expect or Upgrade, or a Connection
// header past what parseConnection takes. The request then goes to
// net/http, which answers it its own way.
func (h *reqHead) addField(name, v []byte) bool {
	if h.n == maxFastHeaders {
		return false
	}
	k := headerKind(name)
	hd := &h.headers[h.n]
	hd.name, hd.value, hd.kind, hd.drop = name, v, k, hopByHop(k)
	switch k {
	case hkHost:
		if h.host >= 0 {
			return false // several Host headers: net/http answers 400
		}
		for _, c := range v {
			if !isHostChar[c] {
				return false
			}
		}
		h.host = h.n
	case hkContentLength:
		if h.contentLength >= 0 {
			return false
		}
		n, ok := parseContentLength(v)
		if !ok {
			return false // net/http answers 400
		}
		h.contentLength = n
		hd.drop = true // the outgoing framing is the fast path's
	case hkTransferEncoding, hkExpect, hkUpgrade:
		return false
	case hkConnection:
		if !h.parseConnection(v) {
			return false
		}
	case hkTE:
		if tokenListHas(v, "trailers") {
			h.teTrailers = true
		}
	case hkUserAgent:
		if h.userAgent < 0 {
			h.userAgent = h.n
		}
	case hkXRequestID:
		if h.xRequestID < 0 {
			h.xRequestID = h.n
		}
	case hkSecFetchSite:
		if h.secFetchSite < 0 {
			h.secFetchSite = h.n
		}
	case hkSecFetchDest:
		if h.secFetchDest < 0 {
			h.secFetchDest = h.n
		}
	case hkXRealIP:
		if h.xRealIP < 0 {
			h.xRealIP = h.n
		}
	case hkXForwardedProto:
		if h.xForwardedProto < 0 {
			h.xForwardedProto = h.n
		}
	case hkIdempotencyKey:
		h.idempotencyKey = true
	}
	h.n++
	return true
}

// endFields closes the field list: a request needs a Host, and the headers
// its Connection header names are hop-by-hop too (Host cannot be one).
func (h *reqHead) endFields() bool {
	if h.host < 0 {
		return false // net/http answers 400
	}
	for i := 0; i < h.nConnNames; i++ {
		cn := h.connNames[i]
		for j := 0; j < h.n; j++ {
			if bytes.EqualFold(h.headers[j].name, cn) {
				if h.headers[j].kind == hkHost {
					return false
				}
				h.headers[j].drop = true
			}
		}
	}
	return true
}

// Get returns the first value of the named request header, as r.Header.Get
// does on the net/http path (where Host is not in the header map). The
// string is only valid while the head is.
func (h *reqHead) Get(name string) string {
	for i := 0; i < h.n; i++ {
		hd := &h.headers[i]
		if hd.kind != hkHost && len(hd.name) == len(name) && strings.EqualFold(bstr(hd.name), name) {
			return bstr(hd.value)
		}
	}
	return ""
}

// rebase points the slices of a head parsed from old at the same bytes of
// nw, a copy of old.
func (h *reqHead) rebase(old, nw []byte) {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(old)))
	h.method = rebaseSlice(h.method, base, nw)
	h.target = rebaseSlice(h.target, base, nw)
	h.path = rebaseSlice(h.path, base, nw)
	h.query = rebaseSlice(h.query, base, nw)
	for i := 0; i < h.n; i++ {
		h.headers[i].name = rebaseSlice(h.headers[i].name, base, nw)
		h.headers[i].value = rebaseSlice(h.headers[i].value, base, nw)
	}
	for i := 0; i < h.nConnNames; i++ {
		h.connNames[i] = rebaseSlice(h.connNames[i], base, nw)
	}
}

func rebaseSlice(b []byte, base uintptr, nw []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	off := uintptr(unsafe.Pointer(unsafe.SliceData(b))) - base
	return nw[off : off+uintptr(len(b)) : off+uintptr(len(b))]
}

// splitTarget splits the origin-form target into path and query and checks
// that the path is kept verbatim by net/url.
func splitTarget(h *reqHead) bool {
	t := h.target
	q := bytes.IndexByte(t, '?')
	if q >= 0 {
		h.path, h.query, h.hasQuery = t[:q], t[q+1:], true
	} else {
		h.path, h.query, h.hasQuery = t, nil, false
	}
	h.pathHasPct = false
	p := h.path
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '%' {
			if i+2 >= len(p) || unhex(p[i+1]) < 0 || unhex(p[i+2]) < 0 {
				return false
			}
			h.pathHasPct = true
			i += 2
			continue
		}
		if !isPathChar[c] {
			return false
		}
	}
	for _, c := range h.query {
		if !isQueryChar[c] {
			return false
		}
	}
	return true
}

func unhex(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c - 'a' + 10)
	case 'A' <= c && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// decodePath appends the percent-decoded path to dst.
func decodePath(dst, p []byte) []byte {
	for i := 0; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) {
			dst = append(dst, byte(unhex(p[i+1])<<4|unhex(p[i+2])))
			i += 2
			continue
		}
		dst = append(dst, p[i])
	}
	return dst
}

// parseConnection records the Connection header's tokens: close, and the
// names of extra hop-by-hop headers. An upgrade goes to net/http.
func (h *reqHead) parseConnection(v []byte) bool {
	for len(v) > 0 {
		var tok []byte
		if i := bytes.IndexByte(v, ','); i >= 0 {
			tok, v = v[:i], v[i+1:]
		} else {
			tok, v = v, nil
		}
		tok = trimOWS(tok)
		switch {
		case len(tok) == 0:
		case equalFoldLower(tok, "close"):
			h.connClose = true
		case equalFoldLower(tok, "keep-alive"):
		case equalFoldLower(tok, "upgrade"):
			return false
		default:
			for _, c := range tok {
				if !isTchar[c] {
					return false
				}
			}
			if h.nConnNames == len(h.connNames) {
				return false
			}
			h.connNames[h.nConnNames] = tok
			h.nConnNames++
		}
	}
	return true
}

// tokenListHas reports whether the comma-separated list v holds tok
// (lower-case), case-insensitively.
func tokenListHas(v []byte, tok string) bool {
	for len(v) > 0 {
		var t []byte
		if i := bytes.IndexByte(v, ','); i >= 0 {
			t, v = v[:i], v[i+1:]
		} else {
			t, v = v, nil
		}
		if equalFoldLower(trimOWS(t), tok) {
			return true
		}
	}
	return false
}

func trimOWS(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t') {
		b = b[:len(b)-1]
	}
	return b
}

// parseContentLength parses a Content-Length value: digits only, no sign,
// no overflow.
func parseContentLength(v []byte) (int64, bool) {
	if len(v) == 0 || len(v) > 18 {
		return 0, false
	}
	var n int64
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	return n, true
}

// parseRespContentLength parses a response's Content-Length as net/http
// does: digits only, up to the largest int64.
func parseRespContentLength(v []byte) (int64, bool) {
	if len(v) == 0 {
		return 0, false
	}
	var n int64
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
		d := int64(c - '0')
		if n > (math.MaxInt64-d)/10 {
			return 0, false
		}
		n = n*10 + d
	}
	return n, true
}

// Response framing.
const (
	bodyNone    = iota // no body (HEAD, 1xx, 204, 304)
	bodyLength         // Content-Length bytes
	bodyChunked        // chunked transfer coding
	bodyClose          // until the backend closes
)

type respHead struct {
	status        int
	headers       []fastHeader // headers[:n]: in hbuf; grown only when big
	hbuf          [maxFastHeaders]fastHeader
	n             int
	headLen       int
	framing       int
	contentLength int64
	connClose     bool     // the backend's connection is not reused after this response
	chunked       bool     // a chunked transfer coding was announced (whatever the framing: HEAD, 204, 304)
	connNames     [][]byte // header names the Connection header lists: in cbuf; grown only when big
	cbuf          [8][]byte
	// big: parsed off the loops, so without a loop's limits (the head's
	// size up to maxFastResponseHead, any number of fields and of
	// Connection names).
	big bool
}

// errResp marks a backend response the fast path cannot relay (the slow path
// would also fail it: malformed, or framing net/http refuses).
type respError string

func (e respError) Error() string { return "malformed backend response: " + string(e) }

// errRespBig: the response head is complete and, as far as it was read,
// well formed, but past what a loop parses (maxLoopResponseHead). It is to
// be parsed again with respHead.big set, off the loop. The bytes read so far
// were only changed in ways a second parse repeats (folded lines).
var errRespBig = errors.New("response head past the loop's limits")

// parseResponse parses a backend response head at the start of b for a
// request with method head (true for HEAD). It returns (false, nil) when
// the head is incomplete.
func parseResponse(b []byte, h *respHead, isHead bool) (bool, error) {
	return parseResponseFrom(b, h, isHead, 0)
}

// parseResponseFrom is parseResponse for a head whose first scanned bytes
// (b[:scanned]) are known not to hold its end: the search resumes there, so
// a head that arrives in many reads is scanned once.
//
// It reads a head as net/http reads it for the net/http path (ReadResponse,
// then the Transport's and ReverseProxy's handling), so that both paths
// accept, refuse and frame a backend's response alike, also when it is
// malformed. TestRespHeadKnownDifferences states where they differ on purpose.
func parseResponseFrom(b []byte, h *respHead, isHead bool, scanned int) (bool, error) {
	end := respHeadEnd(b, scanned)
	if end < 0 {
		if len(b) >= maxFastResponseHead {
			return false, respError("header too large")
		}
		return false, nil
	}
	if end > maxFastResponseHead {
		return false, respError("header too large")
	}
	if end > maxLoopResponseHead && !h.big {
		return false, errRespBig
	}
	h.headLen = end
	head := b[:end]
	// Lines end in LF, with or without a CR before it, as net/http's reader
	// takes them.
	le, p := respLineEnd(head, 0)

	// The status line: "HTTP/d.d", spaces, a code of three digits, then
	// anything (net/http.ReadResponse).
	line := head[:le]
	if len(line) < 9 || string(line[:5]) != "HTTP/" || !isDigit(line[5]) || line[6] != '.' || !isDigit(line[7]) || line[8] != ' ' {
		return false, respError("status line")
	}
	major, minor := line[5]-'0', line[7]-'0'
	code := line[9:]
	for len(code) > 0 && code[0] == ' ' {
		code = code[1:]
	}
	if i := bytes.IndexByte(code, ' '); i >= 0 {
		code = code[:i]
	}
	if len(code) != 3 || !isDigit(code[0]) || !isDigit(code[1]) || !isDigit(code[2]) {
		return false, respError("status code")
	}
	h.status = int(code[0]-'0')*100 + int(code[1]-'0')*10 + int(code[2]-'0')
	if h.status < 100 {
		// net/http's server cannot write such a code (it ends the
		// client's connection without an answer).
		return false, respError("status code")
	}
	// What HTTP/1.1 defines applies from 1.1 on (net/http: ProtoAtLeast),
	// and to "HTTP/0.0", which net/http's body reader takes for 1.1.
	atLeast11 := major > 1 || major == 1 && minor >= 1 || major == 0 && minor == 0

	if p < len(head) && (head[p] == ' ' || head[p] == '\t') {
		return false, respError("header line") // net/http: no leading space on the first header line
	}
	h.headers = h.hbuf[:0]
	if h.big {
		// One allocation of the right size: a line per field at most.
		if n := bytes.Count(head, lflf[:1]); n >= len(h.hbuf) {
			h.headers = make([]fastHeader, 0, n+1)
		}
	}
	h.connNames = h.cbuf[:0]
	h.contentLength = -1
	h.connClose = false
	var (
		chunked, keepAlive  bool
		cl0                 []byte // the first Content-Length, as text
		sawCL, sawCC        bool
		sawPragma, pragmaNC bool
		badTrailer          bool // a Trailer field names a framing field
	)
	for p < len(head) {
		le, next := respLineEnd(head, p)
		if le == p {
			break // the empty line ending the head
		}
		// net/http drops the white space around every line it reads.
		ls, w := p, le
		for w > ls && (head[w-1] == ' ' || head[w-1] == '\t') {
			w--
		}
		// The name ends at a colon of the field's first line.
		colon := bytes.IndexByte(head[ls:w], ':')
		if colon <= 0 {
			return false, respError("header line")
		}
		p = next
		// Lines that start with white space continue the field (obs-fold).
		// net/http joins each with one space, without the white space
		// around it. That is done here in place (the result is never
		// longer than what it replaces), and so that parsing the same
		// bytes again gives the same result (a head past a loop's limits
		// is parsed a second time, errRespBig): what a join leaves behind
		// becomes white space at the end of a line, and an empty
		// continuation line is left as it is.
		empty := 0 // empty continuation lines not joined yet: one space each
		for p < len(head) && (head[p] == ' ' || head[p] == '\t') {
			ce, cnext := respLineEnd(head, p)
			cs := p
			for cs < ce && (head[cs] == ' ' || head[cs] == '\t') {
				cs++
			}
			for ce > cs && (head[ce-1] == ' ' || head[ce-1] == '\t') {
				ce--
			}
			p = cnext
			if cs == ce {
				empty++
				continue
			}
			for ; empty >= 0; empty-- {
				head[w] = ' '
				w++
			}
			empty = 0
			n := copy(head[w:], head[cs:ce])
			w += n
			for i := w; i < ce; i++ {
				head[i] = ' '
			}
		}
		// trail: the value as net/http holds it ends in white space (an
		// empty continuation line came last). It is gone when the value
		// is written on, but the checks net/http makes on the value as
		// read see it.
		trail := empty > 0
		name := head[ls : ls+colon]
		v := head[ls+colon+1 : w]
		skip := false
		for _, c := range name {
			if isTchar[c] {
				continue
			}
			if c == ' ' {
				// net/http reads a name with a space in it (go.dev/issue/34540)
				// but never writes it on: the field is dropped.
				skip = true
				continue
			}
			return false, respError("header name")
		}
		for _, c := range v {
			if !isValueChar[c] {
				return false, respError("header value")
			}
		}
		if skip {
			continue
		}
		v = trimOWS(v)
		if len(h.headers) == len(h.hbuf) && !h.big {
			return false, errRespBig
		}
		k := headerKind(name)
		drop := hopByHop(k)
		switch k {
		case hkContentLength:
			if !sawCL {
				n, ok := parseRespContentLength(v)
				if !ok {
					return false, respError("content-length")
				}
				sawCL, cl0, h.contentLength = true, v, n
			} else {
				// Repeated with the same text, it is one field; with any
				// other text the response is refused.
				if !bytes.Equal(v, cl0) {
					return false, respError("conflicting content-length")
				}
				drop = true
			}
		case hkTransferEncoding:
			// Before HTTP/1.1 the field means nothing and is ignored.
			if atLeast11 {
				if chunked || trail || !equalFoldLower(v, "chunked") {
					return false, respError("transfer-encoding")
				}
				chunked = true
			}
		case hkConnection:
			for vv := v; len(vv) > 0; {
				var tok []byte
				if i := bytes.IndexByte(vv, ','); i >= 0 {
					tok, vv = vv[:i], vv[i+1:]
				} else {
					tok, vv = vv, nil
				}
				tok = trimOWS(tok)
				switch {
				case len(tok) == 0:
				case equalFoldLower(tok, "close"):
					h.connClose = true
				case equalFoldLower(tok, "keep-alive"):
					keepAlive = true
				default:
					if len(h.connNames) == len(h.cbuf) && !h.big {
						return false, errRespBig
					}
					h.connNames = append(h.connNames, tok)
				}
			}
		case hkTrailer:
			for vv := v; len(vv) > 0; {
				var tok []byte
				if i := bytes.IndexByte(vv, ','); i >= 0 {
					tok, vv = vv[:i], vv[i+1:]
				} else {
					tok, vv = vv, nil
				}
				tok = trimOWS(tok)
				if equalFoldLower(tok, "transfer-encoding") || equalFoldLower(tok, "trailer") || equalFoldLower(tok, "content-length") {
					badTrailer = true
				}
			}
		case hkOther:
			switch len(name) {
			case 6:
				if !sawPragma && equalFoldLower(name, "pragma") {
					sawPragma, pragmaNC = true, !trail && string(v) == "no-cache"
				}
			case 13:
				if equalFoldLower(name, "cache-control") {
					sawCC = true
				}
			}
		}
		h.headers = append(h.headers, fastHeader{name: name, value: v, kind: k, drop: drop})
	}
	if pragmaNC && !sawCC {
		// net/http reads "Pragma: no-cache" without a Cache-Control field
		// as "Cache-Control: no-cache", and passes that field on.
		if len(h.headers) == len(h.hbuf) && !h.big {
			return false, errRespBig
		}
		h.headers = append(h.headers, fastHeader{name: hdrCacheControl, value: valNoCache})
	}
	if chunked && badTrailer {
		// A chunked response cannot announce a framing field as a
		// trailer (net/http: "bad trailer key").
		return false, respError("bad trailer key")
	}
	h.n = len(h.headers)
	h.chunked = chunked
	h.dropNamed()
	switch {
	case isHead || (h.status >= 100 && h.status < 200) || h.status == 204 || h.status == 304:
		h.framing = bodyNone
	case chunked:
		h.framing = bodyChunked
		h.contentLength = -1
	case h.contentLength >= 0:
		h.framing = bodyLength
	default:
		h.framing = bodyClose
	}
	// The backend's connection: from 1.1 on it stays unless it says close;
	// 1.0 must ask to keep it; older is one response per connection.
	switch {
	case major < 1:
		h.connClose = true
	case !atLeast11:
		h.connClose = h.connClose || !keepAlive
	}
	return true, nil
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

var (
	hdrCacheControl = []byte("Cache-Control")
	valNoCache      = []byte("no-cache")
)

// dropNamed marks the fields the Connection header names as hop-by-hop.
// Names match as net/http's Header.Del matches them: only the case of ASCII
// letters is ignored.
func (h *respHead) dropNamed() {
	if len(h.connNames) <= len(h.cbuf) {
		for _, cn := range h.connNames {
			for j := range h.headers {
				if asciiEqualFold(h.headers[j].name, cn) {
					h.headers[j].drop = true
				}
			}
		}
		return
	}
	// Many names (a big head only): one pass over the fields against a
	// set, never names × fields.
	set := make(map[string]struct{}, len(h.connNames))
	var lower []byte
	for _, cn := range h.connNames {
		lower = appendLowerASCII(lower[:0], cn)
		set[string(lower)] = struct{}{}
	}
	for j := range h.headers {
		lower = appendLowerASCII(lower[:0], h.headers[j].name)
		if _, ok := set[string(lower)]; ok {
			h.headers[j].drop = true
		}
	}
}

// asciiEqualFold reports whether a and b are equal when the case of ASCII
// letters is ignored.
func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x == y {
			continue
		}
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// appendLowerASCII appends p to dst with its ASCII letters in lower case.
func appendLowerASCII(dst, p []byte) []byte {
	for _, c := range p {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

var (
	lfcrlf = []byte("\n\r\n")
	lflf   = []byte("\n\n")
)

// respHeadEnd returns the length of the response head at the start of b,
// through the empty line that ends it, or -1 when it is not complete; the
// search starts near from. A line ends in LF, with or without a CR before
// it (net/http's reader).
func respHeadEnd(b []byte, from int) int {
	p := max(0, from-3)
	// The head ends at the first empty line: "\n\r\n" (CRLF lines, the
	// usual case: the search stops there) or "\n\n" (bare LF), whichever
	// comes first, so the bare-LF search only covers what precedes.
	end := -1
	limit := len(b)
	if i := bytes.Index(b[p:], lfcrlf); i >= 0 {
		end = p + i + 3
		limit = p + i + 1
	}
	if i := bytes.Index(b[p:limit], lflf); i >= 0 {
		end = p + i + 2
	}
	return end
}

// respLineEnd returns the end of the line starting at p in a complete
// response head (its CR or LF) and the start of the next line.
func respLineEnd(head []byte, p int) (end, next int) {
	i := bytes.IndexByte(head[p:], '\n')
	if i < 0 {
		return len(head), len(head)
	}
	i += p
	end = i
	if end > p && head[end-1] == '\r' {
		end--
	}
	return end, i + 1
}

// chunkReader decodes a chunked body incrementally.
type chunkReader struct {
	state   int
	remain  int64 // data bytes left in the current chunk
	sizeLen int   // hex digits seen
	extLen  int   // bytes of the current size line
	trailer []byte
	// excess counts framing bytes that carry little data, as net/http's
	// chunked reader does: a size line (with its extensions) adds its
	// length, a chunk takes off 16 plus twice its size. Past 16 KiB the
	// body is refused: a backend cannot make the proxy read framing for
	// ever at next to no data.
	excess int64
}

const (
	ckSize      = iota // reading the chunk-size line
	ckData             // reading chunk data
	ckDataCR           // expecting CR after data
	ckDataLF           // expecting LF after data
	ckTrailer          // reading trailer lines
	ckDone             // final CRLF seen
	ckSizeLF           // after CR in the size line
	ckExt              // in a chunk extension
	ckTrailerLF        // after CR of a trailer line
)

// maxChunkLine bounds a chunk-size line (with extensions); maxTrailer the
// trailer section.
const (
	maxChunkLine = 4096
	maxTrailer   = 16 << 10
)

// next consumes chunked framing from b up to the next run of chunk data.
// It returns that data's position, b[off:off+n] (n may be 0), how many bytes
// of b it consumed (framing and data), and whether the body ended (then
// b[used:] follows the body).
func (c *chunkReader) next(b []byte) (off, n, used int, done bool, err error) {
	i := 0
	for i < len(b) {
		switch c.state {
		case ckSize:
			ch := b[i]
			switch {
			case unhex(ch) >= 0:
				if c.sizeLen == 15 {
					return 0, 0, i, false, respError("chunk size")
				}
				c.remain = c.remain<<4 | int64(unhex(ch))
				c.sizeLen++
			case ch == ';' && c.sizeLen > 0:
				c.state = ckExt
			case ch == '\r' && c.sizeLen > 0:
				c.state = ckSizeLF
			case (ch == ' ' || ch == '\t') && c.sizeLen > 0:
				c.state = ckExt // BWS before an extension
			default:
				return 0, 0, i, false, respError("chunk size")
			}
			c.extLen++
			i++
		case ckExt:
			ch := b[i]
			if ch == '\r' {
				c.state = ckSizeLF
			} else if !isValueChar[ch] {
				return 0, 0, i, false, respError("chunk extension")
			}
			c.extLen++
			if c.extLen > maxChunkLine {
				return 0, 0, i, false, respError("chunk line")
			}
			i++
		case ckSizeLF:
			if b[i] != '\n' {
				return 0, 0, i, false, respError("chunk size")
			}
			i++
			// extLen counted the line and its CR; net/http counts the
			// line and the CRLF that follows the chunk's data.
			c.excess += int64(c.extLen) + 1
			c.excess -= 16 + 2*c.remain
			if c.excess < 0 {
				c.excess = 0
			}
			if c.excess > 16<<10 {
				return 0, 0, i, false, errChunkExcess
			}
			c.sizeLen, c.extLen = 0, 0
			if c.remain == 0 {
				c.state = ckTrailer
				c.trailer = c.trailer[:0]
			} else {
				c.state = ckData
			}
		case ckData:
			n := int64(len(b) - i)
			if n > c.remain {
				n = c.remain
			}
			c.remain -= n
			if c.remain == 0 {
				c.state = ckDataCR
			}
			return i, int(n), i + int(n), false, nil
		case ckDataCR:
			if b[i] != '\r' {
				return 0, 0, i, false, respError("chunk data")
			}
			c.state = ckDataLF
			i++
		case ckDataLF:
			if b[i] != '\n' {
				return 0, 0, i, false, respError("chunk data")
			}
			c.state = ckSize
			i++
		case ckTrailer:
			// Trailer lines, then an empty line.
			ch := b[i]
			i++
			if ch == '\r' {
				c.state = ckTrailerLF
				continue
			}
			if ch == '\n' {
				return 0, 0, i, false, respError("trailer")
			}
			c.trailer = append(c.trailer, ch)
			if len(c.trailer) > maxTrailer {
				return 0, 0, i, false, respError("trailer too large")
			}
		case ckTrailerLF:
			if b[i] != '\n' {
				return 0, 0, i, false, respError("trailer")
			}
			i++
			if n := len(c.trailer); n == 0 || (n >= 2 && c.trailer[n-2] == '\r' && c.trailer[n-1] == '\n') {
				c.state = ckDone
				return 0, 0, i, true, nil
			}
			c.trailer = append(c.trailer, '\r', '\n')
			c.state = ckTrailer
		case ckDone:
			return 0, 0, i, true, nil
		}
	}
	return 0, 0, i, c.state == ckDone, nil
}

// trailerLines returns the trailer section read (lines ending in CRLF, no
// final empty line), validated like header lines.
func (c *chunkReader) trailerLines() ([]byte, bool) {
	t := c.trailer
	for p := 0; p < len(t); {
		e := bytes.Index(t[p:], []byte("\r\n"))
		if e < 0 {
			return nil, false
		}
		line := t[p : p+e]
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, false
		}
		for _, ch := range line[:colon] {
			if !isTchar[ch] {
				return nil, false
			}
		}
		for _, ch := range line[colon+1:] {
			if !isValueChar[ch] {
				return nil, false
			}
		}
		p += e + 2
	}
	return t, true
}

func (c *chunkReader) reset() {
	c.state, c.remain, c.sizeLen, c.extLen, c.excess = ckSize, 0, 0, 0, 0
	c.trailer = c.trailer[:0]
}

// errChunkExcess has the text of net/http's error for the same body (it is
// logged like net/http's).
var errChunkExcess = errors.New("chunked encoding contains too much non-data")

// appendChunkHeader appends the size line of an n-byte chunk.
func appendChunkHeader(b []byte, n int) []byte {
	b = strconv.AppendInt(b, int64(n), 16)
	return append(b, '\r', '\n')
}
