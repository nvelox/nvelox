package httpproxy

import "bytes"

// An HTTP/2 request head, from the fields of its header block to the
// reqHead the fast path serves. The rules of a header block are those of
// Go's HTTP/2 server (net/http/internal/http2, readMetaFrame and
// checkPseudos), so that a block is accepted, refused or answered 431 here
// exactly when it is there.

const (
	// h2MaxHeaderList is the largest header list of a request, as HTTP/2
	// counts it (name + value + 32 per field): net/http's default
	// MaxHeaderBytes plus its allowance for ten fields.
	h2MaxHeaderList = 1<<20 + 320
	// h2MaxFields is the largest number of fields of a header block
	// (net/http's DefaultMaxHeaderValueCount).
	h2MaxFields = 500
	// h2FieldOverhead is what a field counts besides its name and value.
	h2FieldOverhead = 32
)

// h2Field is one field of a header block: where its name and value are in
// the block's arena.
type h2Field struct {
	name, nameEnd, valueEnd uint32 // the value starts at nameEnd
}

// h2Block is a header block being decoded: its fields, in order, and what
// Go's reader keeps about it.
type h2Block struct {
	arena  []byte
	fields []h2Field

	remain, remainTrailer uint32 // what is left of the two size budgets
	count, countTrailer   int
	sawRegular            bool
	// invalid: a field broke a rule (a value with a control byte, a
	// pseudo-header after a regular field, a name that is not a lower-case
	// token). The request is refused with a stream error at the block's
	// end; no field after it is kept.
	invalid bool
	// truncated: the list passed a budget or the count limit. No field
	// after that is kept, and the request is answered 431.
	truncated bool
}

// reset starts a new block of an HTTP/2 request.
func (b *h2Block) reset() { b.resetLimit(h2MaxHeaderList) }

// resetLimit starts a new block whose header list may be limit long.
func (b *h2Block) resetLimit(limit uint32) {
	b.arena, b.fields = b.arena[:0], b.fields[:0]
	b.remain, b.remainTrailer = limit, limit
	b.count, b.countTrailer = 0, 0
	b.sawRegular, b.invalid, b.truncated = false, false, false
}

// budget is what Go's reader compares a fragment's length against: a
// fragment longer than twice this is not decoded at all.
func (b *h2Block) budget() uint64 { return uint64(b.remain) + uint64(b.remainTrailer) }

func (b *h2Block) fieldName(i int) []byte {
	f := &b.fields[i]
	return b.arena[f.name:f.nameEnd:f.nameEnd]
}

func (b *h2Block) fieldValue(i int) []byte {
	f := &b.fields[i]
	return b.arena[f.nameEnd:f.valueEnd:f.valueEnd]
}

// add takes the next decoded field (the HPACK decoder's emit).
func (b *h2Block) add(name, value []byte) {
	if b.invalid || b.truncated {
		return
	}
	for _, c := range value {
		if !isValueChar[c] {
			b.invalid = true
			return
		}
	}
	if len(name) > 0 && name[0] == ':' {
		if b.sawRegular {
			b.invalid = true
			return
		}
	} else {
		b.sawRegular = true
		if !h2ValidName(name) {
			b.invalid = true
			return
		}
	}
	var size uint32
	var over bool
	if string(name) == "trailer" {
		// The names a trailer field announces have their own budget, each
		// counted as a field.
		n := bytes.Count(value, comma) + 1
		b.countTrailer += n
		size = uint32(len(value)-n+1) + uint32(n)*h2FieldOverhead
		over = b.countTrailer > h2MaxFields || size > b.remainTrailer
		if !over {
			b.remainTrailer -= size
		}
	} else {
		b.count++
		size = uint32(len(name)) + uint32(len(value)) + h2FieldOverhead
		over = b.count > h2MaxFields || size > b.remain
		if !over {
			b.remain -= size
		}
	}
	if over {
		b.truncated = true
		b.remain, b.remainTrailer = 0, 0
		return
	}
	at := uint32(len(b.arena))
	b.arena = append(append(b.arena, name...), value...)
	b.fields = append(b.fields, h2Field{name: at, nameEnd: at + uint32(len(name)), valueEnd: at + uint32(len(name)) + uint32(len(value))})
}

var comma = []byte(",")

// h2ValidName reports whether name may be a regular field's name on the
// wire: a token without upper-case letters.
func h2ValidName(name []byte) bool {
	if len(name) == 0 {
		return false
	}
	for _, c := range name {
		if !isTchar[c] || 'A' <= c && c <= 'Z' {
			return false
		}
	}
	return true
}

// Pseudo-header bits.
const (
	h2pMethod = 1 << iota
	h2pScheme
	h2pPath
	h2pAuthority
	h2pProtocol
	h2pStatus
)

// pseudos lists the pseudo-header fields of the block. ok is false when
// the set is malformed as checkPseudos has it: an unknown name, one name
// twice, or request and response names together.
func (b *h2Block) pseudos() (set int, ok bool) {
	for i := range b.fields {
		name := b.fieldName(i)
		if name[0] != ':' {
			break
		}
		var bit int
		switch string(name) {
		case ":method":
			bit = h2pMethod
		case ":scheme":
			bit = h2pScheme
		case ":path":
			bit = h2pPath
		case ":authority":
			bit = h2pAuthority
		case ":protocol":
			bit = h2pProtocol
		case ":status":
			bit = h2pStatus
		default:
			return 0, false
		}
		if set&bit != 0 {
			return 0, false
		}
		set |= bit
	}
	if set&h2pStatus != 0 && set&^h2pStatus != 0 {
		return 0, false
	}
	return set, true
}

var h2Host = []byte("Host")

// fastRequest builds in h the head of the request the block carries, when
// it is one the event loops serve; endStream says that no body follows. It
// reports false for every other request: those are answered as Go's server
// answers them (a refusal, a 400, a 431, or the handler through net/http).
//
// The loops take a request with a method other than CONNECT, an http or
// https scheme, a path the HTTP/1.1 engine takes, its host in :authority
// (or in one host field), at most the HTTP/1.1 engine's number of fields
// and bytes, no field an HTTP/2 request must not carry, no announced
// trailers, no Expect, and a body only with a Content-Length that says how
// long it is.
//
// The fields' names are rewritten in place the way net/http names them
// (Content-Type for content-type), which is how the backend has always
// received them. h points into the block's arena.
func (b *h2Block) fastRequest(h *reqHead, endStream bool) bool {
	if b.invalid || b.truncated || len(b.arena) > maxFastRequestHead {
		return false
	}
	var method, scheme, path, authority []byte
	i := 0
	for ; i < len(b.fields); i++ {
		name := b.fieldName(i)
		if name[0] != ':' {
			break
		}
		v := b.fieldValue(i)
		switch string(name) {
		case ":method":
			method = v
		case ":scheme":
			scheme = v
		case ":path":
			path = v
		case ":authority":
			authority = v
		default:
			return false
		}
	}
	if len(method) == 0 || string(method) == "CONNECT" || string(method) == "PRI" {
		return false
	}
	for _, c := range method {
		if !isTchar[c] {
			return false
		}
	}
	if string(scheme) != "https" && string(scheme) != "http" {
		return false
	}
	if len(path) == 0 || path[0] != '/' {
		return false
	}
	h.method, h.target = method, path
	if !splitTarget(h) {
		return false
	}
	h.resetFields()
	h.headLen = 0
	if len(authority) > 0 && !h.addField(h2Host, authority) {
		return false
	}
	cookieAt, joined := -1, 0
	for ; i < len(b.fields); i++ {
		name, v := b.fieldName(i), b.fieldValue(i)
		if len(v) > 0 && (v[0] == ' ' || v[0] == '\t' || v[len(v)-1] == ' ' || v[len(v)-1] == '\t') {
			// net/http's handlers see the value with these spaces and its
			// transport sends it without them.
			return false
		}
		switch headerKind(name) {
		case hkConnection, hkKeepAlive, hkProxyConnection, hkTransferEncoding, hkUpgrade, hkTrailer, hkExpect:
			return false
		case hkTE:
			if h.teTrailers || string(v) != "trailers" {
				return false
			}
		case hkHost:
			if len(authority) > 0 {
				return false // both :authority and host
			}
		case hkCookie:
			// Cookie fields are one header to the backend, joined with "; ".
			if cookieAt >= 0 {
				if joined == 0 {
					joined = len(b.arena)
					b.arena = append(b.arena, h.headers[cookieAt].value...)
				}
				b.arena = append(append(b.arena, "; "...), v...)
				h.headers[cookieAt].value = b.arena[joined:]
				continue
			}
			cookieAt = h.n
		}
		canonicalName(name)
		if !h.addField(name, v) {
			return false
		}
	}
	if !h.endFields() {
		return false
	}
	if endStream {
		return h.contentLength <= 0
	}
	return h.contentLength > 0
}

// canonicalName rewrites a lower-case field name in place as
// textproto.CanonicalMIMEHeaderKey returns it: the first letter and every
// letter after a hyphen in upper case.
func canonicalName(name []byte) {
	upper := true
	for i, c := range name {
		if upper && 'a' <= c && c <= 'z' {
			name[i] = c - ('a' - 'A')
		}
		upper = c == '-'
	}
}
