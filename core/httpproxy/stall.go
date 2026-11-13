package httpproxy

import (
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// A listener's timeouts.read and timeouts.write limit how long a transfer
// with the client may be stuck, not how long it may take (nginx's
// client_body_timeout and send_timeout). The read limit runs only while
// nvelox waits for the next piece of the request body, the write limit only
// while it waits for the client to take a write of the response. A quiet
// event stream, or an upload or download that keeps moving, is never cut; a
// client that stops sending or reading is.
//
// Each deadline is set on the connection (HTTP/1) or the stream (HTTP/2,
// HTTP/3) right before a read or write and cleared right after it. A
// deadline left set would cut an idle stream: on HTTP/2 Go resets a stream
// when its write deadline passes, whether or not a write is waiting, and on
// HTTP/1 a read deadline that passes while net/http watches the connection
// for the client going away cancels the request.

// stallChunk bounds one ReadFrom step: each step of a long sendfile has to
// make progress within the write limit, not the whole file.
const stallChunk = 64 << 10

// stallLimits applies one site's read and write limits to one request.
type stallLimits struct {
	rc    *http.ResponseController // over the server's own writer
	read  time.Duration            // 0: no limit
	write time.Duration            // 0: no limit
	h1    bool                     // an HTTP/1 request
	body  *stallBody               // the request body under the read limit (nil: none)

	// mu serialises the deadline changes. done (set by finish) stops them:
	// a body read the transport completes after the handler returned must
	// not change the deadlines net/http sets for the connection's next
	// request. readBroken / writeBroken: a read or write failed, and from
	// then on that deadline is left as it is (endRead).
	mu                      sync.Mutex
	done                    bool
	readBroken, writeBroken bool
}

// newStallLimits returns site l's limits for request r answered on w, the
// server's own writer, or nil when both are off ("0").
func newStallLimits(w http.ResponseWriter, r *http.Request, l *ListenerConfig) *stallLimits {
	read, write := defaultReadTimeout, defaultWriteTimeout
	if l != nil {
		read = l.Timeouts.ResolveRead(defaultReadTimeout)
		write = l.Timeouts.ResolveWrite(defaultWriteTimeout)
	}
	if read <= 0 && write <= 0 {
		return nil
	}
	return &stallLimits{rc: http.NewResponseController(w), read: max(read, 0), write: max(write, 0), h1: r.ProtoMajor == 1}
}

// writer wraps w, the writer the handler writes to, so that every write
// runs under the write limit. It also guards the request body (see
// stallWriter.WriteHeader), so it wraps even when only the read limit is on.
func (l *stallLimits) writer(w http.ResponseWriter) http.ResponseWriter {
	return &stallWriter{ResponseWriter: w, l: l}
}

// wrapBody wraps a request body so that every read runs under the read
// limit.
func (l *stallLimits) wrapBody(b io.ReadCloser) io.ReadCloser {
	if l.read == 0 || b == nil || b == http.NoBody {
		return b
	}
	l.body = &stallBody{ReadCloser: b, l: l}
	return l.body
}

// unreadBody reports whether an HTTP/1 request body is still unread: net/http
// would read the rest of it before sending the response headers, to reuse
// the connection, and outside any read limit.
func (l *stallLimits) unreadBody() bool {
	return l.h1 && l.body != nil && !l.body.ended.Load()
}

// startRead sets the read deadline for one read.
func (l *stallLimits) startRead() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.done && !l.readBroken {
		_ = l.rc.SetReadDeadline(deadlineIn(l.read))
	}
}

// endRead clears the read deadline after a read that worked (err nil or
// io.EOF). After a failed read it is left as it is, for good: the transfer
// is broken, and whatever reads the connection again (net/http discarding
// the rest of the body) must fail at once, not wait for a client that
// stopped sending.
func (l *stallLimits) endRead(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.done || l.readBroken:
	case err == nil || err == io.EOF:
		_ = l.rc.SetReadDeadline(time.Time{})
	default:
		l.readBroken = true
	}
}

// startWrite sets the write deadline for one write.
func (l *stallLimits) startWrite() {
	if l.write == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.done && !l.writeBroken {
		_ = l.rc.SetWriteDeadline(deadlineIn(l.write))
	}
}

// endWrite is endRead for the write deadline.
func (l *stallLimits) endWrite(err error) {
	if l.write == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.done || l.writeBroken:
	case err == nil:
		_ = l.rc.SetWriteDeadline(time.Time{})
	default:
		l.writeBroken = true
	}
}

// finish ends the request's deadline changes and sets both limits once
// more: they bound what net/http still does after the handler returns
// (writing out the rest of the response, discarding an unread request body).
func (l *stallLimits) finish() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return
	}
	l.done = true
	if l.write > 0 && !l.writeBroken {
		_ = l.rc.SetWriteDeadline(deadlineIn(l.write))
	}
	if l.read > 0 && !l.readBroken {
		_ = l.rc.SetReadDeadline(deadlineIn(l.read))
	}
}

// deadlineIn is the deadline d from now; the zero time (no deadline) for 0.
func deadlineIn(d time.Duration) time.Time {
	if d <= 0 {
		return time.Time{}
	}
	return time.Now().Add(d)
}

// stallWriter runs every write to the client under the write limit.
type stallWriter struct {
	http.ResponseWriter
	l *stallLimits
}

// WriteHeader: an informational (1xx) response is written at once. A final
// response while the request body is unread closes the connection after it:
// net/http would otherwise read the rest of the body first, with no limit on
// how long the client may take (a client that announced a body and sends
// nothing would hold the request forever).
func (w *stallWriter) WriteHeader(code int) {
	switch {
	case code >= 100 && code < 200:
		w.l.startWrite()
		defer w.l.endWrite(nil)
	case w.l.unreadBody():
		w.Header().Set("Connection", "close")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *stallWriter) Write(b []byte) (int, error) {
	w.l.startWrite()
	n, err := w.ResponseWriter.Write(b)
	w.l.endWrite(err)
	return n, err
}

// FlushError is what http.ResponseController.Flush calls.
func (w *stallWriter) FlushError() error {
	w.l.startWrite()
	err := http.NewResponseController(w.ResponseWriter).Flush()
	w.l.endWrite(err)
	return err
}

func (w *stallWriter) Flush() { _ = w.FlushError() }

// ReadFrom keeps the server's sendfile path, one stallChunk at a time.
func (w *stallWriter) ReadFrom(src io.Reader) (int64, error) {
	rf, ok := w.ResponseWriter.(io.ReaderFrom)
	if !ok {
		return io.Copy(struct{ io.Writer }{w}, src)
	}
	// A *io.LimitedReader (what io.CopyN passes) is unwrapped, so that each
	// step is one LimitedReader over the file: sendfile looks through one.
	r, left := src, int64(-1) // left < 0: until src ends
	lr, limited := src.(*io.LimitedReader)
	if limited {
		r, left = lr.R, lr.N
	}
	var total int64
	for left != 0 {
		step := int64(stallChunk)
		if left > 0 && left < step {
			step = left
		}
		w.l.startWrite()
		n, err := rf.ReadFrom(&io.LimitedReader{R: r, N: step})
		w.l.endWrite(err)
		total += n
		if limited {
			lr.N -= n
		}
		if left > 0 {
			left -= n
		}
		if err != nil || n < step {
			return total, err
		}
	}
	return total, nil
}

// Unwrap lets http.ResponseController reach the server's writer (Hijack).
func (w *stallWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// stallBody runs every read of the request body under the read limit.
type stallBody struct {
	io.ReadCloser
	l     *stallLimits
	ended atomic.Bool // read to its end, or closed
}

func (b *stallBody) Read(p []byte) (int, error) {
	b.l.startRead()
	n, err := b.ReadCloser.Read(p)
	b.l.endRead(err)
	if err == io.EOF {
		b.ended.Store(true)
	}
	return n, err
}

// Close can read too: net/http discards what is left of the body, to reuse
// the connection. It runs under the read limit as well.
func (b *stallBody) Close() error {
	b.ended.Store(true)
	b.l.startRead()
	err := b.ReadCloser.Close()
	b.l.endRead(err)
	return err
}
