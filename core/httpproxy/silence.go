package httpproxy

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"nvelox/config"
)

// backendSilenceLimit is backend be's timeouts.read: the longest it may stay
// silent once it has started answering. 0 (unset, or "0"): no limit.
func backendSilenceLimit(be *config.Backend) time.Duration {
	if be == nil {
		return 0
	}
	return max(be.Timeouts.ParseRead(), 0)
}

// silenceBody ends a backend's response when the backend sends nothing for
// limit while nvelox waits to read from it. Only that wait counts: while
// nvelox is writing to a slow client no read is pending, and a backend
// that has to wait for the client is not silent.
type silenceBody struct {
	io.ReadCloser
	limit  time.Duration
	server string
	timer  *time.Timer
	fired  atomic.Bool
}

func newSilenceBody(rc io.ReadCloser, limit time.Duration, server string) *silenceBody {
	b := &silenceBody{ReadCloser: rc, limit: limit, server: server}
	b.timer = time.AfterFunc(limit, b.expire)
	b.timer.Stop()
	return b
}

// expire closes the body under the read waiting on it, which ends that read
// with an error.
func (b *silenceBody) expire() {
	b.fired.Store(true)
	_ = b.ReadCloser.Close()
}

func (b *silenceBody) Read(p []byte) (int, error) {
	b.timer.Reset(b.limit)
	n, err := b.ReadCloser.Read(p)
	b.timer.Stop()
	if err != nil && err != io.EOF && b.fired.Load() {
		// ReverseProxy logs it ("read error during body copy") and aborts
		// the response.
		err = fmt.Errorf("backend server %s sent nothing for %v (its timeouts.read)", b.server, b.limit)
	}
	return n, err
}

func (b *silenceBody) Close() error {
	b.timer.Stop()
	return b.ReadCloser.Close()
}
