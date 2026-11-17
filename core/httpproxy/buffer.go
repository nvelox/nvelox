package httpproxy

import (
	"sync"
)

// BufferPool implements httputil.BufferPool using sync.Pool.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a buffer pool with the given buffer size.
func NewBufferPool(size int) *BufferPool {
	if size <= 0 {
		size = 32 * 1024 // 32KB default
	}
	return &BufferPool{
		size: size,
		pool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, size)
				return b
			},
		},
	}
}

// Get returns a buffer from the pool.
func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

// Put returns a buffer to the pool.
func (bp *BufferPool) Put(b []byte) {
	bp.pool.Put(b)
}

// copyBufferSize is the size of the buffer a response body is copied through
// on a listener that sets no buffering.response_buffer. It is the size
// httputil.ReverseProxy allocates for every response when it has no pool, so
// a response is read and written in the same pieces as before.
const copyBufferSize = 32 * 1024

// copyBufPool holds those buffers for the whole process. It keeps pointers
// to arrays, as net/http does for its own copy buffers: a pointer goes into
// a sync.Pool and comes out of it without an allocation, while a slice costs
// one for its header on every Put.
var copyBufPool = sync.Pool{New: func() any { return new([copyBufferSize]byte) }}

// sharedBuffers is the httputil.BufferPool over copyBufPool. Every site
// without a BufferPool of its own copies its response bodies through it.
//
// ReverseProxy takes a buffer for one body copy and puts it back when the
// copy has returned, also when the copy panicked. The copy writes only the
// bytes it has just read into the buffer, and nothing looks at the buffer
// once the Write that carried them has returned: the cache and the
// compressor keep copies, and the HTTP/1, HTTP/2 and HTTP/3 servers have
// copied or sent the bytes by then, also when the Write failed because the
// client went away. So a buffer that is back can go to the next response, of
// any site. A protocol switch (WebSocket) does not copy through a pool.
type sharedBuffers struct{}

func (sharedBuffers) Get() []byte {
	return copyBufPool.Get().(*[copyBufferSize]byte)[:]
}

// Put takes back a buffer Get handed out. Anything else is dropped: the
// pool only ever holds whole buffers of copyBufferSize.
func (sharedBuffers) Put(b []byte) {
	if cap(b) != copyBufferSize {
		return
	}
	copyBufPool.Put((*[copyBufferSize]byte)(b[:copyBufferSize]))
}
