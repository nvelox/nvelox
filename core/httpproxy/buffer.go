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
