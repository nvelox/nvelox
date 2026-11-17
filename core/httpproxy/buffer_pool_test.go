package httpproxy

import (
	"net/http/httputil"
	"testing"
)

// TestSharedBuffers_HandsOutWholeBuffers: Get always returns a whole
// copyBufferSize buffer, whatever was put back before.
func TestSharedBuffers_HandsOutWholeBuffers(t *testing.T) {
	var pool httputil.BufferPool = sharedBuffers{}
	check := func(what string) {
		t.Helper()
		for range 8 {
			if b := pool.Get(); len(b) != copyBufferSize || cap(b) != copyBufferSize {
				t.Fatalf("%s: Get returned len %d cap %d, want %d", what, len(b), cap(b), copyBufferSize)
			}
		}
	}
	check("fresh")

	// Not buffers of the pool: dropped.
	pool.Put(nil)
	pool.Put(make([]byte, 100))
	pool.Put(make([]byte, copyBufferSize+1)[:copyBufferSize])
	pool.Put(make([]byte, copyBufferSize)[1:])
	check("after foreign slices were put")

	// A buffer of the pool comes back whole, however it was sliced.
	pool.Put(pool.Get()[:10])
	check("after a short slice of a buffer was put")
}

// TestSharedBuffers_ReusesBuffers: a buffer put back is handed out again.
func TestSharedBuffers_ReusesBuffers(t *testing.T) {
	var pool httputil.BufferPool = sharedBuffers{}
	// sync.Pool may drop a buffer (it does so at random under the race
	// detector, and when the goroutine changes threads in between): one
	// reuse in many tries is what is asked.
	for range 1000 {
		b := pool.Get()
		pool.Put(b)
		c := pool.Get()
		same := &b[0] == &c[0]
		pool.Put(c)
		if same {
			return
		}
	}
	t.Fatal("1000 buffers were put back and none was handed out again")
}

// TestSharedBuffers_GetPutDoNotAllocate: taking a buffer and putting it back
// costs no allocation, so a proxied response pays nothing for its copy
// buffer. (A sync.Pool of slices would allocate a slice header on every
// Put.)
func TestSharedBuffers_GetPutDoNotAllocate(t *testing.T) {
	var pool httputil.BufferPool = sharedBuffers{}
	// The race detector makes sync.Pool drop one Put in four; the buffer
	// then allocated on the next Get is a fraction of an allocation per
	// run, which AllocsPerRun rounds down.
	if n := testing.AllocsPerRun(1000, func() { pool.Put(pool.Get()) }); n != 0 {
		t.Fatalf("Get and Put allocate %v times per response, want 0", n)
	}
}

// BenchmarkBufferPools is one Get and Put, what ReverseProxy does per
// response: on the shared pool, and on a listener's own
// buffering.response_buffer pool.
func BenchmarkBufferPools(b *testing.B) {
	for _, bc := range []struct {
		name string
		pool httputil.BufferPool
	}{
		{"shared", sharedBuffers{}},
		{"response_buffer", NewBufferPool(copyBufferSize)},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				bc.pool.Put(bc.pool.Get())
			}
		})
	}
}
