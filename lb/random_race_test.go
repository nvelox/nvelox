package lb

import (
	"sync"
	"testing"
)

// TestRandom_ConcurrentNext (Low): Next / NextExcluding run under the read
// lock; the shared *rand.Rand they used was not safe for concurrent use
// (the race detector flags it). math/rand/v2's top-level functions are.
func TestRandom_ConcurrentNext(t *testing.T) {
	b := NewRandom([]string{"a:1", "b:1", "c:1"})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				b.Next()
				b.NextExcluding([]string{"a:1"})
			}
		}()
	}
	wg.Wait()
}
