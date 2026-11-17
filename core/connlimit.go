package core

import (
	"sync/atomic"

	"nvelox/core/logging"
)

// ConnLimiter limits concurrent connections to a backend using a buffered
// channel semaphore.
//
// The channel alone can't detect a Release without a prior Acquire — the
// receive hits the default branch and the bug goes silent until capacity
// drifts. We track acquireCount/releaseCount separately so over-release
// is observable (logged at WARN and reflected in OverReleaseCount()) and
// callers / tests can assert on it.
type ConnLimiter struct {
	sem               chan struct{}
	max               int
	overReleaseCount  atomic.Int64
}

// NewConnLimiter creates a limiter allowing up to max concurrent connections.
func NewConnLimiter(max int) *ConnLimiter {
	return &ConnLimiter{
		sem: make(chan struct{}, max),
		max: max,
	}
}

// Acquire tries to acquire a slot. Returns false if at capacity.
func (cl *ConnLimiter) Acquire() bool {
	select {
	case cl.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release releases a slot. Over-release (Release without a matching
// Acquire, or a double Release) is logged and counted via OverReleaseCount
// rather than silently ignored — which used to mask bugs that inflated
// effective capacity beyond max.
func (cl *ConnLimiter) Release() {
	select {
	case <-cl.sem:
	default:
		cl.overReleaseCount.Add(1)
		logging.Warn("[CONNLIMIT] Release() called with no outstanding Acquire (bug: total=%d)",
			cl.overReleaseCount.Load())
	}
}

// Active returns the number of active connections.
func (cl *ConnLimiter) Active() int {
	return len(cl.sem)
}

// Max returns the maximum allowed connections.
func (cl *ConnLimiter) Max() int {
	return cl.max
}

// OverReleaseCount reports the total number of Release calls that had no
// matching Acquire. Non-zero indicates a bug in error-path handling.
func (cl *ConnLimiter) OverReleaseCount() int64 {
	return cl.overReleaseCount.Load()
}
