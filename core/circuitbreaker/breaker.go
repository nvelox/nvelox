package circuitbreaker

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	StateClosed   int32 = 0
	StateOpen     int32 = 1
	StateHalfOpen int32 = 2
)

// Breaker implements the circuit breaker pattern per backend.
//
// Concurrency model: `state` and `failures` are accessed with sync/atomic for
// the fast-path (e.g. `State()`, `Failures()` observers). All state
// transitions (threshold crossing, timeout→half-open, half-open→closed/open)
// happen under `mu`. This makes transitions linearizable — two concurrent
// RecordFailure calls at the threshold can't produce torn state between
// `state` and `lastFail`; two concurrent Allow() calls in HalfOpen can't
// both see a stale halfOpenCnt.
type Breaker struct {
	// Fast-path atomics.
	state    atomic.Int32
	failures atomic.Int64

	// Transition-path fields, all guarded by mu.
	mu          sync.Mutex
	threshold   int
	timeout     time.Duration
	halfOpenMax int
	halfOpenCnt int64
	lastFail    time.Time
	// lastProbe is when the most recent half-open probe slot was handed out.
	// A probe whose request never reports back (RecordSuccess / RecordFailure
	// / Release) would otherwise hold its slot forever and wedge the breaker
	// in half-open; Allow frees the slots once no probe was handed out for
	// a whole timeout.
	lastProbe time.Time
}

// New creates a circuit breaker.
func New(threshold int, timeout time.Duration, halfOpenMax int) *Breaker {
	if halfOpenMax <= 0 {
		halfOpenMax = 1
	}
	return &Breaker{
		threshold:   threshold,
		timeout:     timeout,
		halfOpenMax: halfOpenMax,
	}
}

// Allow returns true if the request should proceed.
//
// Fast path: Closed state reads atomic.state and returns true without
// acquiring the mutex. Slow path: Open and HalfOpen acquire mu so the
// state/counter check is atomic with respect to transitions.
func (b *Breaker) Allow() bool {
	// Fast path: closed → no coordination needed.
	if b.state.Load() == StateClosed {
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Re-load state under lock: it may have changed since the Load above.
	switch b.state.Load() {
	case StateClosed:
		return true
	case StateOpen:
		if time.Since(b.lastFail) > b.timeout {
			// Transition to half-open. This request is the first probe, so
			// seed halfOpenCnt=1 BEFORE flipping state — under the mutex no
			// concurrent Allow() can observe the new state with the old count.
			b.halfOpenCnt = 1
			b.lastProbe = time.Now()
			b.state.Store(StateHalfOpen)
			return true
		}
		return false
	case StateHalfOpen:
		// Watchdog: every slot is taken but no probe was handed out for a
		// whole timeout, so the probes holding them never reported back
		// (a caller path that neither recorded nor released). Reclaim them
		// rather than refusing every request from now on.
		if b.halfOpenCnt >= int64(b.halfOpenMax) && time.Since(b.lastProbe) > b.timeout {
			b.halfOpenCnt = 0
		}
		if b.halfOpenCnt < int64(b.halfOpenMax) {
			b.halfOpenCnt++
			b.lastProbe = time.Now()
			return true
		}
		return false
	}
	return true
}

// Release gives back an Allow() that ended without a backend outcome: the
// request was never sent, or it failed for a reason that says nothing about
// the backend (the client went away, its body was too large, ...). In
// half-open it frees the probe slot so another request can probe; in the
// other states there is nothing to give back.
func (b *Breaker) Release() {
	if b.state.Load() != StateHalfOpen {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state.Load() == StateHalfOpen && b.halfOpenCnt > 0 {
		b.halfOpenCnt--
	}
}

// RecordSuccess records a successful request.
func (b *Breaker) RecordSuccess() {
	// Fast path: closed + failures==0 is the overwhelmingly common case;
	// avoid acquiring the mutex on every success.
	if b.state.Load() == StateClosed && b.failures.Load() == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state.Load() {
	case StateHalfOpen:
		// Success probe → close the circuit.
		b.failures.Store(0)
		b.halfOpenCnt = 0
		b.state.Store(StateClosed)
	case StateClosed:
		b.failures.Store(0)
	}
}

// RecordFailure records a failed request.
func (b *Breaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.state.Load() {
	case StateHalfOpen:
		// Failure during recovery probe → re-open.
		b.lastFail = time.Now()
		b.halfOpenCnt = 0
		b.state.Store(StateOpen)
	case StateClosed:
		fails := b.failures.Add(1)
		if int(fails) >= b.threshold {
			b.lastFail = time.Now()
			b.state.Store(StateOpen)
		}
	case StateOpen:
		// Already open — refresh lastFail so the timeout window slides forward
		// when failures continue. This matches the "hold open while failures
		// continue" behaviour most CB implementations use.
		b.lastFail = time.Now()
	}
}

// State returns the current state as a string.
func (b *Breaker) State() string {
	switch b.state.Load() {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Failures returns the current failure count.
func (b *Breaker) Failures() int {
	return int(b.failures.Load())
}
