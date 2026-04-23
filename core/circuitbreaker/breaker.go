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
type Breaker struct {
	state       int32
	failures    int64
	threshold   int
	timeout     time.Duration
	halfOpenMax int
	halfOpenCnt int64
	lastFail    time.Time
	mu          sync.Mutex
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
func (b *Breaker) Allow() bool {
	state := atomic.LoadInt32(&b.state)

	switch state {
	case StateClosed:
		return true
	case StateOpen:
		b.mu.Lock()
		defer b.mu.Unlock()
		if time.Since(b.lastFail) > b.timeout {
			// Transition to half-open, this request counts as the first probe
			atomic.StoreInt32(&b.state, StateHalfOpen)
			atomic.StoreInt64(&b.halfOpenCnt, 1)
			return true
		}
		return false
	case StateHalfOpen:
		cnt := atomic.AddInt64(&b.halfOpenCnt, 1)
		return cnt <= int64(b.halfOpenMax)
	}
	return true
}

// RecordSuccess records a successful request.
func (b *Breaker) RecordSuccess() {
	state := atomic.LoadInt32(&b.state)
	if state == StateHalfOpen {
		// Success in half-open → close the circuit
		atomic.StoreInt32(&b.state, StateClosed)
		atomic.StoreInt64(&b.failures, 0)
	} else if state == StateClosed {
		atomic.StoreInt64(&b.failures, 0)
	}
}

// RecordFailure records a failed request.
func (b *Breaker) RecordFailure() {
	state := atomic.LoadInt32(&b.state)

	if state == StateHalfOpen {
		// Failure in half-open → open the circuit
		b.mu.Lock()
		b.lastFail = time.Now()
		b.mu.Unlock()
		atomic.StoreInt32(&b.state, StateOpen)
		return
	}

	fails := atomic.AddInt64(&b.failures, 1)
	if int(fails) >= b.threshold {
		b.mu.Lock()
		b.lastFail = time.Now()
		b.mu.Unlock()
		atomic.StoreInt32(&b.state, StateOpen)
	}
}

// State returns the current state as a string.
func (b *Breaker) State() string {
	switch atomic.LoadInt32(&b.state) {
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
	return int(atomic.LoadInt64(&b.failures))
}
