package core

// ConnLimiter limits concurrent connections to a backend using a buffered channel semaphore.
type ConnLimiter struct {
	sem chan struct{}
	max int
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

// Release releases a slot.
func (cl *ConnLimiter) Release() {
	select {
	case <-cl.sem:
	default:
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
