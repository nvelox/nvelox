package quic

// The handshake's bytes travel in CRYPTO frames, one stream of them per
// encryption level (RFC 9000, section 19.6; RFC 9001, section 4), and the
// application's in STREAM frames. Either way frames arrive in any order,
// more than once, and overlapping: a reassembly puts a stream of them back
// in order.

// CryptoWindow is how far beyond what has been delivered a level's CRYPTO
// stream may reach: data past it closes the connection with
// CRYPTO_BUFFER_EXCEEDED. A client's first flight is one or two packets; a
// client certificate chain is the largest thing a client sends here.
const CryptoWindow = 64 << 10

// cryptoMaxRanges bounds the separate pieces of a CRYPTO stream held out of
// order; streamMaxRanges those of an application stream, whose window is
// larger and whose packets a lossy path leaves more holes between.
const (
	cryptoMaxRanges = 32
	streamMaxRanges = 512
)

// reassembly puts the frames of one stream back in order. Data that
// arrives in order, which is nearly all of it, is handed on without a
// copy; the rest waits in a buffer that starts at the first byte not yet
// delivered.
type reassembly struct {
	next uint64 // every byte before this offset has been delivered
	// buf[at:] is the bytes from next on, with holes. What is in front of
	// at was delivered: it is dropped when it is as much as what is behind
	// it, so that a piece delivered costs its own length and not that of
	// everything that waits behind it (a client that fills a stream's
	// window with pieces and their holes from the front would otherwise
	// have the whole window moved once per piece).
	buf    []byte
	at     int
	ranges [][2]uint64 // the parts of the stream held in buf: [start, end), ascending, not touching
}

// push takes stream data at offset off and calls deliver with every piece
// that is now next in order (valid during the call only). The data may
// reach at most window bytes past what was delivered (the caller checks
// that before: a stream's flow control, or the CRYPTO window) and leave at
// most maxRanges separate pieces waiting: ok is false when it would leave
// more, and the data is then not taken.
func (c *reassembly) push(off uint64, data []byte, maxRanges int, deliver func([]byte)) (ok bool) {
	end := off + uint64(len(data))
	if end <= c.next {
		return true // all of it was delivered before
	}
	if off < c.next {
		data = data[c.next-off:]
		off = c.next
	}
	if off == c.next && len(c.ranges) == 0 {
		// In order and nothing waiting: straight through.
		c.next = end
		deliver(data)
		return true
	}
	// Where [off, end) goes among the ranges: i is the first range that
	// ends at or after off, j the first that starts after end. The ranges
	// i to j-1 touch or overlap the new data and are merged with it.
	i := 0
	for i < len(c.ranges) && c.ranges[i][1] < off {
		i++
	}
	j := i
	for j < len(c.ranges) && c.ranges[j][0] <= end {
		j++
	}
	if i == j && len(c.ranges) >= maxRanges {
		return false // one piece more than is kept
	}
	if need := int(end - c.next); len(c.buf)-c.at < need {
		if cap(c.buf)-c.at < need {
			nb := make([]byte, need, max(need, 2*(len(c.buf)-c.at), 4096))
			copy(nb, c.buf[c.at:])
			c.buf, c.at = nb, 0
		} else {
			c.buf = c.buf[:c.at+need]
		}
	}
	copy(c.buf[c.at+int(off-c.next):], data)
	if i == j {
		// A new piece between two others (or after the last).
		c.ranges = append(c.ranges, [2]uint64{})
		copy(c.ranges[i+1:], c.ranges[i:])
		c.ranges[i] = [2]uint64{off, end}
	} else {
		c.ranges[i] = [2]uint64{min(off, c.ranges[i][0]), max(end, c.ranges[j-1][1])}
		c.ranges = append(c.ranges[:i+1], c.ranges[j:]...)
	}
	if c.ranges[0][0] != c.next {
		return true // still a hole in front
	}
	// The first range is next in order: deliver it and move the window.
	n := int(c.ranges[0][1] - c.next)
	c.next += uint64(n)
	c.ranges = c.ranges[:copy(c.ranges, c.ranges[1:])]
	deliver(c.buf[c.at : c.at+n])
	if c.buf == nil {
		return true // let go of during the call
	}
	c.at += n
	switch {
	case len(c.ranges) == 0:
		c.buf, c.at = c.buf[:0], 0
	case c.at >= len(c.buf)-c.at:
		c.buf = c.buf[:copy(c.buf, c.buf[c.at:])]
		c.at = 0
	}
	return true
}

// release lets go of the buffer.
func (c *reassembly) release() { c.buf, c.at, c.ranges = nil, 0, c.ranges[:0] }

// CryptoRecv puts the CRYPTO frames of one encryption level back in order.
type CryptoRecv struct {
	r reassembly
}

// Push takes the data of a CRYPTO frame at offset off and calls deliver
// with every piece that is now next in order (the piece is valid during
// the call only). It returns CryptoBufferExceeded for data that reaches
// too far ahead or leaves too many separate pieces, and what deliver
// returns.
func (c *CryptoRecv) Push(off uint64, data []byte, deliver func([]byte) error) error {
	if end := off + uint64(len(data)); end > c.r.next && end-c.r.next > CryptoWindow {
		return CryptoBufferExceeded
	}
	var err error
	if !c.r.push(off, data, cryptoMaxRanges, func(d []byte) {
		if err == nil {
			err = deliver(d)
		}
	}) {
		return CryptoBufferExceeded
	}
	return err
}

// Pending reports whether data is held that is not yet in order.
func (c *CryptoRecv) Pending() bool { return len(c.r.ranges) > 0 }
