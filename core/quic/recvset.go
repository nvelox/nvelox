package quic

// recvSet is the set of packet numbers received in one packet number space,
// kept as the ranges an ACK frame reports: from the highest down, not
// touching. It holds at most recvSetMax ranges; when a new one does not
// fit, the lowest is forgotten (those packets were acknowledged long ago,
// and a sender that still waits for them retransmits).
type recvSet struct {
	r [][2]uint64 // [smallest, largest], the highest range first
}

// recvSetMax bounds the ranges kept, and so the size of an ACK frame.
const recvSetMax = 32

// add records packet number pn. It reports whether pn was there already (a
// duplicate, which is dropped) or lies below everything still remembered
// (also treated as a duplicate: it cannot be told from one).
func (s *recvSet) add(pn uint64) (dup bool) {
	// Find the first range that starts at or below pn+1: pn belongs to it,
	// touches it, or lies in the gap above it.
	i := 0
	for i < len(s.r) && s.r[i][0] > pn+1 {
		i++
	}
	if i < len(s.r) {
		lo, hi := s.r[i][0], s.r[i][1]
		switch {
		case pn >= lo && pn <= hi:
			return true
		case pn == hi+1:
			s.r[i][1] = pn
			// It may now touch the range above.
			if i > 0 && s.r[i-1][0] == pn+1 {
				s.r[i-1][0] = lo
				s.r = append(s.r[:i], s.r[i+1:]...)
			}
			return false
		case pn+1 == lo:
			s.r[i][0] = pn
			// It may now touch the range below.
			if i+1 < len(s.r) && s.r[i+1][1]+1 == pn {
				s.r[i][0] = s.r[i+1][0]
				s.r = append(s.r[:i+1], s.r[i+2:]...)
			}
			return false
		}
	}
	// A new range at position i.
	if len(s.r) == recvSetMax {
		if i == len(s.r) {
			return true // below everything remembered
		}
		s.r = s.r[:len(s.r)-1]
	}
	s.r = append(s.r, [2]uint64{})
	copy(s.r[i+1:], s.r[i:])
	s.r[i] = [2]uint64{pn, pn}
	return false
}

// ranges returns the set for AppendAck: nil when nothing was received.
func (s *recvSet) ranges() [][2]uint64 { return s.r }

// largest returns the highest packet number received, -1 for none.
func (s *recvSet) largest() int64 {
	if len(s.r) == 0 {
		return -1
	}
	return int64(s.r[0][1])
}
