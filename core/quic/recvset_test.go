package quic

import (
	mrand "math/rand"
	"testing"
)

// Packet numbers in any order, with repeats: the set's ranges are exactly
// the numbers added (checked against a map), highest first, not touching,
// and add says which were duplicates.
func TestRecvSet(t *testing.T) {
	for seed := int64(1); seed <= 300; seed++ {
		rng := mrand.New(mrand.NewSource(seed))
		var s recvSet
		have := map[uint64]bool{}
		span := uint64(1 + rng.Intn(recvSetMax-2)) // numbers below 2*span: never more separate ranges than the set keeps
		for i := 0; i < 400; i++ {
			pn := uint64(rng.Intn(int(span)))*2 + uint64(rng.Intn(2))*uint64(rng.Intn(2))
			if rng.Intn(5) == 0 {
				pn = uint64(rng.Intn(int(span) * 2))
			}
			dup := s.add(pn)
			if dup != have[pn] {
				t.Fatalf("seed %d: add(%d) said duplicate=%v, want %v", seed, pn, dup, have[pn])
			}
			have[pn] = true
			checkRecvSet(t, seed, &s, have)
		}
	}
	var s recvSet
	if s.largest() != -1 || s.ranges() != nil {
		t.Errorf("an empty set: largest %d, ranges %v", s.largest(), s.ranges())
	}
}

func checkRecvSet(t *testing.T, seed int64, s *recvSet, have map[uint64]bool) {
	t.Helper()
	n := 0
	for i, r := range s.r {
		if r[0] > r[1] {
			t.Fatalf("seed %d: range %v", seed, r)
		}
		if i > 0 && r[1]+2 > s.r[i-1][0] {
			t.Fatalf("seed %d: ranges %v and %v touch or are out of order", seed, s.r[i-1], r)
		}
		for pn := r[0]; pn <= r[1]; pn++ {
			if !have[pn] {
				t.Fatalf("seed %d: %d is in the set and was never added", seed, pn)
			}
			n++
		}
	}
	if n != len(have) {
		t.Fatalf("seed %d: the set holds %d numbers, %d were added (%v)", seed, n, len(have), s.r)
	}
}

// More gaps than the set keeps: the lowest ranges are forgotten, the
// highest numbers stay, and a number below everything kept is reported as
// a duplicate.
func TestRecvSet_Bounded(t *testing.T) {
	var s recvSet
	for pn := uint64(0); pn < 200; pn += 2 { // 100 separate numbers
		if s.add(pn) {
			t.Fatalf("add(%d): duplicate", pn)
		}
	}
	if len(s.r) != recvSetMax || s.largest() != 198 {
		t.Fatalf("%d ranges, largest %d; want %d and 198", len(s.r), s.largest(), recvSetMax)
	}
	lowest := s.r[len(s.r)-1][0]
	if lowest != 198-2*(recvSetMax-1) {
		t.Errorf("lowest range starts at %d", lowest)
	}
	if !s.add(1) {
		t.Errorf("a number below everything kept was taken as new")
	}
	// A number in a gap among the kept ones joins its neighbours.
	if s.add(197) || len(s.r) != recvSetMax-1 || s.r[0] != [2]uint64{196, 198} {
		t.Errorf("after filling the top gap: %v", s.r[:2])
	}
	// The set written as an ACK frame parses back to the same ranges.
	var f Frame
	b := AppendAck(nil, 0, s.ranges())
	if n, err := ParseFrame(b, &f); err != nil || n != len(b) {
		t.Fatalf("the ACK frame of the set: %v", err)
	}
	i := 0
	f.AckRanges(func(lo, hi uint64) bool {
		if s.r[i] != [2]uint64{lo, hi} {
			t.Fatalf("range %d: %d-%d, the set has %v", i, lo, hi, s.r[i])
		}
		i++
		return true
	})
	if i != len(s.r) {
		t.Errorf("%d ranges in the frame, %d in the set", i, len(s.r))
	}
}
