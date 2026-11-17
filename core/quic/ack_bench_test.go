package quic

import (
	"fmt"
	"testing"
)

// BenchmarkAck: an acknowledgement of two packets, and the two packets sent
// in their place, with n packets waiting for their acknowledgement all the
// while. What it costs must not depend on n: at 400 Mbit/s over a path of
// 100 ms round trip some 3,500 packets wait, and an acknowledgement comes
// for every other one.
func BenchmarkAck(b *testing.B) {
	for _, n := range []int{50, 500, 3000} {
		b.Run(fmt.Sprintf("waiting-%d", n), func(b *testing.B) {
			tc, _ := limitedClient(b, 1<<40, 1<<40)
			c := tc.c
			// A window of n packets, and a stream with more to send than the
			// benchmark sends.
			c.cc.ssthresh = 0
			c.cc.cwnd = int64(n) * c.cc.mds
			id := openUni(b, c)
			data := make([]byte, 256<<10)
			fill := func() {
				for c.StreamWrite(id, data, false) > 0 {
				}
			}
			fill()
			for i := 0; i < 400 && len(c.spaces[LevelApplication].sent) < n-2; i++ {
				tc.now += 1e6
				tc.pump()
				fill()
			}
			if got := len(c.spaces[LevelApplication].sent); got < n*9/10 {
				b.Fatalf("%d packets wait, want about %d", got, n)
			}
			tc.frames, tc.sizes = nil, nil
			acked := 0 // how many of tc.seen are acknowledged
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				acked += 2
				tc.now += 1e5
				c.cc.cwnd, c.cc.epochStart = int64(n)*c.cc.mds, 0 // the window stays what it is
				c.Recv(tc.now, tc.packet(tc.dcid, AppendAck(nil, 0, [][2]uint64{{tc.seen[0], tc.seen[acked-1]}})))
				fill()
				tc.pump()
				tc.frames, tc.sizes = tc.frames[:0], tc.sizes[:0]
				if len(tc.seen)-acked > 2*n {
					b.Fatalf("%d packets were sent and are not acknowledged, with a window of %d", len(tc.seen)-acked, n)
				}
			}
			b.StopTimer()
			if got := len(c.spaces[LevelApplication].sent); got < n/2 {
				b.Fatalf("at the end %d packets wait, want about %d: the benchmark measured something else", got, n)
			}
		})
	}
}
