//go:build linux

// udpbench is a UDP echo origin and a closed-loop load generator for
// benchmarking UDP proxies. Both run on nvelox's event loops, so that the
// tool is not the limit of what it measures.
//
//	udpbench echo -addr 127.0.0.1:9000 -loops 4
//	udpbench load -addr 127.0.0.1:5300 -flows 128 -size 1024 -warm 3s -dur 10s -loops 4
//
// load: every flow is a connected socket with its own source port (one
// proxy session each) and keeps one datagram in flight. A reply that does
// not come within -loss counts as lost, and the flow sends its next
// datagram.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/nvelox/ngx"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "echo":
		echo(os.Args[2:])
	case "load":
		load(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: udpbench echo|load [flags]")
	os.Exit(2)
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "udpbench: %s: %v\n", what, err)
	os.Exit(1)
}

const batch = 16

// echoSock answers every datagram of one SO_REUSEPORT socket to its sender.
type echoSock struct {
	fd    int
	msgs  [batch]ngx.Mmsghdr
	iov   [batch]unix.Iovec
	names [batch]unix.RawSockaddrInet6
	buf   []byte
}

func (s *echoSock) OnEvent(uint32) {
	for {
		for i := range s.msgs {
			s.iov[i].SetLen(65535)
			s.msgs[i].Hdr.Namelen = uint32(unsafe.Sizeof(s.names[i]))
		}
		n, errno := ngx.Recvmmsg(s.fd, s.msgs[:])
		if errno != 0 || n == 0 {
			return
		}
		for i := 0; i < n; i++ {
			s.iov[i].SetLen(int(s.msgs[i].Len))
		}
		for off := 0; off < n; {
			sent, errno := ngx.Sendmmsg(s.fd, s.msgs[off:n])
			off += sent
			if errno != 0 || sent == 0 {
				off++ // this one could not be sent: dropped
			}
		}
		if n < batch {
			return
		}
	}
}

func echo(args []string) {
	fs := flag.NewFlagSet("echo", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9000", "listen address")
	loops := fs.Int("loops", 4, "event loops, one SO_REUSEPORT socket each")
	fs.Parse(args)
	grp, err := ngx.NewGroup(*loops)
	if err != nil {
		fatal("loops", err)
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		c.Control(func(fd uintptr) { serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1) })
		return serr
	}}
	for _, lp := range grp.Loops() {
		pc, err := lc.ListenPacket(context.Background(), "udp", *addr)
		if err != nil {
			fatal("listen", err)
		}
		fd, err := ngx.DetachPacketConn(pc)
		if err != nil {
			fatal("listen", err)
		}
		s := &echoSock{fd: fd, buf: make([]byte, batch*65535)}
		for i := range s.msgs {
			s.iov[i].Base = &s.buf[i*65535]
			s.msgs[i].Hdr.Iov = &s.iov[i]
			s.msgs[i].Hdr.SetIovlen(1)
			s.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&s.names[i]))
		}
		lp := lp
		lp.Post(func() {
			if _, err := lp.RegisterRead(fd, s); err != nil {
				fatal("register", err)
			}
		})
	}
	fmt.Println("echo ready on", *addr)
	select {}
}

// loadLoop is the generator's state on one loop.
type loadLoop struct {
	lp        *ngx.Loop
	flows     []*flow
	measuring bool
	stopped   bool
	replies   uint64
	lost      uint64
	lat       []uint32 // microseconds, one reply in 8
	out       []byte
	in        []byte
	loss      int64
}

// flow is one connected socket with one datagram in flight.
type flow struct {
	ll     *loadLoop
	fd     int
	seq    uint64
	sentAt int64
	timer  ngx.Timer
}

func (f *flow) send() {
	f.seq++
	binary.BigEndian.PutUint64(f.ll.out, f.seq)
	f.sentAt = f.ll.lp.Now()
	ngx.Write(f.fd, f.ll.out)
}

func (f *flow) OnEvent(uint32) {
	ll := f.ll
	n, errno := ngx.Read(f.fd, ll.in)
	if errno != 0 || ll.stopped {
		return
	}
	if n < 8 || binary.BigEndian.Uint64(ll.in) != f.seq {
		return // a late reply to a datagram already counted as lost
	}
	if ll.measuring {
		ll.replies++
		if f.seq%8 == 0 {
			ll.lat = append(ll.lat, uint32((ll.lp.Now()-f.sentAt)/1000))
		}
	}
	f.send()
}

// OnTimer looks for a lost datagram: nothing came for the loss time.
func (f *flow) OnTimer() {
	ll := f.ll
	if ll.stopped {
		return
	}
	if now := ll.lp.Now(); now-f.sentAt >= ll.loss {
		if ll.measuring {
			ll.lost++
		}
		f.send()
	}
	ll.lp.ArmAt(&f.timer, f.sentAt+ll.loss)
}

func load(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:5300", "target address")
	flows := fs.Int("flows", 128, "concurrent flows (one source port each)")
	size := fs.Int("size", 1024, "datagram payload bytes")
	warm := fs.Duration("warm", 3*time.Second, "warm-up")
	dur := fs.Duration("dur", 10*time.Second, "measured time")
	loss := fs.Duration("loss", 100*time.Millisecond, "a reply later than this is lost")
	loops := fs.Int("loops", 4, "event loops")
	fs.Parse(args)
	if *size < 16 {
		*size = 16
	}
	grp, err := ngx.NewGroup(*loops)
	if err != nil {
		fatal("loops", err)
	}
	lls := make([]*loadLoop, *loops)
	for i, lp := range grp.Loops() {
		lls[i] = &loadLoop{lp: lp, out: make([]byte, *size), in: make([]byte, 65535), loss: int64(*loss)}
	}
	for i := 0; i < *flows; i++ {
		c, err := net.Dial("udp", *addr)
		if err != nil {
			fatal("dial", err)
		}
		fd, err := ngx.DetachPacketConn(c.(*net.UDPConn))
		if err != nil {
			fatal("dial", err)
		}
		ll := lls[i%*loops]
		f := &flow{ll: ll, fd: fd}
		f.timer.F = f
		ll.flows = append(ll.flows, f)
	}
	run := func(fn func(ll *loadLoop)) {
		var wg sync.WaitGroup
		for _, ll := range lls {
			ll := ll
			wg.Add(1)
			ll.lp.Post(func() { defer wg.Done(); fn(ll) })
		}
		wg.Wait()
	}
	run(func(ll *loadLoop) {
		for _, f := range ll.flows {
			if _, err := ll.lp.RegisterRead(f.fd, f); err != nil {
				fatal("register", err)
			}
			f.send()
			ll.lp.ArmAt(&f.timer, f.sentAt+ll.loss)
		}
	})
	time.Sleep(*warm)
	run(func(ll *loadLoop) { ll.measuring = true })
	t0 := time.Now()
	time.Sleep(*dur)
	run(func(ll *loadLoop) { ll.measuring = false; ll.stopped = true })
	el := time.Since(t0)
	var replies, lost uint64
	var lat []uint32
	for _, ll := range lls {
		replies += ll.replies
		lost += ll.lost
		lat = append(lat, ll.lat...)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	p := func(q float64) uint32 {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(float64(len(lat)-1)*q)]
	}
	pct := 0.0
	if replies+lost > 0 {
		pct = 100 * float64(lost) / float64(replies+lost)
	}
	fmt.Printf("replies/s=%.0f p50=%dus p99=%dus lost=%d (%.2f%%) flows=%d size=%d\n",
		float64(replies)/el.Seconds(), p(0.50), p(0.99), lost, pct, *flows, *size)
}
