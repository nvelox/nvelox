// udptool is a UDP echo origin and a closed-loop UDP load generator written with
// Go's standard library only, to check UDP proxy throughput with a tool that
// shares no code with any proxy under test.
//
//	udptool echo -addr 127.0.0.1:27500 -workers 4
//	udptool load -target 127.0.0.1:27106 -flows 128 -size 1024 -warm 3s -dur 10s -timeout 100ms
//
// load: every flow is its own connected socket (its own source port, so one proxy
// session each) with one datagram in flight. A reply is matched by the sequence
// number in its first 8 bytes; no matching reply within -timeout counts as one
// lost datagram and the flow sends the next one. Prints one JSON line.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: udptool echo|load [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "echo":
		echo(os.Args[2:])
	case "load":
		load(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: udptool echo|load [flags]")
		os.Exit(2)
	}
}

const soReusePort = 0xf // SO_REUSEPORT on Linux (not exported by package syscall)

func reuseport(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
	}); err != nil {
		return err
	}
	return serr
}

// echo sends every datagram back to its sender, from -workers SO_REUSEPORT
// sockets, one goroutine each.
func echo(args []string) {
	fs := flag.NewFlagSet("echo", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:27500", "listen address")
	workers := fs.Int("workers", 4, "sockets (SO_REUSEPORT), one goroutine each")
	fs.Parse(args)
	lc := net.ListenConfig{Control: reuseport}
	for i := 0; i < *workers; i++ {
		pc, err := lc.ListenPacket(context.Background(), "udp", *addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
		c := pc.(*net.UDPConn)
		_ = c.SetReadBuffer(4 << 20)
		_ = c.SetWriteBuffer(4 << 20)
		go func() {
			buf := make([]byte, 65536)
			for {
				n, a, err := c.ReadFromUDPAddrPort(buf)
				if err != nil {
					continue
				}
				_, _ = c.WriteToUDPAddrPort(buf[:n], a)
			}
		}()
	}
	fmt.Println("echo ready on", *addr)
	select {}
}

type flowStats struct {
	replies, lost, sendErrs uint64
	lat                     []uint32 // microseconds, one reply in 8
}

func load(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	target := fs.String("target", "127.0.0.1:27106", "address to load")
	flows := fs.Int("flows", 128, "concurrent flows, one connected socket (source port) each")
	size := fs.Int("size", 1024, "datagram payload bytes (at least 8)")
	warm := fs.Duration("warm", 3*time.Second, "warm-up, not counted")
	dur := fs.Duration("dur", 10*time.Second, "measured time")
	timeout := fs.Duration("timeout", 100*time.Millisecond, "a datagram not answered within this is lost")
	fs.Parse(args)
	if *size < 8 {
		*size = 8
	}
	raddr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "target:", err)
		os.Exit(1)
	}
	var measuring, stop atomic.Bool
	stats := make([]flowStats, *flows)
	var wg sync.WaitGroup
	for i := 0; i < *flows; i++ {
		c, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dial:", err)
			os.Exit(1)
		}
		wg.Add(1)
		go func(c *net.UDPConn, st *flowStats) {
			defer wg.Done()
			defer c.Close()
			out := make([]byte, *size)
			in := make([]byte, 65536)
			var seq uint64
			for !stop.Load() {
				seq++
				binary.BigEndian.PutUint64(out, seq)
				sent := time.Now()
				if _, err := c.Write(out); err != nil {
					// e.g. ECONNREFUSED left by an ICMP error: count it, wait, go on.
					if measuring.Load() {
						st.sendErrs++
					}
					time.Sleep(*timeout)
					continue
				}
				_ = c.SetReadDeadline(sent.Add(*timeout))
				for {
					n, err := c.Read(in)
					if err != nil {
						var ne net.Error
						if errors.As(err, &ne) && ne.Timeout() && measuring.Load() {
							st.lost++
						}
						break
					}
					if n >= 8 && binary.BigEndian.Uint64(in) == seq {
						if measuring.Load() {
							st.replies++
							if seq%8 == 0 {
								st.lat = append(st.lat, uint32(time.Since(sent)/time.Microsecond))
							}
						}
						break
					}
					// a late reply to a datagram already counted as lost: keep waiting
				}
			}
		}(c, &stats[i])
	}
	time.Sleep(*warm)
	measuring.Store(true)
	t0 := time.Now()
	time.Sleep(*dur)
	measuring.Store(false)
	el := time.Since(t0)
	stop.Store(true)
	wg.Wait()
	var replies, lost, sendErrs uint64
	var lat []uint32
	for i := range stats {
		replies += stats[i].replies
		lost += stats[i].lost
		sendErrs += stats[i].sendErrs
		lat = append(lat, stats[i].lat...)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	q := func(f float64) uint32 {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(float64(len(lat)-1)*f)]
	}
	lostPct := 0.0
	if replies+lost > 0 {
		lostPct = 100 * float64(lost) / float64(replies+lost)
	}
	j, _ := json.Marshal(map[string]any{
		"replies_per_s": float64(replies) / el.Seconds(), "replies": replies, "lost": lost,
		"lost_pct": lostPct, "send_errors": sendErrs, "p50_us": q(0.50), "p99_us": q(0.99),
		"flows": *flows, "size": *size, "elapsed_s": el.Seconds(),
	})
	fmt.Println("UDPJSON " + string(j))
}
