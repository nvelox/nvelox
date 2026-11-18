// bigtool measures large HTTP/1.1 transfers through a proxy, with Go's standard library only.
//
//	bigtool get  -url http://h:p/big/1g.bin -c 4 -warm 3s -dur 12s    downloads, read and discarded
//	bigtool put  -url http://h:p/up -c 2 -size 1073741824 -warm 3s -dur 12s   uploads (Content-Length)
//	bigtool sink -addr 127.0.0.1:27600                                 upload target: reads every body
//	                                                                   to the end, then answers 200;
//	                                                                   GET /stats -> bytes received so far
//
// get/put: -c goroutines, each on its own keep-alive connection, repeat the transfer; only bytes
// moved inside the measured window count. Prints one JSON line.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const bufSize = 256 << 10

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "get", "put":
		load(os.Args[1], os.Args[2:])
	case "sink":
		sink(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bigtool get|put|sink [flags]")
	os.Exit(2)
}

var bufs = sync.Pool{New: func() any { b := make([]byte, bufSize); return &b }}

func sink(args []string) {
	fs := flag.NewFlagSet("sink", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:27600", "listen address")
	fs.Parse(args)
	var total atomic.Int64
	h := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/stats" {
			fmt.Fprint(w, total.Load())
			return
		}
		bp := bufs.Get().(*[]byte)
		var n int64
		for {
			m, err := r.Body.Read(*bp)
			n += int64(m)
			total.Add(int64(m))
			if err != nil {
				break
			}
		}
		bufs.Put(bp)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, n)
	}
	srv := &http.Server{Addr: *addr, Handler: http.HandlerFunc(h)}
	fmt.Println("sink on", *addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// pattern is an upload body of a given length, counting the bytes read off it while measuring.
type pattern struct {
	left      int64
	buf       []byte
	counted   *int64
	measuring *atomic.Bool
}

func (p *pattern) Read(b []byte) (int, error) {
	if p.left <= 0 {
		return 0, io.EOF
	}
	n := len(b)
	if int64(n) > p.left {
		n = int(p.left)
	}
	for off := 0; off < n; {
		off += copy(b[off:n], p.buf)
	}
	p.left -= int64(n)
	if p.measuring.Load() {
		*p.counted += int64(n)
	}
	return n, nil
}

func load(mode string, args []string) {
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	url := fs.String("url", "", "URL")
	conns := fs.Int("c", 4, "concurrent transfers, one connection each")
	size := fs.Int64("size", 1<<30, "upload size (put)")
	warm := fs.Duration("warm", 3*time.Second, "warm-up, not counted")
	dur := fs.Duration("dur", 12*time.Second, "measured time")
	fs.Parse(args)
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		MaxIdleConnsPerHost: *conns, MaxConnsPerHost: *conns, DisableCompression: true,
		ReadBufferSize: 64 << 10, WriteBufferSize: 64 << 10, IdleConnTimeout: time.Minute,
	}
	client := &http.Client{Transport: tr}
	var measuring, stop atomic.Bool
	type st struct {
		bytes, done, errs int64
		lastErr           string
	}
	stats := make([]st, *conns)
	var wg sync.WaitGroup
	for i := 0; i < *conns; i++ {
		wg.Add(1)
		go func(s *st) {
			defer wg.Done()
			buf := make([]byte, bufSize)
			pat := make([]byte, 64<<10)
			for i := range pat {
				pat[i] = byte(i * 7)
			}
			for !stop.Load() {
				var resp *http.Response
				var err error
				if mode == "get" {
					resp, err = client.Get(*url)
				} else {
					body := &pattern{left: *size, buf: pat, counted: &s.bytes, measuring: &measuring}
					req, _ := http.NewRequest(http.MethodPost, *url, body)
					req.ContentLength = *size
					req.Header.Set("Content-Type", "application/octet-stream")
					resp, err = client.Do(req)
				}
				if err != nil {
					if measuring.Load() {
						s.errs++
						s.lastErr = err.Error()
					}
					time.Sleep(50 * time.Millisecond)
					continue
				}
				ok := resp.StatusCode == http.StatusOK
				for {
					n, rerr := resp.Body.Read(buf)
					if mode == "get" && measuring.Load() {
						s.bytes += int64(n)
					}
					if rerr != nil {
						if rerr != io.EOF {
							ok = false
							if measuring.Load() {
								s.lastErr = rerr.Error()
							}
						}
						break
					}
				}
				resp.Body.Close()
				if measuring.Load() {
					if ok {
						s.done++
					} else {
						s.errs++
						if s.lastErr == "" {
							s.lastErr = "status " + strconv.Itoa(resp.StatusCode)
						}
					}
				}
			}
		}(&stats[i])
	}
	time.Sleep(*warm)
	measuring.Store(true)
	t0 := time.Now()
	time.Sleep(*dur)
	measuring.Store(false)
	el := time.Since(t0)
	stop.Store(true)
	// Transfers still running finish on their own; give them a moment, then report.
	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(60 * time.Second):
	}
	var bytes, done, errs int64
	lastErr := ""
	for i := range stats {
		bytes += stats[i].bytes
		done += stats[i].done
		errs += stats[i].errs
		if stats[i].lastErr != "" {
			lastErr = stats[i].lastErr
		}
	}
	j, _ := json.Marshal(map[string]any{"mode": mode, "bytes": bytes, "gbps": float64(bytes) / el.Seconds() / 1e9,
		"completed": done, "errors": errs, "last_error": lastErr, "elapsed_s": el.Seconds(), "conns": *conns, "size": *size})
	fmt.Println("BIGJSON " + string(j))
	os.Exit(0)
}
