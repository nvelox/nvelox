package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	targetHost := flag.String("host", "127.0.0.1", "Target host")
	startPort := flag.Int("start-port", 20000, "Start of port range")
	endPort := flag.Int("end-port", 20100, "End of port range")
	workers := flag.Int("workers", 50, "Number of concurrent workers")
	duration := flag.Duration("duration", 10*time.Second, "Test duration")
	flag.Parse()

	log.Printf("Starting stress test against %s:%d-%d with %d workers for %v", *targetHost, *startPort, *endPort, *workers, *duration)

	var (
		reqs  int64
		errs  int64
		total int64
	)

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					// Pick random port
					port := *startPort + rand.Intn(*endPort-*startPort+1)
					addr := fmt.Sprintf("%s:%d", *targetHost, port)

					start := time.Now()
					conn, err := net.DialTimeout("tcp", addr, 1*time.Second)
					if err != nil {
						atomic.AddInt64(&errs, 1)
						continue
					}

					// Send basics
					conn.SetDeadline(time.Now().Add(1 * time.Second))
					_, err = conn.Write([]byte("PING\n"))
					if err == nil {
						buf := make([]byte, 128)
						_, err = conn.Read(buf)
					}
					conn.Close()

					if err != nil {
						atomic.AddInt64(&errs, 1)
					} else {
						atomic.AddInt64(&reqs, 1)
					}
					atomic.AddInt64(&total, 1)

					// Brief sleep to avoid busy loop local exhaustion
					elapsed := time.Since(start)
					if elapsed < time.Millisecond {
						time.Sleep(time.Millisecond)
					}
				}
			}
		}()
	}

	time.Sleep(*duration)
	close(stopCh)
	wg.Wait()

	rps := float64(reqs) / duration.Seconds()
	log.Printf("Results:\n  Total Requests: %d\n  Errors: %d\n  RPS: %.2f\n", total, errs, rps)

	if errs > 0 {
		log.Printf("Error Rate: %.2f%%", float64(errs)/float64(total)*100)
	}
}
