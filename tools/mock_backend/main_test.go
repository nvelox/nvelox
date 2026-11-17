package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	// Pick random port
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := run(addr, ctx); err != nil {
			// ignore close error
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect and send data
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Connection failed: %v", err)
	}
	conn.Write([]byte("hello"))
	time.Sleep(10 * time.Millisecond)
	conn.Close()

	cancel()
	time.Sleep(50 * time.Millisecond)
}
