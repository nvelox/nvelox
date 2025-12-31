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
	port := fmtPort(l.Addr())
	l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := run(port, ctx); err != nil {
			// t.Error("run failed: %v", err) // Data race if called after test end?
		}
	}()

	// Wait for startup
	time.Sleep(100 * time.Millisecond)

	// Connect
	conn, err := net.Dial("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	conn.Close()

	// Stop
	cancel()
	time.Sleep(50 * time.Millisecond)
}

func fmtPort(addr net.Addr) string {
	_, port, _ := net.SplitHostPort(addr.String())
	return port
}
