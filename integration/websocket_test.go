package integration

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

// startWSEchoBackend starts a simple WebSocket echo server that accepts
// the upgrade and echoes back any frames received.
func startWSEchoBackend(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start WS echo backend: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleWSConn(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })

	return ln.Addr().String()
}

func handleWSConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	// Read HTTP upgrade request
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// Compute accept key
	key := req.Header.Get("Sec-WebSocket-Key")
	acceptKey := computeAcceptKey(key)

	// Send 101 response
	resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acceptKey)
	conn.Write([]byte(resp))

	// Echo raw bytes back (simplified — no frame parsing)
	io.Copy(conn, reader)
}

func computeAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func TestWebSocket_Proxy(t *testing.T) {
	wsBackend := startWSEchoBackend(t)
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "ws-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "ws-be",
		}},
		Backends: []config.Backend{{
			Name: "ws-be", Balance: "roundrobin", Servers: []string{wsBackend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "ws-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "ws-be", Port: proxyPort,
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Connect to proxy with WebSocket upgrade
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Send WebSocket upgrade request
	wsKey := base64.StdEncoding.EncodeToString([]byte("test-ws-key12345"))
	upgradeReq := fmt.Sprintf(
		"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		wsKey,
	)
	conn.Write([]byte(upgradeReq))

	// Read the 101 response
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("failed to read upgrade response: %v", err)
	}

	if resp.StatusCode != 101 {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Errorf("expected Upgrade: websocket, got %q", resp.Header.Get("Upgrade"))
	}

	// Send data through the WebSocket connection (raw bytes — no framing)
	msg := "hello-websocket"
	conn.Write([]byte(msg))

	// Read echo back
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo failed: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Errorf("expected echo %q, got %q", msg, string(buf[:n]))
	}

	cancel()
}
