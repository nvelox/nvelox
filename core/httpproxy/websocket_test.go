package httpproxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/lb"
)

// wsTestTimeout bounds every client read/write in these tests, so a proxy
// that never answers or never closes fails the test instead of hanging it.
const wsTestTimeout = 3 * time.Second

// wsBackend is a minimal WebSocket backend for the handleWebSocket tests. It
// reads the upgrade request and either answers 101 and echoes every byte that
// follows, or answers with a plain status and closes.
type wsBackend struct {
	addr string
	// handshakeErrs receives the TLS handshake error of each failed
	// connection (TLS backends only).
	handshakeErrs chan error
	// closed receives one value per connection once the backend has seen it
	// end (the proxy closed its side).
	closed chan struct{}
}

// startWSBackend starts a wsBackend on 127.0.0.1. tlsCfg != nil makes it a
// TLS server; status is the answer to the upgrade (101 = accept and echo).
func startWSBackend(t *testing.T, tlsCfg *tls.Config, status int) *wsBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &wsBackend{
		addr:          ln.Addr().String(),
		handshakeErrs: make(chan error, 8),
		closed:        make(chan struct{}, 8),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(c, tlsCfg, status)
		}
	}()
	return b
}

func (b *wsBackend) serve(c net.Conn, tlsCfg *tls.Config, status int) {
	defer func() {
		c.Close()
		b.closed <- struct{}{}
	}()
	if tlsCfg != nil {
		tc := tls.Server(c, tlsCfg)
		if err := tc.Handshake(); err != nil {
			b.handshakeErrs <- err
			return
		}
		c = tc
	}
	br := bufio.NewReader(c)
	if _, err := http.ReadRequest(br); err != nil {
		return
	}
	if status != http.StatusSwitchingProtocols {
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, http.StatusText(status))
		return
	}
	io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
	io.Copy(c, br) // echo until the proxy closes
}

// newWSProxy starts the proxy under test in front of a single backend server.
func newWSProxy(t *testing.T, target string, backendTLS config.BackendTLSConfig) string {
	t.Helper()
	backends := map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}, BackendTLS: backendTLS}}
	balancers := map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})}
	l := &ListenerConfig{Name: "edge", Addr: ":0", Protocol: "http", Backend: "be"}
	s := NewHTTPServer(l, balancers, backends, nil, nil, nil, nil, nil)
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts.Listener.Addr().String()
}

// wsUpgrade sends a WebSocket upgrade through the proxy and returns the
// client connection, its reader and the response.
func wsUpgrade(t *testing.T, proxyAddr string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, wsTestTimeout)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(wsTestTimeout))
	io.WriteString(conn, "GET /ws HTTP/1.1\r\nHost: ws.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	return conn, br, resp
}

// assertEcho writes a message through the upgraded connection and expects the
// backend's echo back.
func assertEcho(t *testing.T, conn net.Conn, br *bufio.Reader) {
	t.Helper()
	msg := []byte("ping over the relay")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

// TestWebSocket_TLSBackend: a backend with backend_tls must get the upgrade
// over TLS (it used to be sent in plaintext), with the same verification the
// HTTP transport applies: insecure, or ca_cert checked against the target's host.
func TestWebSocket_TLSBackend(t *testing.T) {
	certPath, keyPath := genCertWithCN(t, t.TempDir(), "localhost")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load backend cert: %v", err)
	}
	b := startWSBackend(t, &tls.Config{Certificates: []tls.Certificate{cert}}, http.StatusSwitchingProtocols)
	_, port, _ := net.SplitHostPort(b.addr)

	cases := []struct {
		name       string
		target     string
		backendTLS config.BackendTLSConfig
	}{
		{"insecure", b.addr, config.BackendTLSConfig{Enabled: true, Insecure: true}},
		{"verified ca_cert", net.JoinHostPort("localhost", port), config.BackendTLSConfig{Enabled: true, CACert: certPath}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, br, resp := wsUpgrade(t, newWSProxy(t, tc.target, tc.backendTLS))
			if resp.StatusCode != http.StatusSwitchingProtocols {
				t.Fatalf("status = %d, want 101", resp.StatusCode)
			}
			assertEcho(t, conn, br)
		})
	}
}

// TestWebSocket_PlaintextBackend: a backend without backend_tls keeps the
// plain TCP dial.
func TestWebSocket_PlaintextBackend(t *testing.T) {
	b := startWSBackend(t, nil, http.StatusSwitchingProtocols)
	conn, br, resp := wsUpgrade(t, newWSProxy(t, b.addr, config.BackendTLSConfig{}))
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)
}

// TestWebSocket_BackendRejectsUpgrade: a backend that answers the upgrade with
// a non-101 and closes must have that answer relayed and the client
// connection closed by the proxy, not held open until the client gives up.
func TestWebSocket_BackendRejectsUpgrade(t *testing.T) {
	b := startWSBackend(t, nil, http.StatusUnauthorized)
	conn, br, resp := wsUpgrade(t, newWSProxy(t, b.addr, config.BackendTLSConfig{}))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
	conn.SetReadDeadline(time.Now().Add(wsTestTimeout))
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("client connection not closed by the proxy after the backend closed: %v", err)
	}
}

// TestWebSocket_ClientCloseClosesBackend: when the client goes away the proxy
// must close the backend connection too, not wait for the backend to close.
func TestWebSocket_ClientCloseClosesBackend(t *testing.T) {
	b := startWSBackend(t, nil, http.StatusSwitchingProtocols)
	conn, br, resp := wsUpgrade(t, newWSProxy(t, b.addr, config.BackendTLSConfig{}))
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	assertEcho(t, conn, br)
	conn.Close()
	select {
	case <-b.closed:
	case <-time.After(wsTestTimeout):
		t.Fatal("backend connection not closed by the proxy after the client closed")
	}
}

// TestWebSocket_TLSBackendBadCA: with verification on and a ca_cert that does
// not match the backend's certificate, the upgrade fails with 502 and nothing
// is sent to the backend in plaintext.
func TestWebSocket_TLSBackendBadCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := genCertWithCN(t, dir, "localhost")
	otherCA, _ := genCertWithCN(t, dir, "other-ca.test")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load backend cert: %v", err)
	}
	b := startWSBackend(t, &tls.Config{Certificates: []tls.Certificate{cert}}, http.StatusSwitchingProtocols)
	_, port, _ := net.SplitHostPort(b.addr)

	_, _, resp := wsUpgrade(t, newWSProxy(t, net.JoinHostPort("localhost", port),
		config.BackendTLSConfig{Enabled: true, CACert: otherCA}))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	select {
	case err := <-b.handshakeErrs:
		var rhe tls.RecordHeaderError
		if errors.As(err, &rhe) {
			t.Fatalf("backend received plaintext instead of a TLS handshake: %v", err)
		}
	case <-time.After(wsTestTimeout):
		t.Fatal("backend saw no TLS handshake attempt")
	}
}
