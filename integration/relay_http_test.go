package integration

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"

	"nvelox/config"
	"nvelox/core"
	"nvelox/proxy"
)

// A relay in accept_proxy_from on an http listener, from the configuration
// to the backend: the PROXY v2 header a relay's connection starts with
// names the client; a relay's connection without it is closed; with a key
// the header must be signed; a reload changes the relays and the keys.
func TestHTTPRelay_FromConfigToBackend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("X-Forwarded-For"))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	port := getFreePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	key := []byte("0123456789abcdef0123456789abcdef-relay-key")
	mkCfg := func(relays []string, keys [][]byte) *config.Config {
		return &config.Config{
			Version:  "2",
			Logging:  config.LoggingConfig{Level: "error"},
			Backends: []config.Backend{{Name: "web", Balance: "roundrobin", Servers: []string{ln.Addr().String()}}},
			Listeners: []config.Listener{{
				Name: "site", Bind: addr, Protocol: "http", Backend: "web",
				AcceptProxyFrom: relays, AcceptProxyKeys: keys,
			}},
		}
	}
	// header is what a relay sends for the client 203.0.113.7.
	header := func(signWith []byte) []byte {
		h := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 4444}, &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 80})
		if signWith != nil {
			if err := proxy.SignHeader(h, signWith, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
		var b bytes.Buffer
		if _, err := h.WriteTo(&b); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	// get returns the client the backend was told of (X-Forwarded-For).
	get := func(hdr []byte) (string, error) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(append(hdr, "GET / HTTP/1.1\r\nHost: site.test\r\nConnection: close\r\n\r\n"...)); err != nil {
			return "", err
		}
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("status %d", resp.StatusCode)
		}
		return string(body), nil
	}

	cfg := mkCfg([]string{"127.0.0.1/32"}, nil)
	listeners, err := core.ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatal(err)
	}
	engine := core.NewEngine(cfg)
	engine.Listeners = listeners
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { engine.Start(ctx); close(stopped) }()
	t.Cleanup(func() { cancel(); <-stopped })
	waitForPort(t, port)

	if got, err := get(header(nil)); err != nil || got != "203.0.113.7" {
		t.Fatalf("through the relay: client %q, err %v; want 203.0.113.7", got, err)
	}
	if got, err := get(nil); err == nil {
		t.Fatalf("a relay's connection without a header was answered (client %q)", got)
	}

	// A reload brings a signing key: an unsigned header is refused.
	if err := engine.Reload(mkCfg([]string{"127.0.0.1/32"}, [][]byte{key})); err != nil {
		t.Fatal(err)
	}
	if got, err := get(header(nil)); err == nil {
		t.Fatalf("an unsigned header was accepted after the key came (client %q)", got)
	}
	if got, err := get(header(key)); err != nil || got != "203.0.113.7" {
		t.Fatalf("a signed header: client %q, err %v; want 203.0.113.7", got, err)
	}

	// A reload drops the relay: this address is a client like any other.
	if err := engine.Reload(mkCfg(nil, nil)); err != nil {
		t.Fatal(err)
	}
	if got, err := get(nil); err != nil || got != "127.0.0.1" {
		t.Fatalf("after the relay left the list: client %q, err %v; want 127.0.0.1", got, err)
	}
}
