package integration

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"

	"github.com/quic-go/quic-go/http3"
)

func startHTTPBackend(t *testing.T, response string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", response)
		fmt.Fprint(w, response)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start HTTP backend: %v", err)
	}

	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String()
}

func TestHTTP_BasicProxy(t *testing.T) {
	backend := startHTTPBackend(t, "hello-http")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name:           "http-test",
			Bind:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol:       "http",
			Backend:         "web",
		}},
		Backends: []config.Backend{{
			Name:    "web",
			Balance: "roundrobin",
			Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name:           "http-test",
		Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol:       "http",
		Backend:         "web",
		Port:           proxyPort,
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/test", proxyPort))
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello-http" {
		t.Errorf("expected 'hello-http', got %q", string(body))
	}

	cancel()
}

func TestHTTP_HostRouting(t *testing.T) {
	apiBackend := startHTTPBackend(t, "api-response")
	webBackend := startHTTPBackend(t, "web-response")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name:     "http-route-test",
			Bind:     fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http",
			Backend:         "web",
		}},
		Backends: []config.Backend{
			{Name: "api", Balance: "roundrobin", Servers: []string{apiBackend}},
			{Name: "web", Balance: "roundrobin", Servers: []string{webBackend}},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name:           "http-route-test",
		Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol:       "http",
		Backend:         "web",
		Port:           proxyPort,
		Routes: []config.RouteConfig{
			{Match: config.RouteMatch{Host: "api.test"}, Backend: "api"},
		},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{}

	// Request with Host: api.test → api backend
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", proxyPort), nil)
	req.Host = "api.test"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("API request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "api-response" {
		t.Errorf("expected 'api-response', got %q", string(body))
	}

	// Request with other host → default web backend
	req, _ = http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", proxyPort), nil)
	req.Host = "other.test"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("Web request failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "web-response" {
		t.Errorf("expected 'web-response', got %q", string(body))
	}

	cancel()
}

func TestHTTP_PathRouting(t *testing.T) {
	apiBackend := startHTTPBackend(t, "api")
	staticBackend := startHTTPBackend(t, "static")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name:     "http-path-test",
			Bind:     fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http",
			Backend:         "api",
		}},
		Backends: []config.Backend{
			{Name: "api", Balance: "roundrobin", Servers: []string{apiBackend}},
			{Name: "static", Balance: "roundrobin", Servers: []string{staticBackend}},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name:           "http-path-test",
		Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol:       "http",
		Backend:         "api",
		Port:           proxyPort,
		Routes: []config.RouteConfig{
			{Match: config.RouteMatch{PathPrefix: "/static"}, Backend: "static"},
		},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// /static → static backend
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/static/img.png", proxyPort))
	if err != nil {
		t.Fatalf("Static request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "static" {
		t.Errorf("expected 'static', got %q", string(body))
	}

	// /api → default api backend
	resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/users", proxyPort))
	if err != nil {
		t.Fatalf("API request failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "api" {
		t.Errorf("expected 'api', got %q", string(body))
	}

	cancel()
}

func TestHTTP_ForwardedHeaders(t *testing.T) {
	var capturedHeaders http.Header
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		fmt.Fprint(w, "ok")
	})

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	proxyPort := getFreePort(t)
	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "hdr-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{ln.Addr().String()},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "hdr-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		Headers: config.HeadersConfig{
			RequestAdd: map[string]string{"X-Custom": "nvelox"},
		},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", proxyPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if capturedHeaders.Get("X-Forwarded-For") == "" {
		t.Error("expected X-Forwarded-For header")
	}
	if capturedHeaders.Get("X-Real-IP") == "" {
		t.Error("expected X-Real-IP header")
	}
	if capturedHeaders.Get("X-Custom") != "nvelox" {
		t.Errorf("expected X-Custom=nvelox, got %q", capturedHeaders.Get("X-Custom"))
	}

	cancel()
}

func TestHTTPS_HTTP2(t *testing.T) {
	backend := startHTTPBackend(t, "https-ok")
	proxyPort := getFreePort(t)
	tmpDir := t.TempDir()
	certFile, keyFile := generateTestCert(t, tmpDir)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "https-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "https", Backend:         "be",
			TLS: config.TLSConfig{Cert: certFile, Key: keyFile},
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "https-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "https", Backend:         "be", Port: proxyPort,
		TLS: &config.TLSConfig{Cert: certFile, Key: keyFile},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(300 * time.Millisecond)

	// Force HTTP/2 with insecure TLS
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/", proxyPort))
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "https-ok" {
		t.Errorf("expected 'https-ok', got %q", string(body))
	}

	// Verify HTTP/2 negotiation
	if resp.Proto != "HTTP/2.0" {
		t.Errorf("expected HTTP/2.0, got %s", resp.Proto)
	}

	cancel()
}

func TestHTTP3(t *testing.T) {
	backend := startHTTPBackend(t, "h3-ok")
	proxyPort := getFreePort(t)
	tmpDir := t.TempDir()
	certFile, keyFile := generateTestCert(t, tmpDir)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "h3-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "https", Backend:         "be", HTTP3: true,
			TLS: config.TLSConfig{Cert: certFile, Key: keyFile},
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "h3-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "https", Backend:         "be", Port: proxyPort, HTTP3: true,
		TLS: &config.TLSConfig{Cert: certFile, Key: keyFile},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(300 * time.Millisecond)

	// Test via HTTP/3 client
	h3Client := &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := h3Client.Get(fmt.Sprintf("https://127.0.0.1:%d/", proxyPort))
	if err != nil {
		t.Fatalf("HTTP/3 request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "h3-ok" {
		t.Errorf("expected 'h3-ok', got %q", string(body))
	}

	// Verify it's HTTP/3
	if resp.Proto != "HTTP/3.0" {
		t.Errorf("expected HTTP/3.0, got %s", resp.Proto)
	}

	// Test Alt-Svc header via HTTP/2
	h2Client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2: true,
		},
	}
	resp2, err := h2Client.Get(fmt.Sprintf("https://127.0.0.1:%d/", proxyPort))
	if err != nil {
		t.Fatalf("HTTP/2 request failed: %v", err)
	}
	resp2.Body.Close()

	altSvc := resp2.Header.Get("Alt-Svc")
	if altSvc == "" {
		t.Error("expected Alt-Svc header in HTTP/2 response")
	}

	cancel()
}

func TestHTTP_MixedWithTCP(t *testing.T) {
	// Start both an HTTP backend and a TCP echo backend
	httpBackend := startHTTPBackend(t, "http-ok")
	tcpBackend := startEchoServer(t)

	httpPort := getFreePort(t)
	tcpPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{
			{Name: "http-l", Bind: fmt.Sprintf("127.0.0.1:%d", httpPort), Protocol: "http", Backend:         "http-be"},
			{Name: "tcp-l", Bind: fmt.Sprintf("127.0.0.1:%d", tcpPort), Protocol: "tcp", Backend:         "tcp-be"},
		},
		Backends: []config.Backend{
			{Name: "http-be", Balance: "roundrobin", Servers: []string{httpBackend}},
			{Name: "tcp-be", Balance: "roundrobin", Servers: []string{tcpBackend}},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{Name: "http-l", Addr: fmt.Sprintf("127.0.0.1:%d", httpPort), Protocol: "http", Backend:         "http-be", Port: httpPort},
		{Name: "tcp-l", Addr: fmt.Sprintf("127.0.0.1:%d", tcpPort), Protocol: "tcp", Backend:         "tcp-be", Port: tcpPort},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Test HTTP
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", httpPort))
	if err != nil {
		t.Fatalf("HTTP request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "http-ok" {
		t.Errorf("HTTP: expected 'http-ok', got %q", string(body))
	}

	// Test TCP echo
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort), 2*time.Second)
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}
	conn.Write([]byte("echo-test"))
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	conn.Close()
	if err != nil {
		t.Fatalf("TCP read failed: %v", err)
	}
	if string(buf[:n]) != "echo-test" {
		t.Errorf("TCP: expected 'echo-test', got %q", string(buf[:n]))
	}

	cancel()
}
