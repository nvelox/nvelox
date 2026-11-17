package integration

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

func TestHTTP_Redirect(t *testing.T) {
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "redir-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin",
			Servers: []string{"127.0.0.1:1"}, // dummy, won't be reached
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "redir-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		Routes: []config.RouteConfig{
			{
				Match:    config.RouteMatch{PathPrefix: "/old"},
				Redirect: config.RedirectConfig{URL: "/new-location", Code: 301},
			},
		},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // don't follow redirects
	}}

	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/old/page", proxyPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 301 {
		t.Errorf("expected 301, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc != "/new-location" {
		t.Errorf("expected Location=/new-location, got %s", loc)
	}

	cancel()
}

func TestHTTP_Compression(t *testing.T) {
	backend := startHTTPBackend(t, "compressible-content-that-is-long-enough")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "compress-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
			Compression: config.CompressionConfig{Enabled: true},
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "compress-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		Compression: config.CompressionConfig{Enabled: true},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	// Request with Accept-Encoding: gzip
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", proxyPort), nil)
	req.Header.Set("Accept-Encoding", "gzip")

	// Use transport that doesn't auto-decompress
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("expected Content-Encoding: gzip, got %q", resp.Header.Get("Content-Encoding"))
	}

	// Decompress and verify
	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("gzip reader failed: %v", err)
	}
	body, _ := io.ReadAll(gr)
	gr.Close()

	if string(body) != "compressible-content-that-is-long-enough" {
		t.Errorf("expected original content, got %q", string(body))
	}

	cancel()
}

func TestHTTP_RegexRouteWithRewrite(t *testing.T) {
	backend := startHTTPBackend(t, "api-ok")
	proxyPort := getFreePort(t)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{{
			Name: "regex-test", Bind: fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol: "http", Backend:         "be",
		}},
		Backends: []config.Backend{{
			Name: "be", Balance: "roundrobin", Servers: []string{backend},
		}},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{{
		Name: "regex-test", Addr: fmt.Sprintf("127.0.0.1:%d", proxyPort),
		Protocol: "http", Backend:         "be", Port: proxyPort,
		Routes: []config.RouteConfig{
			{
				Match:   config.RouteMatch{PathRegex: `^/api/v(\d+)/(.*)`},
				Backend: "be",
				Rewrite: config.RewriteConfig{Path: "/v$1/$2"},
			},
		},
	}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v2/users", proxyPort))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Backend should receive the rewritten path but still return its response
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if string(body) != "api-ok" {
		t.Errorf("expected 'api-ok', got %q", string(body))
	}

	cancel()
}
