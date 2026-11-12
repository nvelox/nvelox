package core_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
	"nvelox/core/logging"
)

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// TestReloadUnderTraffic is the H6 regression test. Reload used to write the
// engine's Balancers / Backends / ConnLimiters / StickyStores maps while L7
// requests, L4 connections and admin API reads read the same maps with no
// lock: "fatal error: concurrent map read and map write" under a SIGHUP (seen
// in production 2026-10-22). Here every reload adds or removes 40 backends
// while HTTP requests, plain TCP connections and admin backend listings run;
// under -race any unsynchronized access to those maps fails the test.
func TestReloadUnderTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("reload stress test")
	}
	_ = logging.Init("error", "", "")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer backend.Close()
	be := backend.Listener.Addr().String()
	httpAddr, tcpAddr, adminAddr := freeTCPAddr(t), freeTCPAddr(t), freeTCPAddr(t)
	const apiKey = "reload-race-test-key"

	mk := func(withExtra bool) *config.Config {
		backends := []config.Backend{{Name: "pool", Servers: []string{be}, MaxConnections: 1000}}
		if withExtra {
			for i := 0; i < 40; i++ {
				backends = append(backends, config.Backend{Name: "extra" + strconv.Itoa(i), Servers: []string{be}, MaxConnections: 100})
			}
		}
		return &config.Config{
			Version: "2",
			Admin:   config.AdminConfig{Enabled: true, Bind: adminAddr, APIKey: apiKey},
			Listeners: []config.Listener{
				{Name: "web", Bind: httpAddr, Protocol: "http", Backend: "pool", DefaultServer: true},
				{Name: "raw", Bind: tcpAddr, Protocol: "tcp", Backend: "pool"},
			},
			Backends: backends,
		}
	}
	cfg := mk(true)
	exp, err := core.ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatal(err)
	}
	e := core.NewEngine(cfg)
	e.Listeners = exp
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Start(ctx)
	ready := false
	for i := 0; i < 150 && !ready; i++ {
		if c, err := net.Dial("tcp", httpAddr); err == nil {
			c.Close()
			ready = true
		} else {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !ready {
		t.Fatal("engine did not start")
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	var l7, l4, adm atomic.Int64
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr := &http.Transport{MaxIdleConnsPerHost: 2}
			defer tr.CloseIdleConnections()
			c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			for !stop.Load() {
				if resp, err := c.Get("http://" + httpAddr + "/"); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					l7.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				c, err := net.DialTimeout("tcp", tcpAddr, 2*time.Second)
				if err != nil {
					continue
				}
				c.SetDeadline(time.Now().Add(3 * time.Second))
				io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
				io.Copy(io.Discard, c)
				c.Close()
				l4.Add(1)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		c := &http.Client{Timeout: 5 * time.Second}
		for !stop.Load() {
			req, _ := http.NewRequest(http.MethodGet, "http://"+adminAddr+"/api/v1/backends", nil)
			req.Header.Set("X-API-Key", apiKey)
			if resp, err := c.Do(req); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				adm.Add(1)
			}
		}
	}()

	reloads := 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := e.Reload(mk(reloads%2 == 1)); err != nil {
			t.Fatalf("reload %d: %v", reloads, err)
		}
		reloads++
		time.Sleep(2 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	if l7.Load() == 0 || l4.Load() == 0 || adm.Load() == 0 {
		t.Fatalf("traffic did not flow during the reloads: l7=%d l4=%d admin=%d", l7.Load(), l4.Load(), adm.Load())
	}
	t.Logf("reloads=%d l7=%d l4=%d admin=%d", reloads, l7.Load(), l4.Load(), adm.Load())
}
