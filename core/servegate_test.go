package core

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

// sgEngine starts an engine that holds serving, with an HTTP, a TCP and a
// UDP listener in front of echo backends; it returns their addresses.
func sgEngine(t *testing.T) (e *Engine, httpAddr, tcpAddr, udpAddr, metricsAddr string) {
	t.Helper()
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "web") }))
	t.Cleanup(web.Close)
	tcpBackend, _ := stTCPEchoBackend(t)
	udpBackend, _ := stUDPBackend(t, stEchoReply)
	httpAddr, tcpAddr, udpAddr, metricsAddr = stFreeTCPAddr(t), stFreeTCPAddr(t), stFreeUDPAddr(t), stFreeTCPAddr(t)
	e = stStart(t, &config.Config{
		Metrics: config.MetricsConfig{Enabled: true, Bind: metricsAddr},
		Listeners: []config.Listener{
			{Name: "web", Bind: httpAddr, Protocol: "http", Backend: "webb"},
			{Name: "tcp", Bind: tcpAddr, Protocol: "tcp", Backend: "tcpb"},
			{Name: "udp", Bind: udpAddr, Protocol: "udp", Backend: "udpb"},
		},
		Backends: []config.Backend{
			{Name: "webb", Servers: []string{strings.TrimPrefix(web.URL, "http://")}},
			{Name: "tcpb", Servers: []string{tcpBackend}},
			{Name: "udpb", Servers: []string{udpBackend}},
		},
	}, func(e *Engine) { e.HoldServing() })
	<-e.Ready()
	return e, httpAddr, tcpAddr, udpAddr, metricsAddr
}

// TestHoldServing_NothingAnsweredUntilServe: with HoldServing, every socket
// is bound but nothing is answered — HTTP, TCP, UDP or metrics — until Serve (main
// switches to server.user in between). What arrived meanwhile is served
// then, not dropped.
func TestHoldServing_NothingAnsweredUntilServe(t *testing.T) {
	e, httpAddr, tcpAddr, udpAddr, metricsAddr := sgEngine(t)
	const held = 400 * time.Millisecond

	client := &http.Client{Timeout: held}
	for _, u := range []string{"http://" + httpAddr + "/", "http://" + metricsAddr + "/metrics"} {
		if resp, err := client.Get(u); err == nil {
			resp.Body.Close()
			t.Fatalf("%s answered %d before Serve", u, resp.StatusCode)
		}
	}
	tc, err := net.DialTimeout("tcp", tcpAddr, time.Second) // the kernel queues it
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	io.WriteString(tc, "tcp")
	tc.SetReadDeadline(time.Now().Add(held))
	buf := make([]byte, 16)
	if n, err := tc.Read(buf); err == nil {
		t.Fatalf("TCP relayed %q before Serve", buf[:n])
	}
	raddr, _ := net.ResolveUDPAddr("udp", udpAddr)
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("udp"))
	uc.SetReadDeadline(time.Now().Add(held))
	if n, err := uc.Read(buf); err == nil {
		t.Fatalf("UDP relayed %q before Serve", buf[:n])
	}

	e.Serve()

	tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := io.ReadFull(tc, buf[:3]); err != nil || string(buf[:n]) != "tcp" {
		t.Fatalf("held TCP connection after Serve: %q %v", buf[:n], err)
	}
	uc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := uc.Read(buf); err != nil || string(buf[:n]) != "udp" {
		t.Fatalf("held UDP datagram after Serve: %q %v", buf[:n], err)
	}
	client.Timeout = 2 * time.Second
	resp, err := client.Get("http://" + httpAddr + "/")
	if err != nil {
		t.Fatalf("HTTP after Serve: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "web" {
		t.Fatalf("HTTP after Serve: %q", body)
	}
	resp, err = client.Get("http://" + metricsAddr + "/metrics")
	if err != nil {
		t.Fatalf("metrics after Serve: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics after Serve: %d", resp.StatusCode)
	}
}

// TestHoldServing_StopWithoutServe: an engine stopped before Serve (the
// switch to server.user failed) shuts down without ever serving, also with
// a connection and a datagram waiting. stStart's cleanup fails the test if
// Start does not return.
func TestHoldServing_StopWithoutServe(t *testing.T) {
	_, httpAddr, tcpAddr, udpAddr, _ := sgEngine(t)
	tc, err := net.DialTimeout("tcp", tcpAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	hc, err := net.DialTimeout("tcp", httpAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer hc.Close()
	raddr, _ := net.ResolveUDPAddr("udp", udpAddr)
	uc, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("udp"))
	time.Sleep(100 * time.Millisecond)
}
