package core

// C1: tls.client_auth / client_ca are applied on the TLS-terminating L4
// listener (they used to be parsed and ignored).

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"nvelox/config"
)

func stTLSDial(addr string, cfg *tls.Config) (*tls.Conn, error) {
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	c := tls.Client(raw, cfg)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// stTLSSessionWorks reports whether a TLS client gets a working session: the
// handshake completes AND data is relayed (with TLS 1.3 a server that rejects
// the client certificate only says so after the client's handshake finished).
func stTLSSessionWorks(addr string, cfg *tls.Config) error {
	c, err := stTLSDial(addr, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	return stEcho(c, "secret")
}

func TestL4TLS_ClientAuthRequire(t *testing.T) {
	pki := newSTPKI(t, "l4mtls")
	other := newSTPKI(t, "rogue")
	echo, accepted := stTCPEchoBackend(t)
	addr := stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "mtls", Bind: addr, Protocol: "tcp", Backend: "be",
			TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey, ClientAuth: "require", ClientCA: pki.caPath}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, nil)

	base := &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"}
	for _, maxV := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		noCert := base.Clone()
		noCert.MaxVersion = maxV
		if err := stTLSSessionWorks(addr, noCert); err == nil {
			t.Fatalf("TLS %x: client without a certificate got a working session", maxV)
		}
		rogue := base.Clone()
		rogue.MaxVersion = maxV
		rogue.Certificates = []tls.Certificate{other.clientCert(t, "mallory")}
		if err := stTLSSessionWorks(addr, rogue); err == nil {
			t.Fatalf("TLS %x: client certificate from another CA got a working session", maxV)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("unauthenticated clients reached the backend (%d connections)", n)
	}

	good := base.Clone()
	good.Certificates = []tls.Certificate{pki.clientCert(t, "alice")}
	if err := stTLSSessionWorks(addr, good); err != nil {
		t.Fatalf("client with a valid certificate: %v", err)
	}
}

func TestL4TLS_ClientAuthRequest(t *testing.T) {
	pki := newSTPKI(t, "l4req")
	echo, _ := stTCPEchoBackend(t)
	addr := stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "req", Bind: addr, Protocol: "tcp", Backend: "be",
			TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey, ClientAuth: "request"}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{echo}}},
	}, nil)

	// "request": a certificate is asked for (the server sends a
	// CertificateRequest) but not required.
	asked := false
	cfg := &tls.Config{RootCAs: pki.caPool, ServerName: "localhost",
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			asked = true
			return &tls.Certificate{}, nil
		}}
	if err := stTLSSessionWorks(addr, cfg); err != nil {
		t.Fatalf("request mode, no certificate: %v", err)
	}
	if !asked {
		t.Fatal("request mode: the server never asked for a client certificate")
	}
}

// A client CA that cannot be loaded fails startup instead of serving without
// the client check.
func TestL4TLS_ClientAuthBadCAFailsStart(t *testing.T) {
	pki := newSTPKI(t, "badca")
	addr := stFreeTCPAddr(t)
	e := NewEngine(&config.Config{Version: "2", Backends: []config.Backend{{Name: "be", Servers: []string{"127.0.0.1:1"}}}})
	e.Listeners = []*ListenerConfig{{Name: "mtls", Addr: addr, Protocol: "tcp", Backend: "be",
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey, ClientAuth: "require",
			ClientCA: filepath.Join(t.TempDir(), "missing-ca.pem")}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := e.Start(ctx)
	if err == nil || !strings.Contains(err.Error(), "client CA") {
		t.Fatalf("Start with an unreadable client CA: err=%v, want a client CA error", err)
	}
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("the listener came up despite the client CA error")
	}
}

// The HTTPS path through the engine (client_auth parsed once by
// ExpandListeners and handed to the site): no certificate, no response.
func TestHTTPS_ClientAuthViaEngine(t *testing.T) {
	pki := newSTPKI(t, "httpsmtls")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "backend-200")
	}))
	defer backend.Close()
	addr := stFreeTCPAddr(t)
	stStart(t, &config.Config{
		Listeners: []config.Listener{{Name: "web", Bind: addr, Protocol: "https", Backend: "be",
			TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey, ClientAuth: "require", ClientCA: pki.caPath}}},
		Backends: []config.Backend{{Name: "be", Servers: []string{strings.TrimPrefix(backend.URL, "http://")}}},
	}, nil)
	waitTCP(t, addr)

	get := func(cert *tls.Certificate) (string, error) {
		cfg := &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"}
		if cert != nil {
			cfg.Certificates = []tls.Certificate{*cert}
		}
		tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + addr + "/")
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	if body, err := get(nil); err == nil {
		t.Fatalf("no client certificate: served %q", body)
	}
	good := pki.clientCert(t, "alice")
	if body, err := get(&good); err != nil || body != "backend-200" {
		t.Fatalf("valid client certificate: %q %v", body, err)
	}
}

// waitTCP waits until addr accepts connections (HTTP bind groups listen from
// a goroutine).
func waitTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never accepted: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A reload whose client CA cannot be loaded is refused before anything
// changes: the running HTTPS site keeps serving with its current policy.
func TestHTTPS_ClientAuthBadCAFailsReload(t *testing.T) {
	pki := newSTPKI(t, "reloadca")
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "backend-200")
	}))
	defer backend.Close()
	addr := stFreeTCPAddr(t)
	listener := config.Listener{Name: "web", Bind: addr, Protocol: "https", Backend: "be",
		TLS: config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey}}
	backends := []config.Backend{{Name: "be", Servers: []string{strings.TrimPrefix(backend.URL, "http://")}}}
	e := stStart(t, &config.Config{Listeners: []config.Listener{listener}, Backends: backends}, nil)
	waitTCP(t, addr)

	get := func() error {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pki.caPool, ServerName: "localhost"}, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Get("https://" + addr + "/")
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
	if err := get(); err != nil {
		t.Fatalf("before reload: %v", err)
	}

	bad := listener
	bad.TLS.ClientAuth = "require"
	bad.TLS.ClientCA = filepath.Join(t.TempDir(), "missing-ca.pem")
	err := e.Reload(&config.Config{Version: "2", Listeners: []config.Listener{bad}, Backends: backends})
	if err == nil || !strings.Contains(err.Error(), "client CA") {
		t.Fatalf("Reload with an unreadable client CA: err=%v, want a client CA error", err)
	}
	if err := get(); err != nil {
		t.Fatalf("after the refused reload the running site must still serve: %v", err)
	}
}
