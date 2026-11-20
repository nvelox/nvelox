package httpproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/lb"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// caPKI is a test CA issuing server and client certificates.
type caPKI struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	pool    *x509.CertPool
	caPath  string
	srvCert string
	srvKey  string
	serial  int64
}

func newCAPKI(t *testing.T, name string) *caPKI {
	t.Helper()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := &caPKI{key: key, serial: 1}
	p.cert, _ = x509.ParseCertificate(der)
	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.cert)
	p.caPath = filepath.Join(dir, "ca.pem")
	os.WriteFile(p.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	c, k := p.issue(t, x509.ExtKeyUsageServerAuth, "a.test", "b.test", "c.test", "localhost")
	p.srvCert, p.srvKey = filepath.Join(dir, "srv.pem"), filepath.Join(dir, "srv.key")
	os.WriteFile(p.srvCert, c, 0o600)
	os.WriteFile(p.srvKey, k, 0o600)
	return p
}

func (p *caPKI) issue(t *testing.T, usage x509.ExtKeyUsage, dns ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	p.serial++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(p.serial), Subject: pkix.Name{CommonName: "leaf"},
		DNSNames: dns, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.cert, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

func (p *caPKI) clientCert(t *testing.T) tls.Certificate {
	t.Helper()
	c, k := p.issue(t, x509.ExtKeyUsageClientAuth)
	cert, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// mtlsSite builds a real site (NewHTTPServer) answering "site=<name>" through
// a backend, with its own server_names and client_auth.
func mtlsSite(t *testing.T, pki *caPKI, name string, names []string, def bool, clientAuth, clientCA string) *HTTPServer {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "site=%s", name)
	}))
	t.Cleanup(backend.Close)
	target := strings.TrimPrefix(backend.URL, "http://")
	backends := map[string]*config.Backend{"be": {Name: "be", Servers: []string{target}}}
	balancers := map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})}
	l := &ListenerConfig{Name: name, Addr: ":0", Protocol: "https", Backend: "be",
		ServerNames: names, DefaultServer: def,
		TLS: &config.TLSConfig{Cert: pki.srvCert, Key: pki.srvKey, ClientAuth: clientAuth, ClientCA: clientCA}}
	return NewHTTPServer(l, balancers, backends, nil, nil, nil, nil, nil)
}

// freeAddr returns a loopback address whose port nobody holds, for TCP or
// for UDP: a group that serves HTTP/3 binds both, and a port the kernel
// gives out as free for TCP may be the UDP port of a QUIC client, of this
// test process or of another one on the machine.
func freeAddr(t *testing.T) string {
	t.Helper()
	var held error
	for i := 0; i < 100; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		pc, err := net.ListenPacket("udp", addr)
		ln.Close()
		if err == nil {
			pc.Close()
			return addr
		}
		held = err
	}
	t.Fatalf("no port that is free for TCP and UDP alike: %v", held)
	return ""
}

func startGroup(t *testing.T, addr string, sites ...*HTTPServer) *BindGroup {
	t.Helper()
	g := NewBindGroup(addr, "https")
	for _, s := range sites {
		g.AddSite(s)
	}
	if err := g.Start(); err != nil {
		t.Fatalf("bind group start: %v", err)
	}
	t.Cleanup(func() { g.Stop(t.Context()) })
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return g
		}
		if time.Now().After(deadline) {
			t.Fatalf("bind group never listened: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// httpsGet does one request with a fresh connection: TLS SNI sni, Host host,
// optional client certificate. It returns the status and body, or the error.
func httpsGet(pki *caPKI, addr, sni, host string, cert *tls.Certificate, h2 bool) (int, string, error) {
	cfg := &tls.Config{RootCAs: pki.pool, ServerName: sni}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: h2, DisableKeepAlives: true}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "https://"+addr+"/", nil)
	req.Host = host
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func TestHTTPS_ClientAuthPerSite(t *testing.T) {
	pki := newCAPKI(t, "mtls-ca")
	rogue := newCAPKI(t, "rogue-ca")
	addr := freeAddr(t)
	// a.test requires a client certificate; b.test (the default) asks for
	// none; c.test requests one but does not require it.
	startGroup(t, addr,
		mtlsSite(t, pki, "a", []string{"a.test"}, false, "require", pki.caPath),
		mtlsSite(t, pki, "b", []string{"b.test"}, true, "", ""),
		mtlsSite(t, pki, "c", []string{"c.test"}, false, "request", ""),
	)
	good := pki.clientCert(t)
	bad := rogue.clientCert(t)

	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			if code, body, err := httpsGet(pki, addr, "b.test", "b.test", nil, h2); err != nil || code != 200 || body != "site=b" {
				t.Fatalf("site without client_auth, no cert: %d %q %v", code, body, err)
			}
			if code, body, err := httpsGet(pki, addr, "a.test", "a.test", nil, h2); err == nil {
				t.Fatalf("require site, no cert: served %d %q", code, body)
			}
			if code, body, err := httpsGet(pki, addr, "a.test", "a.test", &bad, h2); err == nil {
				t.Fatalf("require site, cert from another CA: served %d %q", code, body)
			}
			if code, body, err := httpsGet(pki, addr, "a.test", "a.test", &good, h2); err != nil || code != 200 || body != "site=a" {
				t.Fatalf("require site, valid cert: %d %q %v", code, body, err)
			}
			if code, body, err := httpsGet(pki, addr, "c.test", "c.test", nil, h2); err != nil || code != 200 || body != "site=c" {
				t.Fatalf("request site, no cert: %d %q %v", code, body, err)
			}
			// SNI of a site without client_auth, Host of the require site:
			// the certificate check never ran for a.test — refused (421).
			if code, body, err := httpsGet(pki, addr, "b.test", "a.test", nil, h2); err != nil || code != http.StatusMisdirectedRequest {
				t.Fatalf("SNI b.test + Host a.test: %d %q %v, want 421", code, body, err)
			}
			if code, _, err := httpsGet(pki, addr, "c.test", "a.test", nil, h2); err != nil || code != http.StatusMisdirectedRequest {
				t.Fatalf("SNI c.test + Host a.test: %d %v, want 421", code, err)
			}
			// The other way round needs no client cert: allowed.
			if code, body, err := httpsGet(pki, addr, "a.test", "b.test", &good, h2); err != nil || code != 200 || body != "site=b" {
				t.Fatalf("SNI a.test (with cert) + Host b.test: %d %q %v", code, body, err)
			}
		})
	}
}

// Single-site bind with client_auth: require (the plain case).
func TestHTTPS_ClientAuthRequireSingleSite(t *testing.T) {
	pki := newCAPKI(t, "single-ca")
	addr := freeAddr(t)
	startGroup(t, addr, mtlsSite(t, pki, "only", nil, false, "require", pki.caPath))
	if _, _, err := httpsGet(pki, addr, "localhost", "localhost", nil, false); err == nil {
		t.Fatal("no client cert: request served")
	}
	good := pki.clientCert(t)
	if code, body, err := httpsGet(pki, addr, "localhost", "localhost", &good, false); err != nil || code != 200 || body != "site=only" {
		t.Fatalf("valid client cert: %d %q %v", code, body, err)
	}
}

// HTTP/3 shares the group's tls.Config: each site gets its own client_auth
// policy by SNI there too, on connections that resume a session as on new
// ones.
func TestHTTP3_ClientAuth(t *testing.T) {
	quicGoPath(t)
	clientAuthOverHTTP3(t, func(addr string, sites ...*HTTPServer) {
		if g := startGroup(t, addr, sites...); g.http3Server == nil {
			t.Fatal("http3 server not started")
		}
	})
}

// h3SiteGet does one request over a new HTTP/3 connection: SNI sni, Host
// host, the client certificate cert when given, sessions kept in cache when
// given. It returns the status and body and whether the connection resumed
// a session, or the error.
func h3SiteGet(pki *caPKI, addr, sni, host string, cert *tls.Certificate, cache tls.ClientSessionCache) (code int, body string, resumed bool, err error) {
	cfg := &tls.Config{RootCAs: pki.pool, ServerName: sni, NextProtos: []string{http3.NextProtoH3}, ClientSessionCache: cache}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, cfg, nil)
	if err != nil {
		return 0, "", false, err
	}
	defer conn.CloseWithError(0, "")
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/", nil)
	resp, err := (&http3.Transport{}).NewClientConn(conn).RoundTrip(req)
	if err != nil {
		return 0, "", false, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), conn.ConnectionState().TLS.DidResume, err
}

// refusedInHandshake reports whether err is a QUIC connection the server
// ended with a TLS alert.
func refusedInHandshake(err error) bool {
	var te *quic.TransportError
	return errors.As(err, &te) && te.Remote && te.ErrorCode >= 0x100 && te.ErrorCode < 0x200
}

// anySession is a client session cache that offers the last session stored
// in it to every server: a client that resumes where it has no business
// to.
type anySession struct {
	mu sync.Mutex
	cs *tls.ClientSessionState
}

func (c *anySession) Get(string) (*tls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cs, c.cs != nil
}

func (c *anySession) Put(_ string, cs *tls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cs != nil {
		c.cs = cs
	}
}

// clientAuthOverHTTP3 checks client_auth over HTTP/3 on a group of three
// sites that start runs: "a.test" requires a certificate of the test CA,
// "c.test" one of another CA, and "b.test", the default site, asks for
// none.
func clientAuthOverHTTP3(t *testing.T, start func(addr string, sites ...*HTTPServer)) {
	pki := newCAPKI(t, "h3-ca")
	other := newCAPKI(t, "h3-other-ca")
	sites := []*HTTPServer{
		mtlsSite(t, pki, "a", []string{"a.test"}, false, "require", pki.caPath),
		mtlsSite(t, pki, "b", []string{"b.test"}, true, "", ""),
		mtlsSite(t, pki, "c", []string{"c.test"}, false, "require", other.caPath),
	}
	for _, s := range sites {
		s.Listener.HTTP3 = true
	}
	addr := freeAddr(t)
	start(addr, sites...)
	certA, certC := pki.clientCert(t), other.clientCert(t)

	served := func(what, sni, host string, cert *tls.Certificate, cache tls.ClientSessionCache, wantCode int, wantBody string, wantResumed bool) {
		t.Helper()
		code, body, resumed, err := h3SiteGet(pki, addr, sni, host, cert, cache)
		if err != nil || code != wantCode || wantBody != "" && body != wantBody {
			t.Errorf("%s: status %d, body %q, err %v; want %d %q", what, code, body, err, wantCode, wantBody)
		}
		if resumed != wantResumed {
			t.Errorf("%s: the connection resumed a session: %v, want %v", what, resumed, wantResumed)
		}
	}
	refused := func(what, sni string, cert *tls.Certificate, cache tls.ClientSessionCache) {
		t.Helper()
		code, body, _, err := h3SiteGet(pki, addr, sni, sni, cert, cache)
		if !refusedInHandshake(err) {
			t.Errorf("%s: status %d, body %q, err %v; want the handshake refused", what, code, body, err)
		}
	}

	// Each site's own policy, chosen by the handshake's server name.
	served("a.test with its CA's certificate", "a.test", "a.test", &certA, nil, 200, "site=a", false)
	refused("a.test without a certificate", "a.test", nil, nil)
	refused("a.test with another CA's certificate", "a.test", &certC, nil)
	served("b.test without a certificate", "b.test", "b.test", nil, nil, 200, "site=b", false)
	served("c.test with its CA's certificate", "c.test", "c.test", &certC, nil, 200, "site=c", false)
	refused("c.test with another CA's certificate", "c.test", &certA, nil)
	// A handshake as the site that asks for nothing does not open the
	// sites that ask: the request is for another connection.
	served("a.test asked on b.test's connection", "b.test", "a.test", nil, nil, http.StatusMisdirectedRequest, "", false)
	served("a.test asked on b.test's connection, with a certificate", "b.test", "a.test", &certA, nil, http.StatusMisdirectedRequest, "", false)
	served("a.test asked on c.test's connection", "c.test", "a.test", &certC, nil, http.StatusMisdirectedRequest, "", false)

	// A client that comes back to a.test resumes its session, which holds
	// its certificate.
	cache := tls.NewLRUClientSessionCache(4)
	served("a.test, first connection", "a.test", "a.test", &certA, cache, 200, "site=a", false)
	served("a.test, second connection", "a.test", "a.test", &certA, cache, 200, "site=a", true)

	// A session is no way around another site's policy. One of b.test,
	// made without a certificate, does not stand in for the certificate
	// a.test requires; one of a.test does not carry its certificate over to
	// c.test, whose CA did not issue it.
	fromB := &anySession{}
	served("b.test, for its session", "b.test", "b.test", nil, fromB, 200, "site=b", false)
	refused("a.test with b.test's session and no certificate", "a.test", nil, fromB)
	fromA := &anySession{}
	served("a.test, for its session", "a.test", "a.test", &certA, fromA, 200, "site=a", false)
	refused("c.test with a.test's session", "c.test", &certA, fromA)
}

// A site whose client CA cannot be loaded fails the bind group's start.
func TestBindGroup_ClientAuthBadCAFailsStart(t *testing.T) {
	pki := newCAPKI(t, "bad-ca")
	s := mtlsSite(t, pki, "a", nil, true, "require", filepath.Join(t.TempDir(), "missing.pem"))
	g := NewBindGroup(freeAddr(t), "https")
	g.AddSite(s)
	if err := g.Start(); err == nil {
		g.Stop(t.Context())
		t.Fatal("bind group started with an unreadable client CA")
	}
}

// net/http's server has a TLS config of its own, not the group's: Go
// 1.26's Serve sets fields of it when it starts serving, while handshakes
// read the group's config and a reload clones it (under Go 1.26 the race
// detector reported that in TestBindGroup_ClientAuthFollowsReplaceSites).
func TestBindGroup_HTTPServerOwnTLSConfig(t *testing.T) {
	pki := newCAPKI(t, "own-config-ca")
	addr := freeAddr(t)
	g := startGroup(t, addr, mtlsSite(t, pki, "a", nil, true, "", ""))
	if g.httpServer.TLSConfig == nil || g.tlsBase == nil || g.httpServer.TLSConfig == g.tlsBase {
		t.Fatalf("net/http's TLS config %p, the group's %p: want two configs", g.httpServer.TLSConfig, g.tlsBase)
	}
	if code, _, err := httpsGet(pki, addr, "localhost", "localhost", nil, true); err != nil || code != 200 {
		t.Fatalf("HTTP/2: %d %v", code, err)
	}
	if code, _, err := httpsGet(pki, addr, "localhost", "localhost", nil, false); err != nil || code != 200 {
		t.Fatalf("HTTP/1.1: %d %v", code, err)
	}
}

// A reload that turns client_auth on for a site applies to new handshakes.
func TestBindGroup_ClientAuthFollowsReplaceSites(t *testing.T) {
	pki := newCAPKI(t, "reload-ca")
	addr := freeAddr(t)
	g := startGroup(t, addr, mtlsSite(t, pki, "a", nil, true, "", ""))
	if code, _, err := httpsGet(pki, addr, "localhost", "localhost", nil, false); err != nil || code != 200 {
		t.Fatalf("before: %d %v", code, err)
	}
	if err := g.ReplaceSites([]*HTTPServer{mtlsSite(t, pki, "a", nil, true, "require", pki.caPath)}); err != nil {
		t.Fatal(err)
	}
	if code, _, err := httpsGet(pki, addr, "localhost", "localhost", nil, false); err == nil {
		t.Fatalf("after enabling client_auth: no-cert request served (%d)", code)
	}
	good := pki.clientCert(t)
	if code, _, err := httpsGet(pki, addr, "localhost", "localhost", &good, false); err != nil || code != 200 {
		t.Fatalf("after enabling client_auth, valid cert: %d %v", code, err)
	}
}

// M5: a backend with backend_tls whose TLS config cannot be built is answered
// 502 — the request never reaches it in plaintext (it used to).
func TestBackendTLS_BrokenConfigNeverPlaintext(t *testing.T) {
	var hits atomic.Int64
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "plaintext!")
	}))
	defer plain.Close()
	target := strings.TrimPrefix(plain.URL, "http://")
	backends := map[string]*config.Backend{"be": {Name: "be", Servers: []string{target},
		BackendTLS: config.BackendTLSConfig{Enabled: true, CACert: "/nonexistent/ca.pem"}}}
	balancers := map[string]lb.Balancer{"be": lb.NewRoundRobin([]string{target})}
	s := NewHTTPServer(&ListenerConfig{Name: "edge", Addr: ":0", Protocol: "http", Backend: "be"},
		balancers, backends, nil, nil, nil, nil, nil)
	ts := httptest.NewServer(s)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/secret?token=abc")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the backend received %d plaintext request(s)", n)
	}
}

func TestWebSocket_BrokenBackendTLSNeverPlaintext(t *testing.T) {
	b := startWSBackend(t, nil, http.StatusSwitchingProtocols) // a plaintext listener: any dial shows up
	_, _, resp := wsUpgrade(t, newWSProxy(t, b.addr, config.BackendTLSConfig{Enabled: true, CACert: "/nonexistent/ca.pem"}))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	select {
	case <-b.closed:
		t.Fatal("the upgrade was dialed to the backend in plaintext")
	case <-time.After(300 * time.Millisecond):
	}
}

// Two sites requiring client certificates from DIFFERENT CAs share a bind:
// a certificate verified for one site's SNI must not reach the other site by
// naming it in the Host header (421), even though the connection does carry a
// verified chain.
func TestHTTPS_ClientAuthHostMustMatchSNISite(t *testing.T) {
	srv := newCAPKI(t, "srv-ca")
	caA := newCAPKI(t, "ca-a")
	caB := newCAPKI(t, "ca-b")
	addr := freeAddr(t)
	startGroup(t, addr,
		mtlsSite(t, srv, "a", []string{"a.test"}, true, "require", caA.caPath),
		mtlsSite(t, srv, "b", []string{"b.test"}, false, "require", caB.caPath),
	)
	certA := caA.clientCert(t)
	certB := caB.clientCert(t)

	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("h2=%v", h2), func(t *testing.T) {
			if code, body, err := httpsGet(srv, addr, "a.test", "a.test", &certA, h2); err != nil || code != 200 || body != "site=a" {
				t.Fatalf("CA-A cert on site a: %d %q %v", code, body, err)
			}
			if code, body, err := httpsGet(srv, addr, "b.test", "b.test", &certB, h2); err != nil || code != 200 || body != "site=b" {
				t.Fatalf("CA-B cert on site b: %d %q %v", code, body, err)
			}
			if _, _, err := httpsGet(srv, addr, "b.test", "b.test", &certA, h2); err == nil {
				t.Fatal("CA-A cert accepted by site b's handshake")
			}
			// Handshake as site a (CA-A cert verifies), then ask for site b.
			if code, body, err := httpsGet(srv, addr, "a.test", "b.test", &certA, h2); err != nil || code != http.StatusMisdirectedRequest {
				t.Fatalf("SNI a.test (CA-A cert) + Host b.test: %d %q %v, want 421", code, body, err)
			}
		})
	}
}
