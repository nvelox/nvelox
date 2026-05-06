package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

// genCertForHost issues a self-signed cert for the given DNS name (also
// covering 127.0.0.1 so dialing the proxy by IP works) and returns the
// cert/key file paths plus the *x509.Certificate for client-side verification.
func genCertForHost(t *testing.T, dir, host string) (certFile, keyFile string, leaf *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	leaf, _ = x509.ParseCertificate(der)
	certFile = filepath.Join(dir, host+".pem")
	keyFile = filepath.Join(dir, host+".key")
	cf, _ := os.Create(certFile)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, _ := os.Create(keyFile)
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()
	return
}

// TestMultiSite_HTTPS_SNIDispatch is the end-to-end proof that two HTTPS
// sites can share :443 — each gets its own cert via SNI and its own backend
// via Host-header routing.
func TestMultiSite_HTTPS_SNIDispatch(t *testing.T) {
	apiBE := startHTTPBackend(t, "from-api-backend")
	webBE := startHTTPBackend(t, "from-web-backend")

	port := getFreePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	tmpDir := t.TempDir()

	apiCert, apiKey, apiLeaf := genCertForHost(t, tmpDir, "api.example.test")
	webCert, webKey, webLeaf := genCertForHost(t, tmpDir, "web.example.test")

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "warning"},
		Backends: []config.Backend{
			{Name: "api-be", Balance: "roundrobin", Servers: []string{apiBE}},
			{Name: "web-be", Balance: "roundrobin", Servers: []string{webBE}},
		},
	}
	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "api-site",
			Addr:           proxyAddr,
			Protocol:       "https",
			DefaultBackend: "api-be",
			Port:           port,
			ServerNames:    []string{"api.example.test"},
			TLS:            &config.TLSConfig{Cert: apiCert, Key: apiKey},
		},
		{
			Name:           "web-site",
			Addr:           proxyAddr,
			Protocol:       "https",
			DefaultBackend: "web-be",
			Port:           port,
			DefaultServer:  true, // catch-all
			TLS:            &config.TLSConfig{Cert: webCert, Key: webKey},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	waitForPort(t, port)

	// dial helper: connects with the given SNI, returns the server cert
	// presented and the response body the proxy returned.
	//
	// skipVerify is for the "unknown SNI" probe: nvelox correctly returns
	// the default site's cert, but its SAN doesn't cover the unknown name
	// — Go's TLS client would reject it on verification. We still want to
	// observe which cert was served, so verification is bypassed there.
	dial := func(sni string, skipVerify bool) (presentedCN string, body string) {
		t.Helper()
		rootPool := x509.NewCertPool()
		rootPool.AddCert(apiLeaf)
		rootPool.AddCert(webLeaf)
		tlsCfg := &tls.Config{
			ServerName:         sni,
			RootCAs:            rootPool,
			InsecureSkipVerify: skipVerify,
		}
		tr := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 2 * time.Second}
				rawConn, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(rawConn, tlsCfg)
				if err := tc.Handshake(); err != nil {
					rawConn.Close()
					return nil, err
				}
				presentedCN = tc.ConnectionState().PeerCertificates[0].Subject.CommonName
				return tc, nil
			},
		}
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequest("GET", "https://"+proxyAddr+"/", nil)
		req.Host = sni // host header matches SNI
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("dial %q: %v", sni, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return presentedCN, string(b)
	}

	// SNI api.example.test → api cert + api backend.
	cn, body := dial("api.example.test", false)
	if cn != "api.example.test" {
		t.Errorf("api SNI: presented cert CN = %q, want api.example.test", cn)
	}
	if body != "from-api-backend" {
		t.Errorf("api SNI: body = %q, want from-api-backend", body)
	}

	// SNI web.example.test → web cert + web backend (default site).
	cn, body = dial("web.example.test", false)
	if cn != "web.example.test" {
		t.Errorf("web SNI: presented cert CN = %q, want web.example.test", cn)
	}
	if body != "from-web-backend" {
		t.Errorf("web SNI: body = %q, want from-web-backend", body)
	}

	// Unknown SNI → falls back to default site's cert + backend.
	// Skip verify because the default cert's SAN doesn't cover "unknown".
	cn, body = dial("unknown.example.test", true)
	if cn != "web.example.test" {
		t.Errorf("unknown SNI: presented cert CN = %q, want web.example.test (default)", cn)
	}
	if body != "from-web-backend" {
		t.Errorf("unknown SNI: body = %q, want from-web-backend (default)", body)
	}
}

// TestMultiSite_HTTP3_PerSiteAltSvc verifies that in a bind group with two
// HTTPS sites where only one has http3: true, only that site's HTTP/2
// responses carry the Alt-Svc header advertising HTTP/3. The other site
// — sharing the same socket and the same shared QUIC listener — must not
// advertise H3 to its clients.
func TestMultiSite_HTTP3_PerSiteAltSvc(t *testing.T) {
	apiBE := startHTTPBackend(t, "api")
	webBE := startHTTPBackend(t, "web")

	port := getFreePort(t)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
	tmpDir := t.TempDir()
	apiCert, apiKey, apiLeaf := genCertForHost(t, tmpDir, "api.example.test")
	webCert, webKey, webLeaf := genCertForHost(t, tmpDir, "web.example.test")

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "warning"},
		Backends: []config.Backend{
			{Name: "api-be", Balance: "roundrobin", Servers: []string{apiBE}},
			{Name: "web-be", Balance: "roundrobin", Servers: []string{webBE}},
		},
	}
	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "api-h3",
			Addr:           proxyAddr,
			Protocol:       "https",
			DefaultBackend: "api-be",
			Port:           port,
			HTTP3:          true, // only this one
			ServerNames:    []string{"api.example.test"},
			TLS:            &config.TLSConfig{Cert: apiCert, Key: apiKey},
		},
		{
			Name:           "web-no-h3",
			Addr:           proxyAddr,
			Protocol:       "https",
			DefaultBackend: "web-be",
			Port:           port,
			DefaultServer:  true,
			TLS:            &config.TLSConfig{Cert: webCert, Key: webKey},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go engine.Start(ctx)
	waitForPort(t, port)

	// HTTP/2 client that overrides SNI per request.
	dialAltSvc := func(sni string, leaf *x509.Certificate) string {
		t.Helper()
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: sni, RootCAs: pool},
			ForceAttemptHTTP2: true,
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 2 * time.Second}
				raw, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(raw, &tls.Config{ServerName: sni, RootCAs: pool, NextProtos: []string{"h2", "http/1.1"}})
				if err := tc.Handshake(); err != nil {
					raw.Close()
					return nil, err
				}
				return tc, nil
			},
		}
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		req, _ := http.NewRequest("GET", "https://"+proxyAddr+"/", nil)
		req.Host = sni
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("dial %s: %v", sni, err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.Header.Get("Alt-Svc")
	}

	if got := dialAltSvc("api.example.test", apiLeaf); got == "" {
		t.Error("api site (http3: true) must advertise Alt-Svc, got empty")
	}
	if got := dialAltSvc("web.example.test", webLeaf); got != "" {
		t.Errorf("web site (no http3) must not advertise Alt-Svc, got %q", got)
	}
}
