package main

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
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestRun_SIGHUPRotatesCertWithoutDroppingConnections drives the exact path a
// certificate rotation takes in production (ngris cert-sync on public-gw):
// replace the cert/key files by atomic rename, send SIGHUP, and nvelox must
//   - present the NEW certificate to new TLS handshakes,
//   - keep serving the already-established keep-alive connection (no drop),
//   - and, when a later rotation leaves an unusable pair (key doesn't match),
//     keep presenting the last good certificate instead of failing.
func TestRun_SIGHUPRotatesCertWithoutDroppingConnections(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "public.pem")
	keyPath := filepath.Join(dir, "public.key")

	v1cert, v1key := selfSigned(t, "v1.rotation.test")
	v2cert, v2key := selfSigned(t, "v2.rotation.test")
	v3cert, _ := selfSigned(t, "v3.rotation.test")
	installPair(t, dir, certPath, keyPath, v1cert, v1key)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	addr := freeAddr(t)
	configPath := filepath.Join(dir, "nvelox.yaml")
	config := fmt.Sprintf(`
version: '2'
listeners:
  - name: site
    bind: %q
    protocol: https
    backend: be
    default_server: true
    tls:
      cert: %q
      key: %q
backends:
  - name: be
    servers:
      - %q
logging:
  level: error
`, addr, certPath, keyPath, backend.Listener.Addr().String())
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	reloadCh := make(chan os.Signal, 1)
	runErr := make(chan error, 1)
	go func() { runErr <- run([]string{"nvelox", "-config", configPath}, ctx, reloadCh) }()
	defer func() {
		cancel()
		select {
		case err := <-runErr:
			if err != nil {
				t.Errorf("run: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("run did not return after cancel")
		}
	}()

	waitFor(t, "listener up", func() bool { _, err := servedCN(addr); return err == nil })

	// One long-lived client with a single keep-alive connection.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "site.rotation.test"},
		MaxConnsPerHost: 1,
		IdleConnTimeout: time.Minute,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	reused, cn := get(t, client, addr)
	if cn != "v1.rotation.test" {
		t.Fatalf("before rotation: served %q, want v1", cn)
	}
	_ = reused

	// Rotate like cert-sync: temp file in the same dir + rename, key then cert.
	installPair(t, dir, certPath, keyPath, v2cert, v2key)
	reloadCh <- syscall.SIGHUP
	waitFor(t, "new handshakes get v2", func() bool { got, err := servedCN(addr); return err == nil && got == "v2.rotation.test" })

	// The pre-rotation keep-alive connection is still alive and still serves.
	reused, cn = get(t, client, addr)
	if !reused {
		t.Fatal("the established connection was dropped by the reload (request needed a new connection)")
	}
	if cn != "v1.rotation.test" {
		t.Fatalf("established connection reports %q; its session was negotiated with v1", cn)
	}

	// A broken rotation (v3 cert with v2's key — a mismatched pair) must not
	// take the site down: nvelox keeps the last good certificate.
	installPair(t, dir, certPath, keyPath, v3cert, v2key)
	reloadCh <- syscall.SIGHUP
	time.Sleep(500 * time.Millisecond) // reload is async; give it time to (not) apply
	for i := 0; i < 3; i++ {
		got, err := servedCN(addr)
		if err != nil {
			t.Fatalf("handshake after a broken rotation: %v", err)
		}
		if got != "v2.rotation.test" {
			t.Fatalf("after a broken rotation: served %q, want the last good v2", got)
		}
	}
	if reused, _ = get(t, client, addr); !reused {
		t.Fatal("the established connection was dropped by the failed reload")
	}
}

// get performs one request and reports whether it rode an existing
// connection and which certificate that connection was negotiated with.
func get(t *testing.T, c *http.Client, addr string) (reused bool, cn string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, "https://"+addr+"/", nil)
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
	}))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}
	return reused, resp.TLS.PeerCertificates[0].Subject.CommonName
}

// servedCN does a fresh TLS handshake and returns the leaf's CommonName.
func servedCN(addr string) (string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true, ServerName: "site.rotation.test"})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName, nil
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func selfSigned(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
}

// installPair replaces the files the way cert-sync does: write a temp file in
// the destination directory, then rename over the target (key first).
func installPair(t *testing.T, dir, certPath, keyPath string, certPEM, keyPEM []byte) {
	t.Helper()
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{keyPath, keyPEM, 0o600}, {certPath, certPEM, 0o644}} {
		tmp, err := os.CreateTemp(dir, ".rotate-")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tmp.Write(f.data); err != nil {
			t.Fatal(err)
		}
		if err := tmp.Chmod(f.mode); err != nil {
			t.Fatal(err)
		}
		tmp.Close()
		if err := os.Rename(tmp.Name(), f.path); err != nil {
			t.Fatal(err)
		}
	}
}
