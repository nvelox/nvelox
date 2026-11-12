package core

// Shared helpers for the L4 / TLS / UDP security tests (st = security test).

import (
	"bytes"
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
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/proxy"

	"github.com/pires/go-proxyproto"
)

// stPKI is a test CA with a server certificate (localhost, 127.0.0.1) and
// the ability to issue client certificates.
type stPKI struct {
	caPath          string
	caPool          *x509.CertPool
	caCert          *x509.Certificate
	caKey           *ecdsa.PrivateKey
	srvCert, srvKey string
	serial          atomic.Int64
	dir             string
}

func newSTPKI(t *testing.T, name string) *stPKI {
	t.Helper()
	p := &stPKI{dir: t.TempDir()}
	p.serial.Store(1)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name + "-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p.caCert, _ = x509.ParseCertificate(der)
	p.caKey = key
	p.caPool = x509.NewCertPool()
	p.caPool.AddCert(p.caCert)
	p.caPath = filepath.Join(p.dir, "ca.pem")
	if err := os.WriteFile(p.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := p.issue(t, "localhost", x509.ExtKeyUsageServerAuth,
		[]string{"localhost", "a.test", "b.test", "c.test"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	p.srvCert = filepath.Join(p.dir, "server.pem")
	p.srvKey = filepath.Join(p.dir, "server.key")
	os.WriteFile(p.srvCert, certPEM, 0o600)
	os.WriteFile(p.srvKey, keyPEM, 0o600)
	return p
}

func (p *stPKI) issue(t *testing.T, cn string, usage x509.ExtKeyUsage, dns []string, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial.Add(1)), Subject: pkix.Name{CommonName: cn},
		DNSNames: dns, IPAddresses: ips,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// clientCert issues a client certificate signed by this CA.
func (p *stPKI) clientCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	certPEM, keyPEM := p.issue(t, cn, x509.ExtKeyUsageClientAuth, nil, nil)
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func stFreeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func stFreeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().String()
}

// stTCPEchoBackend echoes every connection and counts accepted ones.
func stTCPEchoBackend(t *testing.T) (addr string, accepted *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted = new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String(), accepted
}

// stUDPBackend runs a UDP server that records every datagram it receives
// and, when reply is set, answers with reply(datagram).
func stUDPBackend(t *testing.T, reply func([]byte) []byte) (addr string, got chan []byte) {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	got = make(chan []byte, 1024)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			d := append([]byte(nil), buf[:n]...)
			select {
			case got <- d:
			default:
			}
			if reply != nil {
				c.WriteToUDP(reply(d), from)
			}
		}
	}()
	return c.LocalAddr().String(), got
}

func stEchoReply(b []byte) []byte { return b }

// stStart starts an engine for cfg (listeners expanded like main.go), waits
// until startup completed and stops it at cleanup. tweak runs before Start.
func stStart(t *testing.T, cfg *config.Config, tweak func(*Engine)) *Engine {
	t.Helper()
	if cfg.Version == "" {
		cfg.Version = "2"
	}
	exp, err := ExpandListeners(cfg.Listeners)
	if err != nil {
		t.Fatalf("expand listeners: %v", err)
	}
	e := NewEngine(cfg)
	e.Listeners = exp
	e.DrainTimeout = 2 * time.Second
	if tweak != nil {
		tweak(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("engine did not stop within 10s")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("engine stopped during startup: %v", err)
		default:
		}
		e.reloadMu.Lock()
		up := e.l4Handler != nil
		e.reloadMu.Unlock()
		if up {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("engine did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Start holds reloadMu until every listener is up; taking it once more
	// orders the test after that.
	e.reloadMu.Lock()
	e.reloadMu.Unlock()
	return e
}

// stHandler returns the engine's L4 handler (set by Start).
func stHandler(e *Engine) *ProxyEventHandler {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()
	return e.l4Handler
}

// stEcho writes msg on c and expects it back within 2 s.
func stEcho(c net.Conn, msg string) error {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo mismatch: %q", buf)
	}
	return nil
}

// stRefused asserts the proxy closes c without relaying msg.
func stRefused(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if err := stEcho(c, msg); err == nil {
		t.Fatalf("connection was relayed; want it refused")
	} else {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("connection hung instead of being closed: %v", err)
		}
	}
}

// stUDPExchange sends payload to addr from a fresh socket bound to srcIP and
// returns the first reply.
func stUDPExchange(srcIP, addr string, payload []byte, wait time.Duration) ([]byte, error) {
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(srcIP)}, raddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Write(payload); err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// stUDPDatagramWithProxy prefixes payload with a PROXY v2 DGRAM header
// naming client (as a trusted relay sends it).
func stUDPDatagramWithProxy(t *testing.T, client string, dst string, payload []byte) []byte {
	t.Helper()
	src, err := net.ResolveUDPAddr("udp", client)
	if err != nil {
		t.Fatal(err)
	}
	d, err := net.ResolveUDPAddr("udp", dst)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := proxy.WriteProxyHeaderV2(&b, src, d); err != nil {
		t.Fatal(err)
	}
	return append(b.Bytes(), payload...)
}

// stTCPProxyHeader writes a PROXY v2 header naming client on c.
func stTCPProxyHeader(t *testing.T, c net.Conn, client string) {
	t.Helper()
	src, err := net.ResolveTCPAddr("tcp", client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := proxyproto.HeaderProxyFromAddrs(2, src, c.RemoteAddr()).WriteTo(c); err != nil {
		t.Fatal(err)
	}
}

// stWaitGot waits for a datagram on got (true) or times out (false).
func stWaitGot(got chan []byte, wait time.Duration) ([]byte, bool) {
	select {
	case d := <-got:
		return d, true
	case <-time.After(wait):
		return nil, false
	}
}

// stDrain empties got.
func stDrain(got chan []byte) {
	for {
		select {
		case <-got:
		default:
			return
		}
	}
}
