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
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nvelox/config"
	"nvelox/core"
)

// generateTestCert creates a self-signed cert+key pair in tmpDir and returns file paths.
func generateTestCert(t *testing.T, tmpDir string) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certFile = filepath.Join(tmpDir, "cert.pem")
	keyFile = filepath.Join(tmpDir, "key.pem")

	certOut, _ := os.Create(certFile)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyOut, _ := os.Create(keyFile)
	pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	keyOut.Close()

	return certFile, keyFile
}

func TestTLS_EndToEnd(t *testing.T) {
	backend := startEchoServer(t)
	proxyPort := getFreePort(t)
	tmpDir := t.TempDir()
	certFile, keyFile := generateTestCert(t, tmpDir)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{
			{
				Name:           "tls-test",
				Bind:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
				Protocol:       "tcp",
				DefaultBackend: "tls-pool",
			},
		},
		Backends: []config.Backend{
			{
				Name:    "tls-pool",
				Balance: "roundrobin",
				Servers: []string{backend},
			},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "tls-test",
			Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol:       "tcp",
			DefaultBackend: "tls-pool",
			Port:           proxyPort,
			TLS: &config.TLSConfig{
				Cert: certFile,
				Key:  keyFile,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- engine.Start(ctx)
	}()

	time.Sleep(300 * time.Millisecond)

	// Connect with TLS
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp",
		fmt.Sprintf("127.0.0.1:%d", proxyPort),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		t.Fatalf("TLS dial failed: %v", err)
	}
	defer tlsConn.Close()

	// Send data through proxy
	msg := "hello-tls"
	_, err = tlsConn.Write([]byte(msg))
	if err != nil {
		t.Fatalf("TLS write failed: %v", err)
	}

	buf := make([]byte, 64)
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := tlsConn.Read(buf)
	if err != nil {
		t.Fatalf("TLS read failed: %v", err)
	}

	if string(buf[:n]) != msg {
		t.Errorf("expected %q, got %q", msg, string(buf[:n]))
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Errorf("engine error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("engine didn't stop in time")
	}
}

func TestTLS_PlaintextClientFails(t *testing.T) {
	backend := startEchoServer(t)
	proxyPort := getFreePort(t)
	tmpDir := t.TempDir()
	certFile, keyFile := generateTestCert(t, tmpDir)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
		Listeners: []config.Listener{
			{
				Name:           "tls-plain-test",
				Bind:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
				Protocol:       "tcp",
				DefaultBackend: "tls-pool2",
			},
		},
		Backends: []config.Backend{
			{
				Name:    "tls-pool2",
				Balance: "roundrobin",
				Servers: []string{backend},
			},
		},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "tls-plain-test",
			Addr:           fmt.Sprintf("127.0.0.1:%d", proxyPort),
			Protocol:       "tcp",
			DefaultBackend: "tls-pool2",
			Port:           proxyPort,
			TLS: &config.TLSConfig{
				Cert: certFile,
				Key:  keyFile,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go engine.Start(ctx)
	time.Sleep(300 * time.Millisecond)

	// Plaintext connection to TLS listener should fail to get meaningful echo
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
	if err != nil {
		// Connection refused is acceptable
		cancel()
		return
	}
	defer conn.Close()

	conn.Write([]byte("hello"))
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := conn.Read(buf)

	// Either read error or garbled response (TLS handshake response, not "hello")
	if err == nil && string(buf[:n]) == "hello" {
		t.Error("plaintext connection should not get valid echo from TLS listener")
	}

	cancel()
}

func TestTLS_InvalidCertFails(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "bad_cert.pem")
	keyFile := filepath.Join(tmpDir, "bad_key.pem")
	os.WriteFile(certFile, []byte("not a cert"), 0644)
	os.WriteFile(keyFile, []byte("not a key"), 0644)

	cfg := &config.Config{
		Version: "2",
		Logging: config.LoggingConfig{Level: "debug"},
	}

	engine := core.NewEngine(cfg)
	engine.Listeners = []*core.ListenerConfig{
		{
			Name:           "bad-tls",
			Addr:           "127.0.0.1:19999",
			Protocol:       "tcp",
			DefaultBackend: "pool",
			Port:           19999,
			TLS: &config.TLSConfig{
				Cert: certFile,
				Key:  keyFile,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := engine.Start(ctx)
	if err == nil {
		t.Error("expected error for invalid TLS cert/key, got nil")
	}
}
