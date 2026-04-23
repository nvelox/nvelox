package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nvelox/config"
)

func TestConfigureClientAuth_None(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureClientAuth(tlsCfg, config.TLSConfig{ClientAuth: "none"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientAuth != tls.NoClientCert {
		t.Errorf("expected NoClientCert, got %v", tlsCfg.ClientAuth)
	}
}

func TestConfigureClientAuth_Empty(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureClientAuth(tlsCfg, config.TLSConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigureClientAuth_Require(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureClientAuth(tlsCfg, config.TLSConfig{ClientAuth: "require"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("expected RequireAndVerifyClientCert, got %v", tlsCfg.ClientAuth)
	}
}

func TestConfigureClientAuth_Request(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureClientAuth(tlsCfg, config.TLSConfig{ClientAuth: "request"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientAuth != tls.RequestClientCert {
		t.Errorf("expected RequestClientCert, got %v", tlsCfg.ClientAuth)
	}
}

func TestConfigureClientAuth_Invalid(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureClientAuth(tlsCfg, config.TLSConfig{ClientAuth: "invalid"})
	if err == nil {
		t.Error("expected error for invalid client_auth value")
	}
}

func TestConfigureClientAuth_WithCA(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.pem")

	// Generate a real self-signed CA cert for testing
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	os.WriteFile(caFile, certPEM, 0644)

	tlsCfg := &tls.Config{}
	err := ConfigureClientAuth(tlsCfg, config.TLSConfig{
		ClientAuth: "require",
		ClientCA:   caFile,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsCfg.ClientCAs == nil {
		t.Error("expected ClientCAs pool to be set")
	}
}

func TestConfigureClientAuth_MissingCA(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureClientAuth(tlsCfg, config.TLSConfig{
		ClientAuth: "require",
		ClientCA:   "/nonexistent/ca.pem",
	})
	if err == nil {
		t.Error("expected error for missing CA file")
	}
}

func TestClientAuthMode(t *testing.T) {
	if ClientAuthMode("require") != tls.RequireAndVerifyClientCert {
		t.Error("require should map to RequireAndVerifyClientCert")
	}
	if ClientAuthMode("request") != tls.RequestClientCert {
		t.Error("request should map to RequestClientCert")
	}
	if ClientAuthMode("none") != tls.NoClientCert {
		t.Error("none should map to NoClientCert")
	}
	if ClientAuthMode("") != tls.NoClientCert {
		t.Error("empty should map to NoClientCert")
	}
}
