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

func TestConfigureClientAuth_RequireWithoutCA(t *testing.T) {
	tlsCfg := &tls.Config{}
	err := ConfigureClientAuth(tlsCfg, config.TLSConfig{ClientAuth: "require"})
	if err == nil {
		t.Error("expected error for require without client_ca")
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

func TestValidateOCSPFreshness(t *testing.T) {
	now := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	past := now.Add(-2 * time.Hour)
	future := now.Add(2 * time.Hour)
	zero := time.Time{}

	cases := []struct {
		name               string
		thisUpdate, nextUp time.Time
		wantErr            bool
	}{
		{"valid window", past, future, false},
		{"just-issued at now", now, future, false},
		{"expired by NextUpdate", past, past, true},
		{"ThisUpdate in the future (beyond skew)", future, future.Add(1 * time.Hour), true},
		{"ThisUpdate within skew window", now.Add(1 * time.Minute), future, false},
		{"expired within skew window", past, now.Add(-1 * time.Minute), false},
		{"zero ThisUpdate skipped", zero, future, false},
		{"zero NextUpdate skipped", past, zero, false},
		{"both zero = accept", zero, zero, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateOCSPFreshness(c.thisUpdate, c.nextUp, now)
			if (err != nil) != c.wantErr {
				t.Errorf("validateOCSPFreshness(%v, %v, %v): wantErr=%v, got %v",
					c.thisUpdate, c.nextUp, now, c.wantErr, err)
			}
		})
	}
}

func TestOCSPStapler_NextRefreshDelay(t *testing.T) {
	s := &OCSPStapler{}

	// No live response yet: retry soon.
	if d := s.nextRefreshDelay(); d != 5*time.Minute {
		t.Errorf("no staple: expected 5m, got %v", d)
	}

	// NextUpdate in 10 hours → refresh in ~9 hours.
	s.nextUpdate = time.Now().Add(10 * time.Hour)
	d := s.nextRefreshDelay()
	if d < 8*time.Hour || d > 10*time.Hour {
		t.Errorf("10h NextUpdate: expected ~9h delay, got %v", d)
	}

	// NextUpdate in the past: clamp to 1m minimum (so we retry soon without hammering).
	s.nextUpdate = time.Now().Add(-1 * time.Hour)
	d = s.nextRefreshDelay()
	if d != 1*time.Minute {
		t.Errorf("past NextUpdate: expected 1m floor, got %v", d)
	}

	// NextUpdate way in the future: cap at 24h.
	s.nextUpdate = time.Now().Add(30 * 24 * time.Hour)
	d = s.nextRefreshDelay()
	if d != 24*time.Hour {
		t.Errorf("far-future NextUpdate: expected 24h ceiling, got %v", d)
	}
}
