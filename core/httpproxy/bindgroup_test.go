package httpproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nvelox/config"
)

// genCertWithCN creates a self-signed cert+key with the given CommonName,
// returning the file paths. Used to verify SNI-based cert dispatch.
func genCertWithCN(t *testing.T, dir, cn string) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	certPath = filepath.Join(dir, cn+".pem")
	keyPath = filepath.Join(dir, cn+".key")
	cf, _ := os.Create(certPath)
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()
	kf, _ := os.Create(keyPath)
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()
	return certPath, keyPath
}

// newSite builds a minimal HTTPServer (Site) for tests: just enough fields
// for the BindGroup TLS / dispatch tests. It does NOT call NewHTTPServer to
// avoid pulling in balancers etc.
func newSite(name string, names []string, defaultSrv bool, certPath, keyPath string) *HTTPServer {
	tlsCfg := &config.TLSConfig{Cert: certPath, Key: keyPath}
	return &HTTPServer{
		Listener: &ListenerConfig{
			Name:          name,
			Addr:          ":443",
			Protocol:      "https",
			TLS:           tlsCfg,
			ServerNames:   names,
			DefaultServer: defaultSrv,
		},
	}
}

// TestBindGroup_PickCert verifies SNI-based cert selection picks the correct
// cert for: exact name, wildcard, default fallback, no SNI.
func TestBindGroup_PickCert(t *testing.T) {
	dir := t.TempDir()
	apiCert, apiKey := genCertWithCN(t, dir, "api.example.com")
	wildCert, wildKey := genCertWithCN(t, dir, "wild.example.com") // CN doesn't have to match patterns
	defCert, defKey := genCertWithCN(t, dir, "default.example.com")

	g := NewBindGroup(":443", "https")
	g.AddSite(newSite("api", []string{"api.example.com"}, false, apiCert, apiKey))
	g.AddSite(newSite("wild", []string{"*.example.com"}, false, wildCert, wildKey))
	g.AddSite(newSite("default", nil, true, defCert, defKey))

	if _, err := g.buildTLSConfig(); err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	cases := []struct {
		sni  string
		want string // expected cert source (matched by Leaf.Subject.CommonName)
	}{
		{"api.example.com", "api.example.com"},                  // exact
		{"other.example.com", "wild.example.com"},               // wildcard
		{"unknown.com", "default.example.com"},                  // fallback to default
		{"", "default.example.com"},                             // no SNI → default
	}
	for _, c := range cases {
		t.Run(c.sni, func(t *testing.T) {
			cert := g.pickCert(c.sni)
			if cert == nil || len(cert.Certificate) == 0 {
				t.Fatalf("nil cert for sni %q", c.sni)
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatalf("parse leaf: %v", err)
			}
			if leaf.Subject.CommonName != c.want {
				t.Errorf("sni %q got CN %q, want %q", c.sni, leaf.Subject.CommonName, c.want)
			}
		})
	}
}

// TestBindGroup_PickCert_NoDefault: when no DefaultServer is set and SNI
// matches nothing, pickCert should still return *something* (the implicit
// first-site default) rather than nil — matches today's single-site behaviour.
func TestBindGroup_PickCert_NoDefault(t *testing.T) {
	dir := t.TempDir()
	c1, k1 := genCertWithCN(t, dir, "a.example.com")
	c2, k2 := genCertWithCN(t, dir, "b.example.com")

	g := NewBindGroup(":443", "https")
	g.AddSite(newSite("a", []string{"a.example.com"}, false, c1, k1))
	g.AddSite(newSite("b", []string{"b.example.com"}, false, c2, k2))

	if _, err := g.buildTLSConfig(); err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}

	// The first site is the implicit default — unknown SNI gets a.example.com.
	cert := g.pickCert("nope.example.com")
	if cert == nil {
		t.Fatal("expected fallback cert, got nil")
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	if leaf.Subject.CommonName != "a.example.com" {
		t.Errorf("implicit default: got CN %q, want a.example.com", leaf.Subject.CommonName)
	}
}
