package tlsutil

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"sync"
	"time"

	"nvelox/core/logging"

	"golang.org/x/crypto/ocsp"
)

// OCSPStapler fetches and refreshes OCSP responses for TLS certificates.
type OCSPStapler struct {
	cert   *tls.Certificate
	issuer *x509.Certificate
	mu     sync.Mutex
	stopCh chan struct{}
}

// NewOCSPStapler creates a stapler that will periodically refresh the OCSP response.
func NewOCSPStapler(cert *tls.Certificate) *OCSPStapler {
	s := &OCSPStapler{
		cert:   cert,
		stopCh: make(chan struct{}),
	}

	// Parse the leaf certificate to find the issuer
	if len(cert.Certificate) > 1 {
		issuer, err := x509.ParseCertificate(cert.Certificate[1])
		if err == nil {
			s.issuer = issuer
		}
	}

	return s
}

// Start begins periodic OCSP response fetching.
func (s *OCSPStapler) Start() {
	// Initial fetch
	s.refresh()

	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.refresh()
			}
		}
	}()
}

// Stop halts the stapler.
func (s *OCSPStapler) Stop() {
	close(s.stopCh)
}

func (s *OCSPStapler) refresh() {
	leaf, err := x509.ParseCertificate(s.cert.Certificate[0])
	if err != nil {
		logging.Error("[OCSP] Failed to parse leaf certificate: %v", err)
		return
	}

	if len(leaf.OCSPServer) == 0 {
		logging.Warn("[OCSP] No OCSP server URL in certificate")
		return
	}

	if s.issuer == nil {
		logging.Warn("[OCSP] No issuer certificate available for OCSP request")
		return
	}

	ocspReq, err := ocsp.CreateRequest(leaf, s.issuer, nil)
	if err != nil {
		logging.Error("[OCSP] Failed to create OCSP request: %v", err)
		return
	}

	ocspURL := leaf.OCSPServer[0]

	// POST the OCSP request with proper body and timeout
	httpClient := &http.Client{Timeout: 10 * time.Second}
	httpResp, err := httpClient.Post(ocspURL, "application/ocsp-request", bytes.NewReader(ocspReq))
	if err != nil {
		logging.Error("[OCSP] Failed to fetch OCSP response from %s: %v", ocspURL, err)
		return
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		logging.Error("[OCSP] Failed to read OCSP response: %v", err)
		return
	}

	ocspResp, err := ocsp.ParseResponse(body, s.issuer)
	if err != nil {
		logging.Warn("[OCSP] Failed to parse OCSP response: %v", err)
		return
	}

	if ocspResp.Status == ocsp.Good {
		s.mu.Lock()
		s.cert.OCSPStaple = body
		s.mu.Unlock()
		logging.Info("[OCSP] Staple refreshed, valid until %v", ocspResp.NextUpdate)
	} else {
		logging.Warn("[OCSP] Certificate status: %d (not good)", ocspResp.Status)
	}
}
