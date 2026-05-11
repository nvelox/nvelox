package tlsutil

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"nvelox/core/logging"

	"golang.org/x/crypto/ocsp"
)

// OCSPStapler fetches and refreshes OCSP responses for TLS certificates.
type OCSPStapler struct {
	cert       *tls.Certificate
	issuer     *x509.Certificate
	mu         sync.Mutex
	nextUpdate time.Time // NextUpdate of the currently-stapled response; zero if none
	stopCh     chan struct{}
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

// Start begins periodic OCSP response fetching. The refresh cadence is
// adaptive: we refresh at NextUpdate-1h (or hourly, whichever is sooner)
// so a stapled response never drifts close to expiry in production.
func (s *OCSPStapler) Start() {
	// Initial fetch
	s.refresh()

	go func() {
		for {
			// Compute next refresh delay based on current staple's NextUpdate.
			// If we don't have a live response yet, retry in 5 minutes.
			delay := s.nextRefreshDelay()
			timer := time.NewTimer(delay)
			select {
			case <-s.stopCh:
				timer.Stop()
				return
			case <-timer.C:
				s.refresh()
			}
		}
	}()
}

// nextRefreshDelay returns how long to wait before the next refresh. It
// targets NextUpdate-1h so the staple is always rotated before expiry;
// falls back to 5 minutes if there is no valid NextUpdate yet.
func (s *OCSPStapler) nextRefreshDelay() time.Duration {
	s.mu.Lock()
	next := s.nextUpdate
	s.mu.Unlock()
	if next.IsZero() {
		return 5 * time.Minute
	}
	d := time.Until(next.Add(-1 * time.Hour))
	if d < 1*time.Minute {
		return 1 * time.Minute
	}
	if d > 24*time.Hour {
		return 24 * time.Hour
	}
	return d
}

// Stop halts the stapler.
func (s *OCSPStapler) Stop() {
	close(s.stopCh)
}

// ocspFreshnessSkew is the tolerated clock-skew window for OCSP freshness
// checks. 5 minutes matches what most TLS clients tolerate.
const ocspFreshnessSkew = 5 * time.Minute

// validateOCSPFreshness rejects OCSP responses that are not currently valid.
// Zero ThisUpdate / NextUpdate (optional per RFC 6960) is skipped.
func validateOCSPFreshness(thisUpdate, nextUpdate, now time.Time) error {
	if !thisUpdate.IsZero() && now.Add(ocspFreshnessSkew).Before(thisUpdate) {
		return fmt.Errorf("response ThisUpdate %v is in the future — rejecting", thisUpdate)
	}
	if !nextUpdate.IsZero() && now.After(nextUpdate.Add(ocspFreshnessSkew)) {
		return fmt.Errorf("response expired at NextUpdate=%v — rejecting", nextUpdate)
	}
	return nil
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

	// ParseResponse with a non-nil issuer validates the OCSP responder's
	// signature against the issuer's public key.
	ocspResp, err := ocsp.ParseResponse(body, s.issuer)
	if err != nil {
		logging.Warn("[OCSP] Failed to parse OCSP response: %v", err)
		return
	}

	// Freshness: reject responses that are not currently valid.
	// Without these checks, a cached-before-revocation response keeps
	// getting stapled indefinitely (or a MITM can replay an old Good
	// response against a since-revoked cert).
	if err := validateOCSPFreshness(ocspResp.ThisUpdate, ocspResp.NextUpdate, time.Now()); err != nil {
		logging.Warn("[OCSP] %v", err)
		return
	}

	if ocspResp.Status == ocsp.Good {
		s.mu.Lock()
		s.cert.OCSPStaple = body
		s.nextUpdate = ocspResp.NextUpdate
		s.mu.Unlock()
		logging.Info("[OCSP] Staple refreshed, valid until %v", ocspResp.NextUpdate)
	} else {
		logging.Warn("[OCSP] Certificate status: %d (not good)", ocspResp.Status)
	}
}
