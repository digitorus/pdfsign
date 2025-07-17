package verify

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// performExternalOCSPCheck performs an external OCSP check for the given certificate
func performExternalOCSPCheck(cert, issuer *x509.Certificate, options *VerifyOptions) (*ocsp.Response, error) {
	if !options.EnableExternalRevocationCheck {
		return nil, fmt.Errorf("external revocation checking is disabled")
	}

	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("certificate has no OCSP server URLs")
	}

	// Create OCSP request
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %v", err)
	}

	// Get HTTP client with timeout
	client := options.HTTPClient
	if client == nil {
		timeout := options.HTTPTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}

	// Try each OCSP server URL
	var lastErr error
	for _, serverURL := range cert.OCSPServer {
		resp, err := http.Post(serverURL, "application/ocsp-request", bytes.NewReader(ocspReq))
		if err != nil {
			lastErr = fmt.Errorf("failed to contact OCSP server %s: %v", serverURL, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("OCSP server %s returned status %d", serverURL, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read OCSP response from %s: %v", serverURL, err)
			continue
		}

		ocspResp, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse OCSP response from %s: %v", serverURL, err)
			continue
		}

		// Successfully got OCSP response
		return ocspResp, nil
	}

	return nil, lastErr
}

// performExternalCRLCheck performs an external CRL check for the given certificate
// Returns (revocationTime, isRevoked, error)
func performExternalCRLCheck(cert *x509.Certificate, options *VerifyOptions) (*time.Time, bool, error) {
	if !options.EnableExternalRevocationCheck {
		return nil, false, fmt.Errorf("external revocation checking is disabled")
	}

	if len(cert.CRLDistributionPoints) == 0 {
		return nil, false, fmt.Errorf("certificate has no CRL distribution points")
	}

	// Get HTTP client with timeout
	client := options.HTTPClient
	if client == nil {
		timeout := options.HTTPTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}

	// Try each CRL distribution point
	var lastErr error
	for _, crlURL := range cert.CRLDistributionPoints {
		resp, err := client.Get(crlURL)
		if err != nil {
			lastErr = fmt.Errorf("failed to download CRL from %s: %v", crlURL, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("CRL server %s returned status %d", crlURL, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read CRL from %s: %v", crlURL, err)
			continue
		}

		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse CRL from %s: %v", crlURL, err)
			continue
		}

		// Check if certificate is revoked
		for _, revokedCert := range crl.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return &revokedCert.RevocationTime, true, nil // Certificate is revoked
			}
		}

		// Successfully checked CRL, certificate not revoked
		return nil, false, nil
	}

	return nil, false, lastErr
}
