package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/digitorus/pdfsign/internal/ocspx"
	"golang.org/x/crypto/ocsp"
)

// requestContext returns options.Context, defaulting to context.Background()
// when unset.
func requestContext(options *VerifyOptions) context.Context {
	if options.Context != nil {
		return options.Context
	}
	return context.Background()
}

// OCSPRequestFunc allows mocking OCSP request creation for tests
type OCSPRequestFunc func(cert, issuer *x509.Certificate) ([]byte, error)

// performExternalOCSPCheck performs an external OCSP check for the given certificate
func performExternalOCSPCheck(cert, issuer *x509.Certificate, options *VerifyOptions) (*ocsp.Response, error, error) {
	return performExternalOCSPCheckWithFunc(cert, issuer, options, nil)
}

// performExternalOCSPCheckWithFunc allows injecting a custom OCSP request function for testing.
// Returns (response, warning, err): warning is a non-fatal condition (e.g.
// an unexpected response Content-Type) to surface to the caller, nil when
// there's nothing to warn about.
func performExternalOCSPCheckWithFunc(cert, issuer *x509.Certificate, options *VerifyOptions, ocspRequestFunc OCSPRequestFunc) (*ocsp.Response, error, error) {
	if !options.EnableExternalRevocationCheck {
		return nil, nil, fmt.Errorf("external revocation checking is disabled")
	}

	if len(cert.OCSPServer) == 0 {
		return nil, nil, fmt.Errorf("certificate has no OCSP server URLs")
	}

	// Create OCSP request (use injected func if provided)
	var ocspReq []byte
	var err error
	if ocspRequestFunc != nil {
		ocspReq, err = ocspRequestFunc(cert, issuer)
	} else {
		ocspReq, err = ocsp.CreateRequest(cert, issuer, ocspRequestOptions(cert, issuer))
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create OCSP request: %v", err)
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

	maxBytes := options.MaxOCSPResponseBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxOCSPResponseBytes
	}

	ctx := requestContext(options)

	// Try each OCSP server URL
	var lastErr error
	for _, serverURL := range cert.OCSPServer {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, bytes.NewReader(ocspReq))
		if err != nil {
			lastErr = fmt.Errorf("failed to build OCSP request for %s: %v", serverURL, err)
			continue
		}
		// RFC 6960 SS4.2.1: request and response bodies are DER-encoded
		// ASN.1; the request Content-Type and the Accept for the response
		// each have exactly one RFC-defined value.
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to contact OCSP server %s: %v", serverURL, err)
			continue
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				// Log error but don't fail the operation
				lastErr = fmt.Errorf("failed to close response body: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("OCSP server %s returned status %d", serverURL, resp.StatusCode)
			continue
		}

		warning := checkContentType(resp, serverURL, "application/ocsp-response", "RFC 6960 SS4.2.1")

		body, err := readLimitedBody(resp, maxBytes)
		if err != nil {
			lastErr = fmt.Errorf("failed to read OCSP response from %s: %v", serverURL, err)
			continue
		}

		ocspResp, err := ocspx.ParseResponseForCert(body, cert, issuer)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse OCSP response from %s (content-type %q): %v", serverURL, resp.Header.Get("Content-Type"), err)
			continue
		}

		// Successfully got OCSP response
		return ocspResp, warning, nil
	}

	return nil, nil, lastErr
}

// ocspRequestOptions avoids introducing SHA-1 CertIDs into an otherwise
// ML-DSA-only validation path. Classical certificate deployments retain the
// historical default for responder compatibility.
func ocspRequestOptions(cert, issuer *x509.Certificate) *ocsp.RequestOptions {
	if cert != nil {
		if _, ok := cert.PublicKey.(*mldsa.PublicKey); ok {
			return &ocsp.RequestOptions{Hash: crypto.SHA512}
		}
	}
	if issuer != nil {
		if _, ok := issuer.PublicKey.(*mldsa.PublicKey); ok {
			return &ocsp.RequestOptions{Hash: crypto.SHA512}
		}
	}
	return nil
}

// performExternalCRLCheck performs an external CRL check for the given certificate.
// Returns (revocationTime, isRevoked, warning, error); warning is a
// non-fatal condition (e.g. an unexpected response Content-Type) to
// surface to the caller, nil when there's nothing to warn about.
func performExternalCRLCheck(cert *x509.Certificate, options *VerifyOptions) (*time.Time, bool, error, error) {
	return performExternalCRLCheckWithIssuer(cert, nil, options)
}

// performExternalCRLCheckWithIssuer additionally verifies the CRL signature
// when the certificate chain supplies its issuer. The wrapper above preserves
// the existing test helper/API shape for callers that only need retrieval and
// parsing behavior.
func performExternalCRLCheckWithIssuer(cert, issuer *x509.Certificate, options *VerifyOptions) (*time.Time, bool, error, error) {
	if !options.EnableExternalRevocationCheck {
		return nil, false, nil, fmt.Errorf("external revocation checking is disabled")
	}

	if len(cert.CRLDistributionPoints) == 0 {
		return nil, false, nil, fmt.Errorf("certificate has no CRL distribution points")
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

	maxBytes := options.MaxCRLResponseBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxCRLResponseBytes
	}

	ctx := requestContext(options)

	// Try each CRL distribution point
	var lastErr error
	for _, crlURL := range cert.CRLDistributionPoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, crlURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to build CRL request for %s: %v", crlURL, err)
			continue
		}
		// RFC 2585 SS4.2: a CRL retrieval response's Content-Type MUST be
		// application/pkix-crl - that's the only value we ask for. Servers
		// generally don't perform content negotiation on static CRL
		// distribution points and ignore Accept entirely either way; one
		// that actually rejects based on it is non-conformant on the CA's
		// end, not something to route around by requesting non-standard
		// alternates. The response is still accepted and sniffed for format
		// (see decodeCRLBody) rather than gated on Content-Type, since real
		// responders - especially internal/enterprise CAs - are often wrong
		// or inconsistent about this header in practice.
		req.Header.Set("Accept", "application/pkix-crl")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to download CRL from %s: %v", crlURL, err)
			continue
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				// Log error but don't fail the operation
				lastErr = fmt.Errorf("failed to close response body: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("CRL server %s returned status %d", crlURL, resp.StatusCode)
			continue
		}

		warning := checkContentType(resp, crlURL, "application/pkix-crl", "RFC 2585 SS4.2")

		body, err := readLimitedBody(resp, maxBytes)
		if err != nil {
			lastErr = fmt.Errorf("failed to read CRL from %s: %v", crlURL, err)
			continue
		}

		crl, err := x509.ParseRevocationList(decodeCRLBody(body))
		if err != nil {
			lastErr = fmt.Errorf("failed to parse CRL from %s (content-type %q): %v", crlURL, resp.Header.Get("Content-Type"), err)
			continue
		}
		if issuer != nil {
			if err := crl.CheckSignatureFrom(issuer); err != nil {
				lastErr = fmt.Errorf("failed to verify CRL signature from %s: %v", crlURL, err)
				continue
			}
		}

		// Check if certificate is revoked
		for _, revokedCert := range crl.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return &revokedCert.RevocationTime, true, warning, nil // Certificate is revoked
			}
		}

		// Successfully checked CRL, certificate not revoked
		return nil, false, warning, nil
	}

	return nil, false, nil, lastErr
}

// readLimitedBody reads resp.Body, refusing to buffer more than maxBytes.
// It checks Content-Length up front as a fast path when the server
// declares one, and enforces the same limit on the actual stream
// regardless, since Content-Length can be absent or untrustworthy -
// without this, a malicious or misbehaving responder could exhaust memory
// by streaming an arbitrarily large body.
func readLimitedBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("response declares Content-Length %d, exceeding the %d byte limit", resp.ContentLength, maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds the %d byte limit", maxBytes)
	}
	return body, nil
}

// checkContentType returns a *ContentTypeWarning when resp's Content-Type
// doesn't match expected (compared ignoring parameters such as
// ";charset=..."), or nil when it matches or the header is absent
// entirely. This never blocks processing the response - many real-world
// responders, especially internal/enterprise CAs, are wrong or
// inconsistent about this header - it only surfaces a compliance note.
func checkContentType(resp *http.Response, url, expected, rfc string) error {
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return nil
	}
	base, _, err := mime.ParseMediaType(ct)
	if err != nil {
		base = ct
	}
	if strings.EqualFold(base, expected) {
		return nil
	}
	return &ContentTypeWarning{URL: url, Got: ct, Expected: expected, RFC: rfc}
}

// decodeCRLBody returns the DER-encoded CRL bytes from body. Most CRL
// distribution points serve raw DER as RFC 5280 specifies, but some CAs -
// especially internal/enterprise ones - serve PEM-encoded CRLs instead
// ("-----BEGIN X509 CRL-----"). If body is PEM-encoded, its decoded
// contents are returned; otherwise body is returned unchanged.
func decodeCRLBody(body []byte) []byte {
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("-----BEGIN")) {
		return body
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return body
	}
	return block.Bytes
}
