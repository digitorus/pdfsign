package sign

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"

	"sync"

	"github.com/digitorus/pdfsign/revocation"
	"golang.org/x/crypto/ocsp"
)

// RevocationCache interfaces caching for revocation data.
type RevocationCache interface {
	Get(key string) ([]byte, bool)
	Put(key string, data []byte)
}

// MemoryCache implements a simple thread-safe in-memory cache.
type MemoryCache struct {
	mu    sync.RWMutex
	items map[string][]byte
}

func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		items: make(map[string][]byte),
	}
}

func (c *MemoryCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, ok := c.items[key]
	return data, ok
}

func (c *MemoryCache) Put(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = data
}

func embedOCSPRevocationStatus(cert, issuer *x509.Certificate, i *revocation.InfoArchival, cache RevocationCache) error {
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return err
	}

	ocspUrl := fmt.Sprintf("%s/%s", strings.TrimRight(cert.OCSPServer[0], "/"),
		base64.StdEncoding.EncodeToString(req))

	if cache != nil {
		if data, ok := cache.Get(ocspUrl); ok {
			return i.AddOCSP(data)
		}
	}

	resp, err := http.Get(ocspUrl)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// check if we got a valid OCSP response
	ocspResp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		return err
	}
	if ocspResp.Status != ocsp.Good {
		return fmt.Errorf("OCSP status is not 'Good': %v", ocspResp.Status)
	}

	if cache != nil {
		cache.Put(ocspUrl, body)
	}

	return i.AddOCSP(body)
}

// embedCRLRevocationStatus requires an issuer as it needs to implement the
// the interface, a nil argment might be given if the issuer is not known.
func embedCRLRevocationStatus(cert, issuer *x509.Certificate, i *revocation.InfoArchival, cache RevocationCache) error {
	crlUrl := cert.CRLDistributionPoints[0]
	if cache != nil {
		if data, ok := cache.Get(crlUrl); ok {
			return i.AddCRL(data)
		}
	}

	resp, err := http.Get(crlUrl)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Verify CRL signature and content
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return fmt.Errorf("failed to parse CRL: %v", err)
	}

	if err := crl.CheckSignatureFrom(issuer); err != nil {
		// Just log or strictly fail? Strict fail is better for security.
		return fmt.Errorf("CRL signature invalid: %v", err)
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return fmt.Errorf("certificate is revoked in CRL")
		}
	}

	if cache != nil {
		cache.Put(crlUrl, body)
	}

	return i.AddCRL(body)
}

// RevocationOptions configures how revocation status is fetched and embedded.
type RevocationOptions struct {
	EmbedOCSP     bool
	EmbedCRL      bool
	PreferCRL     bool            // If true, try CRL before OCSP.
	StopOnSuccess bool            // If true, stop after successfully embedding one status.
	Cache         RevocationCache // Optional cache for revocation data.
}

// NewRevocationFunction creates a RevocationFunction with the specified options.
func NewRevocationFunction(opts RevocationOptions) RevocationFunction {
	return func(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error {
		// Wrapper for OCSP that returns (embedded, error)
		tryOCSP := func() (bool, error) {
			if opts.EmbedOCSP && issuer != nil && len(cert.OCSPServer) > 0 {
				err := embedOCSPRevocationStatus(cert, issuer, i, opts.Cache)
				return err == nil, err
			}
			return false, nil
		}

		// Wrapper for CRL that returns (embedded, error)
		tryCRL := func() (bool, error) {
			if opts.EmbedCRL && len(cert.CRLDistributionPoints) > 0 {
				err := embedCRLRevocationStatus(cert, issuer, i, opts.Cache)
				return err == nil, err
			}
			return false, nil
		}

		var first, second func() (bool, error)
		if opts.PreferCRL {
			first, second = tryCRL, tryOCSP
		} else {
			first, second = tryOCSP, tryCRL
		}

		embedded, err := first()
		if err == nil {
			if opts.StopOnSuccess && embedded {
				return nil
			}
		} else {
			_ = err // Ignore first error, will fallback to second
		}

		// Proceed to second if first failed or if we don't stop on success
		embedded2, err2 := second()
		if err2 != nil {
			// If both failed, we return error.
			// If first failed and second failed, return combined.
			// If first succeeded (embedded=true) and second failed, we usually ignore second error if not strict?
			if embedded {
				return nil
			}
			if err != nil {
				return fmt.Errorf("revocation check failed: primary=%v, secondary=%v", err, err2)
			}
			return err2
		}

		if embedded || embedded2 {
			return nil
		}

		// If neither embedded, but we had an error in first (and second was skipped/nil), return first error
		if err != nil {
			return err
		}

		return nil
	}
}

func DefaultEmbedRevocationStatusFunction(cert, issuer *x509.Certificate, i *revocation.InfoArchival) error {
	// Default behavior: Try both, OCSP first, do not stop on success (embed both if possible).
	return NewRevocationFunction(RevocationOptions{
		EmbedOCSP:     true,
		EmbedCRL:      true,
		PreferCRL:     false,
		StopOnSuccess: false,
	})(cert, issuer, i)
}
