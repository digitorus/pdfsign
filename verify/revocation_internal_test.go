package verify

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pkcs7"
	"golang.org/x/crypto/ocsp"
)

// MockRoundTripper allows mocking HTTP responses
type MockRoundTripper struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req)
}

// TestPerformExternalOCSPCheck_ErrorPaths tests the external OCSP check logic,
// targeting edge cases and error paths in performExternalOCSPCheck and performExternalOCSPCheckWithFunc.
func TestPerformExternalOCSPCheck_ErrorPaths(t *testing.T) {
	// Setup dummy certificates
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(100),
		Subject:      pkix.Name{CommonName: "Issuer"},
		PublicKey:    &struct{}{}, // Simplified
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "Subject"},
		OCSPServer:   []string{"http://ocsp.example.com"},
	}

	tests := []struct {
		name          string
		options       *VerifyOptions
		ocspFunc      OCSPRequestFunc
		roundTripFunc func(req *http.Request) (*http.Response, error)
		expectError   bool
		errorContains string
	}{
		{
			name: "Disabled Checks",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: false,
			},
			expectError:   true,
			errorContains: "disabled",
		},
		{
			name: "No OCSP Server",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
			},
			// Override cert for this case inside the loop or use a modified cert logic?
			// Easier to just pass a cert with no OCSP server in the test execution logic if needed.
			// But for simplicity, we'll assume the cert has it, and handle the "No OCSP Server" case by
			// passing a cert with empty slice in the execution block.
			expectError: false, // We'll handle this special case in logic below
		},
		{
			name: "Request Creation Failed",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
			},
			ocspFunc: func(c, i *x509.Certificate) ([]byte, error) {
				return nil, errors.New("request creation error")
			},
			expectError:   true,
			errorContains: "failed to create OCSP request",
		},
		{
			name: "HTTP Post Failed",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
				HTTPClient: &http.Client{
					Transport: &MockRoundTripper{
						RoundTripFunc: func(req *http.Request) (*http.Response, error) {
							return nil, errors.New("network error")
						},
					},
				},
			},
			ocspFunc: func(c, i *x509.Certificate) ([]byte, error) {
				return []byte("dummy"), nil
			},
			expectError:   true,
			errorContains: "failed to contact OCSP server",
		},
		{
			name: "HTTP Bad Status",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
				HTTPClient: &http.Client{
					Transport: &MockRoundTripper{
						RoundTripFunc: func(req *http.Request) (*http.Response, error) {
							return &http.Response{
								StatusCode: http.StatusInternalServerError,
								Body:       io.NopCloser(bytes.NewReader(nil)),
							}, nil
						},
					},
				},
			},
			ocspFunc: func(c, i *x509.Certificate) ([]byte, error) {
				return []byte("dummy"), nil
			},
			expectError:   true,
			errorContains: "returned status 500",
		},
		{
			name: "Read Body Failed",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
				HTTPClient: &http.Client{
					Transport: &MockRoundTripper{
						RoundTripFunc: func(req *http.Request) (*http.Response, error) {
							// Return a body that fails on read
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(&failReader{}),
							}, nil
						},
					},
				},
			},
			ocspFunc: func(c, i *x509.Certificate) ([]byte, error) {
				return []byte("dummy"), nil
			},
			expectError:   true,
			errorContains: "failed to read OCSP response",
		},
		{
			name: "Parse Response Failed",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
				HTTPClient: &http.Client{
					Transport: &MockRoundTripper{
						RoundTripFunc: func(req *http.Request) (*http.Response, error) {
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(bytes.NewReader([]byte("garbage"))),
							}, nil
						},
					},
				},
			},
			ocspFunc: func(c, i *x509.Certificate) ([]byte, error) {
				return []byte("dummy"), nil
			},
			expectError:   true,
			errorContains: "failed to parse OCSP response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Special handling for "No OCSP Server" case
			currentCert := cert
			if tt.name == "No OCSP Server" {
				currentCert = &x509.Certificate{SerialNumber: big.NewInt(200)} // No URL
				// Error expectations for this case
				tt.expectError = true
				tt.errorContains = "no OCSP server URLs"
			}

			// Execute
			_, _, err := performExternalOCSPCheckWithFunc(currentCert, issuer, tt.options, tt.ocspFunc)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if tt.errorContains != "" {
					if !contains(err.Error(), tt.errorContains) {
						t.Errorf("Expected error containing %q, got %q", tt.errorContains, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestPerformExternalCRLCheck_ErrorPaths tests the external CRL check logic.
func TestPerformExternalCRLCheck_ErrorPaths(t *testing.T) {
	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(123),
		CRLDistributionPoints: []string{"http://crl.example.com"},
	}

	tests := []struct {
		name          string
		options       *VerifyOptions
		roundTripFunc func(req *http.Request) (*http.Response, error)
		expectError   bool
		errorContains string
	}{
		{
			name: "Disabled Checks",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: false,
			},
			expectError:   true,
			errorContains: "disabled",
		},
		{
			name: "HTTP Get Failed",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
				HTTPClient: &http.Client{
					Transport: &MockRoundTripper{
						RoundTripFunc: func(req *http.Request) (*http.Response, error) {
							return nil, errors.New("network error")
						},
					},
				},
			},
			expectError:   true,
			errorContains: "failed to download CRL",
		},
		{
			name: "HTTP Bad Status",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
				HTTPClient: &http.Client{
					Transport: &MockRoundTripper{
						RoundTripFunc: func(req *http.Request) (*http.Response, error) {
							return &http.Response{
								StatusCode: http.StatusNotFound,
								Body:       io.NopCloser(bytes.NewReader(nil)),
							}, nil
						},
					},
				},
			},
			expectError:   true,
			errorContains: "returned status 404",
		},
		{
			name: "Parse CRL Failed",
			options: &VerifyOptions{
				EnableExternalRevocationCheck: true,
				HTTPClient: &http.Client{
					Transport: &MockRoundTripper{
						RoundTripFunc: func(req *http.Request) (*http.Response, error) {
							return &http.Response{
								StatusCode: http.StatusOK,
								Body:       io.NopCloser(bytes.NewReader([]byte("garbage"))),
							}, nil
						},
					},
				},
			},
			expectError:   true,
			errorContains: "failed to parse CRL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := performExternalCRLCheck(cert, tt.options)
			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				} else if tt.errorContains != "" {
					if !contains(err.Error(), tt.errorContains) {
						t.Errorf("Expected error containing %q, got %q", tt.errorContains, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// failReader always fails on Read
type failReader struct{}

func (f *failReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("read error")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr ||
		len(s) > len(substr) && contains(s[1:], substr)
}

// TestPerformExternalOCSPCheck_Wrapper tests the external OCSP check logic wrapper.
func TestPerformExternalOCSPCheck_Wrapper(t *testing.T) {
	// Just hit the wrapper to ensure it calls the internal function
	// We expect error because default options have external check disabled (or we set it)
	_, _, err := performExternalOCSPCheck(nil, nil, DefaultVerifyOptions())
	if err == nil {
		t.Error("Expected error from wrapper when check is disabled")
	}
}

func TestBuildChains_ErrorHandling(t *testing.T) {
	// Test error accumulation logic in buildCertificateChainsWithOptions
	// by providing invalid OCSP/CRL bytes

	p7 := &pkcs7.PKCS7{
		Certificates: []*x509.Certificate{{}},
	}
	signer := NewSigner()
	revInfo := revocation.InfoArchival{
		OCSP: revocation.OCSP{{FullBytes: []byte("garbage")}},
		CRL:  revocation.CRL{{FullBytes: []byte("garbage")}},
	}
	options := DefaultVerifyOptions()

	// This should run without panic and accumulate parse errors into the returned error
	err := buildCertificateChainsWithOptions(p7, signer, revInfo, options, false)
	if err == nil {
		t.Error("Expected non-nil error for unparseable OCSP/CRL data")
	}
}

// TestApplyRevocationStatus_ZeroValueOptionsChecksEmbeddedData proves that a
// bare, zero-value VerifyOptions{} (i.e. a caller who never touches
// SkipRevocationCheck/SkipOCSP/SkipCRL at all) still consults embedded OCSP
// and CRL data. These are opt-OUT switches: the secure, fully-checked
// configuration must be reachable without setting anything.
func TestApplyRevocationStatus_ZeroValueOptionsChecksEmbeddedData(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(42)}
	serialStr := "2a" // hex of 42

	ocspStatus := map[string]*ocsp.Response{
		serialStr: {SerialNumber: big.NewInt(42), Status: ocsp.Good},
	}
	crlStatus := map[string]*time.Time{}

	signer := NewSigner()
	var c Certificate
	options := &VerifyOptions{} // zero value: nothing set

	if err := applyRevocationStatus(cert, nil, ocspStatus, crlStatus, signer, &c, options); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.OCSPEmbedded {
		t.Error("expected embedded OCSP to be consulted with zero-value VerifyOptions, but OCSPEmbedded is false")
	}
}

// TestApplyRevocationStatus_SkipFlags proves the Skip* flags actually
// disable revocation checking (i.e. they are not no-ops either).
func TestApplyRevocationStatus_SkipFlags(t *testing.T) {
	cert := &x509.Certificate{SerialNumber: big.NewInt(42)}
	serialStr := "2a"
	ocspStatus := map[string]*ocsp.Response{
		serialStr: {SerialNumber: big.NewInt(42), Status: ocsp.Good},
	}

	t.Run("SkipOCSP disables OCSP only", func(t *testing.T) {
		signer := NewSigner()
		var c Certificate
		options := &VerifyOptions{SkipOCSP: true}
		if err := applyRevocationStatus(cert, nil, ocspStatus, map[string]*time.Time{}, signer, &c, options); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.OCSPEmbedded {
			t.Error("expected OCSPEmbedded to stay false when SkipOCSP is set")
		}
	})

	t.Run("SkipRevocationCheck disables everything", func(t *testing.T) {
		signer := NewSigner()
		var c Certificate
		options := &VerifyOptions{SkipRevocationCheck: true}
		if err := applyRevocationStatus(cert, nil, ocspStatus, map[string]*time.Time{}, signer, &c, options); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.OCSPEmbedded {
			t.Error("expected OCSPEmbedded to stay false when SkipRevocationCheck is set")
		}
	})
}

// TestApplyRevocationStatus_RevokedCertificateReturnsError proves that a
// certificate found to be revoked produces an actual error, not just the
// informational RevokedCertificate flag - without this, the flag alone
// never propagates into ValidationErrors and Valid() incorrectly stays
// true for a signature made with a revoked certificate.
func TestApplyRevocationStatus_RevokedCertificateReturnsError(t *testing.T) {
	revokedAt := time.Now().Add(-time.Hour)
	cert := &x509.Certificate{SerialNumber: big.NewInt(42)}
	ocspStatus := map[string]*ocsp.Response{
		"2a": {SerialNumber: big.NewInt(42), Status: ocsp.Revoked, RevokedAt: revokedAt},
	}

	signer := NewSigner() // VerificationTime is nil -> conservatively treated as revoked-before-signing
	var c Certificate
	options := &VerifyOptions{}

	err := applyRevocationStatus(cert, nil, ocspStatus, map[string]*time.Time{}, signer, &c, options)
	if err == nil {
		t.Fatal("expected an error for a revoked certificate, got nil")
	}
	if !signer.RevokedCertificate {
		t.Error("expected RevokedCertificate to be true")
	}
}

// TestBuildChains_KeyUsagePolicyViolationReturnsError proves that a leaf
// certificate failing the default KeyUsage/ExtKeyUsage policy (e.g.
// RequireDigitalSignatureKU, RequiredEKUs/AllowedEKUs) produces an actual
// error - without this, validateKeyUsage's result is computed and recorded
// on the Certificate struct but never gates ValidSignature/Valid().
func TestBuildChains_KeyUsagePolicyViolationReturnsError(t *testing.T) {
	p7 := &pkcs7.PKCS7{
		Certificates: []*x509.Certificate{{}}, // no KeyUsage, no ExtKeyUsage
	}
	signer := NewSigner()
	options := DefaultVerifyOptions()

	err := buildCertificateChainsWithOptions(p7, signer, revocation.InfoArchival{}, options, false)
	if err == nil {
		t.Fatal("expected an error for a certificate with no KeyUsage/ExtKeyUsage, got nil")
	}
	var policyErr *PolicyError
	if !errors.As(err, &policyErr) {
		t.Errorf("expected a *PolicyError among the returned error(s), got: %v", err)
	}
	if len(signer.Certificates) != 1 || signer.Certificates[0].KeyUsageValid {
		t.Error("expected KeyUsageValid to be false")
	}
}

// TestBuildChains_DocTimeStampSkipsSignerEKUPolicy proves that a document
// timestamp's own TSA certificate (isDocTimeStamp=true) is not rejected by
// the signer KeyUsage/EKU policy (Document Signing / Email Protection /
// Client Auth), which does not apply to it - only its own
// id-kp-timeStamping EKU matters, checked separately.
func TestBuildChains_DocTimeStampSkipsSignerEKUPolicy(t *testing.T) {
	p7 := &pkcs7.PKCS7{
		Certificates: []*x509.Certificate{{
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		}},
	}
	signer := NewSigner()
	options := DefaultVerifyOptions()

	err := buildCertificateChainsWithOptions(p7, signer, revocation.InfoArchival{}, options, true)
	var policyErr *PolicyError
	if errors.As(err, &policyErr) {
		t.Errorf("did not expect a KeyUsage/EKU policy error for a DocTimeStamp certificate, got: %v", policyErr)
	}
}
