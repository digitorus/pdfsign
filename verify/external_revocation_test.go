package verify

import (
	"bytes"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPerformExternalOCSPCheck(t *testing.T) {
	// Create a test certificate with OCSP server
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		OCSPServer:   []string{}, // Will be set by individual tests
	}

	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	tests := []struct {
		name          string
		setupServer   func() *httptest.Server
		setupOptions  func(serverURL string) *VerifyOptions
		setupCert     func(serverURL string) *x509.Certificate
		expectError   bool
		errorContains string
	}{
		{
			name: "External revocation disabled",
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: false,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				return cert
			},
			expectError:   true,
			errorContains: "external revocation checking is disabled",
		},
		{
			name: "No OCSP server URLs",
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.OCSPServer = []string{}
				return &testCert
			},
			expectError:   true,
			errorContains: "certificate has no OCSP server URLs",
		},
		{
			name: "OCSP server returns valid response",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "POST" {
						w.WriteHeader(http.StatusMethodNotAllowed)
						return
					}

					// Return a mock response that will fail parsing
					// In a real implementation, you'd need proper OCSP response signing
					w.Header().Set("Content-Type", "application/ocsp-response")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("mock-ocsp-response"))
				}))
			},
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
					HTTPTimeout:                   5 * time.Second,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.OCSPServer = []string{serverURL}
				return &testCert
			},
			expectError:   true, // Will fail parsing the mock response
			errorContains: "failed to parse OCSP response",
		},
		{
			name: "OCSP server returns error status",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.OCSPServer = []string{serverURL}
				return &testCert
			},
			expectError:   true,
			errorContains: "returned status 500",
		},
		{
			name: "Custom HTTP client",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("custom-client-response"))
				}))
			},
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
					HTTPClient: &http.Client{
						Timeout: 1 * time.Second,
					},
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.OCSPServer = []string{serverURL}
				return &testCert
			},
			expectError:   true,
			errorContains: "failed to parse OCSP response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			var serverURL string

			if tt.setupServer != nil {
				server = tt.setupServer()
				defer server.Close()
				serverURL = server.URL
			}

			options := tt.setupOptions(serverURL)
			testCert := tt.setupCert(serverURL)

			// Use a mock OCSP request function for all cases except those that expect error due to disabled/external
			var ocspRequestFunc OCSPRequestFunc
			if tt.name != "External revocation disabled" && tt.name != "No OCSP server URLs" {
				ocspRequestFunc = func(cert, issuer *x509.Certificate) ([]byte, error) {
					return []byte("dummy-ocsp-request"), nil
				}
			}

			_, _, err := performExternalOCSPCheckWithFunc(testCert, issuer, options, ocspRequestFunc)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorContains != "" && !containsString(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPerformExternalCRLCheck(t *testing.T) {
	// Create a test certificate with CRL distribution points
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
	}

	tests := []struct {
		name          string
		setupServer   func() *httptest.Server
		setupOptions  func(serverURL string) *VerifyOptions
		setupCert     func(serverURL string) *x509.Certificate
		expectError   bool
		errorContains string
		expectRevoked bool
	}{
		{
			name: "External revocation disabled",
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: false,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				return cert
			},
			expectError:   true,
			errorContains: "external revocation checking is disabled",
		},
		{
			name: "No CRL distribution points",
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.CRLDistributionPoints = []string{}
				return &testCert
			},
			expectError:   true,
			errorContains: "certificate has no CRL distribution points",
		},
		{
			name: "CRL server returns error status",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
			},
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.CRLDistributionPoints = []string{serverURL}
				return &testCert
			},
			expectError:   true,
			errorContains: "returned status 404",
		},
		{
			name: "CRL server returns invalid CRL",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("invalid-crl-data"))
				}))
			},
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.CRLDistributionPoints = []string{serverURL}
				return &testCert
			},
			expectError:   true,
			errorContains: "failed to parse CRL",
		},
		{
			name: "Multiple CRL URLs with first failing",
			setupServer: func() *httptest.Server {
				// Create two servers - first fails, second works
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("invalid-crl-data"))
				}))
			},
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.CRLDistributionPoints = []string{
					"http://invalid-url.example.com/crl",
					serverURL,
				}
				return &testCert
			},
			expectError:   true,
			errorContains: "failed to parse CRL",
		},
		{
			name: "Custom HTTP client with timeout",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("invalid-crl-data"))
				}))
			},
			setupOptions: func(serverURL string) *VerifyOptions {
				return &VerifyOptions{
					EnableExternalRevocationCheck: true,
					HTTPClient: &http.Client{
						Timeout: 1 * time.Second,
					},
				}
			},
			setupCert: func(serverURL string) *x509.Certificate {
				testCert := *cert
				testCert.CRLDistributionPoints = []string{serverURL}
				return &testCert
			},
			expectError:   true,
			errorContains: "failed to parse CRL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var server *httptest.Server
			var serverURL string

			if tt.setupServer != nil {
				server = tt.setupServer()
				defer server.Close()
				serverURL = server.URL
			}

			options := tt.setupOptions(serverURL)
			testCert := tt.setupCert(serverURL)

			revocationTime, isRevoked, _, err := performExternalCRLCheck(testCert, options)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorContains != "" && !containsString(err.Error(), tt.errorContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errorContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if isRevoked != tt.expectRevoked {
					t.Errorf("Expected revoked=%v, got %v", tt.expectRevoked, isRevoked)
				}
				if tt.expectRevoked && revocationTime == nil {
					t.Error("Expected revocation time when certificate is revoked")
				}
			}
		})
	}
}

// containsString checks if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsStringHelper(s, substr))))
}

func containsStringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// panicReader fails the test if anything ever reads from it - used to prove
// readLimitedBody's Content-Length fast path rejects an oversized response
// without touching the body at all.
type panicReader struct{}

func (panicReader) Read([]byte) (int, error) {
	panic("body should not have been read")
}

func TestReadLimitedBody(t *testing.T) {
	t.Run("declared Content-Length over limit is rejected without reading the body", func(t *testing.T) {
		resp := &http.Response{
			ContentLength: 1000,
			Body:          io.NopCloser(panicReader{}),
		}
		if _, err := readLimitedBody(resp, 100); err == nil {
			t.Fatal("expected error for a declared Content-Length exceeding the limit")
		}
	})

	t.Run("streamed body exceeding the limit without a Content-Length is rejected", func(t *testing.T) {
		resp := &http.Response{
			ContentLength: -1, // unknown, as with chunked transfer-encoding
			Body:          io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("A"), 1000))),
		}
		if _, err := readLimitedBody(resp, 100); err == nil {
			t.Fatal("expected error for a streamed body exceeding the limit")
		}
	})

	t.Run("body within the limit is read fully", func(t *testing.T) {
		want := []byte("hello world")
		resp := &http.Response{
			ContentLength: int64(len(want)),
			Body:          io.NopCloser(bytes.NewReader(want)),
		}
		got, err := readLimitedBody(resp, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

func TestCheckContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    string
		wantWarning bool
	}{
		{"exact match", "application/pkix-crl", "application/pkix-crl", false},
		{"match with parameter", "application/ocsp-response; charset=binary", "application/ocsp-response", false},
		{"case-insensitive match", "Application/Pkix-CRL", "application/pkix-crl", false},
		{"mismatch", "text/html", "application/pkix-crl", true},
		{"missing header - no warning (real-world responders often omit it)", "", "application/pkix-crl", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			got := checkContentType(resp, "http://example.test/crl", tt.expected, "RFC X")
			if (got != nil) != tt.wantWarning {
				t.Errorf("checkContentType() = %v, wantWarning=%v", got, tt.wantWarning)
			}
			var ctWarning *ContentTypeWarning
			if got != nil && !errors.As(got, &ctWarning) {
				t.Errorf("expected a *ContentTypeWarning, got %T", got)
			}
		})
	}
}

// TestPerformExternalCRLCheck_OversizedResponseRejected proves an oversized
// CRL response is rejected rather than fully buffered into memory, and that
// MaxCRLResponseBytes is honored when set (a small limit here keeps the
// test fast instead of transferring the full default 256 MiB).
func TestPerformExternalCRLCheck_OversizedResponseRejected(t *testing.T) {
	const limit = 1000
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte{0x30}, limit+1))
	}))
	defer server.Close()

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		CRLDistributionPoints: []string{server.URL},
	}
	options := &VerifyOptions{EnableExternalRevocationCheck: true, MaxCRLResponseBytes: limit}

	_, _, _, err := performExternalCRLCheck(cert, options)
	if err == nil {
		t.Fatal("expected an error for a CRL response exceeding the size limit")
	}
	t.Logf("got expected error: %v", err)
}
