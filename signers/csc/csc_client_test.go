package csc

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
)

// mockCSCServer provides a flexible mock server for CSC API endpoints.
type mockCSCServer struct {
	// Handlers for specific endpoints
	infoHandler      func(w http.ResponseWriter, r *http.Request)
	authorizeHandler func(w http.ResponseWriter, r *http.Request)
	signHandler      func(w http.ResponseWriter, r *http.Request)
}

func generateDummyCert() string {
	priv := testpki.GenerateKey(nil, testpki.RSA_2048)
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	der, _ := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	return base64.StdEncoding.EncodeToString(der)
}

func newMockServer(m *mockCSCServer) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch {
		case strings.HasSuffix(r.URL.Path, "/credentials/info"):
			if m.infoHandler != nil {
				m.infoHandler(w, r)
			} else {
				// Return a valid generated cert by default
				cert := generateDummyCert()
				if _, err := fmt.Fprintf(w, `{
					"key": {"status": "enabled", "algo": ["1.2.840.113549.1.1.11"], "len": 2048},
					"cert": {"status": "valid", "certificates": ["%s"]},
					"authMode": "explicit"
				}`, cert); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}
		case strings.HasSuffix(r.URL.Path, "/credentials/authorize"):
			if m.authorizeHandler != nil {
				m.authorizeHandler(w, r)
			} else {
				// Default success response for authorize
				_, _ = w.Write([]byte(`{"SAD": "mock-sad-token"}`))
			}
		case strings.HasSuffix(r.URL.Path, "/signatures/signHash"):
			if m.signHandler != nil {
				m.signHandler(w, r)
			} else {
				// Default success response for sign
				// Returns a dummy base64 signature
				sig := base64.StdEncoding.EncodeToString([]byte("dummy-signature"))
				if _, err := fmt.Fprintf(w, `{"signatures": ["%s"]}`, sig); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestSigner_Sign_Success(t *testing.T) {
	mock := &mockCSCServer{}
	server := newMockServer(mock)
	defer server.Close()

	signer, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test-creds",
	})
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	hash := []byte("test-hash")
	opts := crypto.SHA256

	sig, err := signer.Sign(nil, hash, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if string(sig) != "dummy-signature" {
		t.Errorf("expected signature 'dummy-signature', got %s", string(sig))
	}
}

func TestSigner_Sign_AuthError(t *testing.T) {
	mock := &mockCSCServer{
		authorizeHandler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "invalid_grant"}`))
		},
		// If auth fails (or is skipped/swallowed), the sign request should also fail
		signHandler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error": "unauthorized"}`))
		},
	}
	server := newMockServer(mock)
	defer server.Close()

	signer, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test-creds",
	})
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	_, err = signer.Sign(nil, []byte("hash"), crypto.SHA256)
	if err == nil {
		t.Fatal("expected error for auth failure, got nil")
	}
	// We might get "sign request failed" instead of "failed to authorize" because authorize() swallows errors
	if !strings.Contains(err.Error(), "sign request failed") && !strings.Contains(err.Error(), "failed to authorize credential") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSigner_FetchCredentialInfo_Error(t *testing.T) {
	mock := &mockCSCServer{
		infoHandler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal server error"))
		},
	}
	server := newMockServer(mock)
	defer server.Close()

	_, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test-creds",
	})
	if err == nil {
		t.Error("expected error for info fetch failure")
	}
}

func TestSigner_Sign_UnsupportedHash(t *testing.T) {
	mock := &mockCSCServer{} // Default handler provides valid cert
	server := newMockServer(mock)
	defer server.Close()

	signer, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test",
	})
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	_, err = signer.Sign(nil, []byte("hash"), crypto.MD5)
	if err == nil {
		t.Error("expected error for unsupported hash MD5")
	}
}

func TestSigner_Public(t *testing.T) {
	mock := &mockCSCServer{} // Default handler provides valid cert
	server := newMockServer(mock)
	defer server.Close()

	signer, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test-creds",
	})
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	if signer.Public() == nil {
		t.Error("expected public key, got nil")
	}
}

func TestSigner_Authorize_InvalidJSON(t *testing.T) {
	mock := &mockCSCServer{
		authorizeHandler: func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`invalid-json`))
		},
	}
	server := newMockServer(mock)
	defer server.Close()

	signer, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test-creds",
	})
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	// Should swallow error and return empty credentials, allowing Sign to proceed (and likely fail later or succeed if signHandler is permissive)
	// We just want to cover the code path.
	_, _ = signer.Sign(nil, []byte("hash"), crypto.SHA256)
}

func TestSigner_Sign_APIError(t *testing.T) {
	mock := &mockCSCServer{
		signHandler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "invalid_request"}`))
		},
	}
	server := newMockServer(mock)
	defer server.Close()

	signer, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test-creds",
	})
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	_, err = signer.Sign(nil, []byte("hash"), crypto.SHA256)
	if err == nil {
		t.Error("expected error for sign API failure")
	}
}

func TestSigner_InvalidJSONResponse(t *testing.T) {
	mock := &mockCSCServer{
		signHandler: func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`invalid-json`))
		},
	}
	server := newMockServer(mock)
	defer server.Close()

	signer, err := NewSigner(Config{
		BaseURL:      server.URL,
		CredentialID: "test-creds",
	})
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}

	_, err = signer.Sign(nil, []byte("hash"), crypto.SHA256)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}
