package sign

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/revocation"
)

func TestHTTPGetWithTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("DefaultTimeout", func(t *testing.T) {
		started := time.Now()
		resp, err := httpGetWithTimeout(context.Background(), server.URL, 20*time.Millisecond)
		if resp != nil {
			_ = resp.Body.Close()
		}
		var netErr net.Error
		if err == nil || !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("httpGetWithTimeout() error = %v, want a timeout", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("httpGetWithTimeout() took %s, want a bounded timeout", elapsed)
		}
	})

	t.Run("CallerDeadlineTakesPrecedence", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()

		resp, err := httpGetWithTimeout(ctx, server.URL, time.Second)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("httpGetWithTimeout() error = %v, want the caller deadline", err)
		}
	})
}

func TestPAdESRejectsEmbeddedRevocationData(t *testing.T) {
	signContext := &SignContext{
		SignData: SignData{
			DigestAlgorithm: crypto.SHA256,
			SubFilter:       SubFilterETSICAdESDetached,
		},
	}
	if err := signContext.SignData.RevocationData.AddCRL([]byte{0x30, 0x00}); err != nil {
		t.Fatal(err)
	}

	err := signContext.validateSignData()
	if err == nil || !strings.Contains(err.Error(), "cannot embed Adobe revocation information") {
		t.Fatalf("validateSignData() error = %v, want the PAdES revocation rejection", err)
	}
}

func TestDefaultEmbedRevocationStatusFunction(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	info := &revocation.InfoArchival{}
	issuer := pki.IntermediateCerts[0]

	// Create a dummy key for issuer to avoid panic/error in ocsp.CreateRequest
	// strictly speaking ocsp.CreateRequest needs RSA/ECDSA/Ed25519 key.
	// But let's see if we can trigger the HTTP call.
	// Actually, embedOCSPRevocationStatus calls ocsp.CreateRequest first.
	// If that fails, we return early.
	// To reach http.Get, we need valid request creation.

	// We'll skip OCSP success path if it's too hard to setup keys,
	// but we can definitely test CRL path which just does http.Get.

	t.Run("CRL Check", func(t *testing.T) {
		priv, cert := pki.IssueLeaf("CRL Test")
		_ = priv // Not used directly in this subtest

		err := DefaultEmbedRevocationStatusFunction(cert, issuer, info)
		if err != nil {
			t.Errorf("Expected success (or at least no error for dummy bytes), got: %v", err)
		}
		if len(info.CRL) != 1 {
			t.Error("CRL was not added")
		}
	})

	t.Run("OCSP Check (Fail Request creation)", func(t *testing.T) {
		// Invalid issuer key -> CreateRequest fails
		cert := &x509.Certificate{
			OCSPServer: []string{pki.Server.URL},
		}
		// Use a mock issuer with invalid key/data for OCSP creation to trigger error
		mockIssuer := &x509.Certificate{
			PublicKey: "invalid",
		}

		err := DefaultEmbedRevocationStatusFunction(cert, mockIssuer, info)
		if err != nil {
			// Expected error because OCSP request creation fails and CRL is missing
			return
		}
		t.Error("Expected error because OCSP request creation fails and CRL is missing")
	})
}
