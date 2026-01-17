package sign

import (
	"crypto/x509"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
	"github.com/digitorus/pdfsign/revocation"
)

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
