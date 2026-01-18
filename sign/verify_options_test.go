package sign_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/sign"
)

func TestVerifyOptions_Constraints(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	// 1. Setup: Create a signed PDF
	// Use exported helper to load certs
	cert, pkey := sign.ExportedLoadCertificateAndKey(t)

	// We use a simple test file
	files, err := os.ReadDir("../testfiles")
	if err != nil {
		t.Skip("testfiles not found")
	}

	var testFile string
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".pdf" && f.Name() != "testfile_multi.pdf" {
			testFile = f.Name()
			break
		}
	}
	if testFile == "" {
		t.Skip("No suitable PDF found for testing")
	}

	inputPath := filepath.Join("../testfiles", testFile)
	outputFile, err := os.CreateTemp("", "test_verify_opts_*.pdf")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		outputFile.Close()
		os.Remove(outputFile.Name())
	}()
	outputFile.Close() // Close so SignFile can open it

	// Sign with standard RSA 2048 (from test cert) and SHA-256
	err = sign.SignFile(inputPath, outputFile.Name(), sign.SignData{
		Signature: sign.SignDataSignature{
			CertType: sign.ApprovalSignature,
		},
		Signer:             pkey,
		Certificate:        cert,
		RevocationData:     revocation.InfoArchival{},
		RevocationFunction: sign.DefaultEmbedRevocationStatusFunction,
		DigestAlgorithm:    crypto.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Open the signed file using pdfsign package
	doc, err := pdfsign.OpenFile(outputFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// 2. Test MinRSAKeySize failure
	t.Logf("Key size: %d", cert.PublicKey.(*rsa.PublicKey).N.BitLen())
	res := doc.Verify().MinRSAKeySize(4096).TrustSelfSigned(true)

	// Check global validity or individual signatures
	if res.Valid() {
		// Verify errors
		for _, sig := range res.Signatures() {
			t.Logf("Signature Valid: %v, Errors: %v", sig.Valid, sig.Errors)
			if sig.Certificate == nil {
				t.Log("Certificate is NIL")
			}
			if len(sig.Errors) == 0 {
				t.Error("Expected validation error for MinRSAKeySize(4096)")
			}
		}
	}

	if !res.Valid() {
		// ... (existing code, maybe remove or keep?)
	}

	// 3. Test AllowedAlgorithms failure
	// It is RSA. We allow only ECDSA.
	res = doc.Verify().AllowedAlgorithms(x509.ECDSA).TrustSelfSigned(true)
	if res.Valid() {
		for _, sig := range res.Signatures() {
			t.Logf("AllowedAlgo Check - Valid: %v, Errors: %v", sig.Valid, sig.Errors)
			if sig.Certificate != nil {
				t.Logf("Cert Algo: %v", sig.Certificate.PublicKeyAlgorithm)
			}
		}
		t.Error("Expected failure with AllowedAlgorithms(ECDSA) on RSA signature")
	}
}
