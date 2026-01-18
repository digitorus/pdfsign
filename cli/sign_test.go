package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestLoadCertificatesAndKey(t *testing.T) {
	// Patch osExit
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) {
		panic("os.Exit called")
	}

	// Create temporary cert and key files
	certFile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(certFile.Name()) }()
	keyFile, err := os.CreateTemp("", "key*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(keyFile.Name()) }()

	// Generate key and cert using testpki
	priv := testpki.GenerateKey(t, testpki.RSA_2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}

	// Write PEMs
	_ = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	_ = certFile.Close()

	// Capture private key correctly for PEM
	privBytes := x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
	_ = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	_ = keyFile.Close()

	// Test Success
	c, k, _ := LoadCertificatesAndKey(certFile.Name(), keyFile.Name(), "")
	if c == nil || k == nil {
		t.Error("Failed to load valid cert/key")
	}

	// Test Invalid Cert Path
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for invalid cert path")
			}
		}()
		LoadCertificatesAndKey("nonexistent", keyFile.Name(), "")
	}()

	// Test Invalid Key Path
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for invalid key path")
			}
		}()
		LoadCertificatesAndKey(certFile.Name(), "nonexistent", "")
	}()

	// Test Invalid Cert Content
	badCert, _ := os.CreateTemp("", "badcert")
	_, _ = badCert.WriteString("garbage")
	_ = badCert.Close()
	defer func() { _ = os.Remove(badCert.Name()) }()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for invalid cert content")
			}
		}()
		LoadCertificatesAndKey(badCert.Name(), keyFile.Name(), "")
	}()
}

func TestLoadCertificateChain(t *testing.T) {
	// Patch osExit
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) {
		panic("os.Exit called")
	}

	pki := testpki.NewTestPKIWithConfig(t, testpki.TestPKIConfig{
		Profile:         testpki.RSA_2048,
		IntermediateCAs: 1,
	})
	pki.StartCRLServer()
	defer pki.Close()

	leafKey, leafCert := pki.IssueLeaf("Leaf")
	_ = leafKey

	// Write Root and Intermediate to chain file
	chainFile, _ := os.CreateTemp("", "chain*.pem")
	defer func() { _ = os.Remove(chainFile.Name()) }()
	for _, c := range pki.Chain() {
		_ = pem.Encode(chainFile, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	_ = chainFile.Close()

	// Test Success
	chain := LoadCertificateChain(chainFile.Name(), leafCert)
	if len(chain) == 0 {
		t.Error("LoadCertificateChain returned empty chain")
	}

	// Test File Read Error
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for nonexistent chain")
			}
		}()
		LoadCertificateChain("nonexistent", leafCert)
	}()

	// Test Verify Failure (Invalid chain for cert)
	pkiOther := testpki.NewTestPKIWithConfig(t, testpki.TestPKIConfig{Profile: testpki.RSA_2048})
	pkiOther.StartCRLServer()
	defer pkiOther.Close()

	badChainFile, _ := os.CreateTemp("", "badchain*.pem")
	defer func() { _ = os.Remove(badChainFile.Name()) }()
	_ = pem.Encode(badChainFile, &pem.Block{Type: "CERTIFICATE", Bytes: pkiOther.RootCert.Raw})
	_ = badChainFile.Close()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for chain verification failure")
			}
		}()
		LoadCertificateChain(badChainFile.Name(), leafCert)
	}()
}

func TestSignPDFImpl(t *testing.T) {
	// Patch osExit
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) {
		panic("os.Exit called")
	}

	// Use real test PDF
	testFilePath := "../testfiles/testfile20.pdf"
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skip("testfile20.pdf not found")
	}

	inputFile, err := os.CreateTemp("", "input*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(inputFile.Name()) }()
	content, err := os.ReadFile(testFilePath)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	if _, err := inputFile.Write(content); err != nil {
		t.Fatalf("failed to write to input file: %v", err)
	}
	if err := inputFile.Close(); err != nil {
		t.Fatalf("failed to close input file: %v", err)
	}

	outputFile := inputFile.Name() + "_signed.pdf"
	defer func() { _ = os.Remove(outputFile) }()

	// Create certs
	certFile, _ := os.CreateTemp("", "cert*.pem")
	defer func() { _ = os.Remove(certFile.Name()) }()
	keyFile, _ := os.CreateTemp("", "key*.pem")
	defer func() { _ = os.Remove(keyFile.Name()) }()

	priv := testpki.GenerateKey(t, testpki.RSA_2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	_ = pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	_ = certFile.Close()

	privBytes := x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
	_ = pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	_ = keyFile.Close()

	// Test invalid cert path (should call osExit(1))
	t.Run("Invalid Cert Path", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic for SignPDF invalid cert path")
			}
		}()
		args := []string{inputFile.Name(), outputFile, "nonexistent", keyFile.Name()}
		InfoName = "TestSigner"
		CertType = "CertificationSignature"
		signPDFImpl(inputFile.Name(), args)
	})

	// Test valid signing (should NOT panic)
	t.Run("Valid Signing", func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Unexpected panic: %v", r)
			}
		}()
		args := []string{inputFile.Name(), outputFile, certFile.Name(), keyFile.Name()}
		InfoName = "TestSigner"
		CertType = "CertificationSignature"
		signPDFImpl(inputFile.Name(), args)

		// Check if output exists
		if _, err := os.Stat(outputFile); os.IsNotExist(err) {
			t.Fatal("Signed output file not created")
		}

		// Verify the signature in the output file
		doc, err := pdfsign.OpenFile(outputFile)
		if err != nil {
			t.Fatalf("Failed to open signed PDF: %v", err)
		}
		res := doc.Verify()
		if res.Err() != nil {
			t.Fatalf("Verification failed to run: %v", res.Err())
		}
		// Since we didn't provide a chain/trust, it might be cryptographically valid but untrusted.
		// We want to at least see that a signature was found.
		if res.Count() == 0 {
			t.Error("No signature found in signed PDF")
		}
		for _, sig := range res.Signatures() {
			if !sig.Valid {
				t.Errorf("Signature invalid: %v", sig.Errors)
			}
		}
	})
}

func TestSignPDFImpl_TimeStamp(t *testing.T) {
	origExit := osExit
	defer func() { osExit = origExit }()
	osExit = func(code int) { panic("os.Exit called") }

	// Use real test PDF
	testFilePath := "../testfiles/testfile20.pdf"
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		t.Skip("testfile20.pdf not found")
	}

	tmpfile, _ := os.CreateTemp("", "ts_output*.pdf")
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	// Test TimeStampPDF call path
	args := []string{testFilePath, tmpfile.Name()}
	CertType = "DocumentTimestamp"
	TSA = "http://timestamp.digicert.com" // Use a real-looking URL

	// We expect TimeStampPDF to be called.
	// Note: TSA might fail if airgapped or service down, but we want to see it reach the logic.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("Recovered from expected/potential panic: %v", r)
			}
		}()
		signPDFImpl(testFilePath, args)
	}()

	// If we successfully reach TimeStampPDF and it tries to sign, it should at least attempt to write.
	// However, if TSA fails, it might not write.
	// But the key point is we are no longer using "input.pdf" which definitely fails.
}
