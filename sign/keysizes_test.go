package sign

// Comprehensive test suite for PDF signing with various key types and sizes.
// This file systematically tests the library's behavior with different
// cryptographic configurations to identify limitations and bugs.
//
// PDF Signing Cryptography Background:
// ====================================
// In PDF signing, there are TWO separate cryptographic operations:
//
// 1. Certificate Signing (by CA): How the CA signed your certificate
//    - Stored in Certificate.SignatureAlgorithm
//    - Examples: SHA256-RSA, SHA384-RSA, ECDSA-SHA256
//    - This is INDEPENDENT of your key size
//
// 2. Document Signing (by you): Using your private key to sign the PDF
//    - Signature size depends on YOUR key size, not the CA's algorithm
//    - RSA: signature size = key size in bytes (e.g., RSA-3072 = 384 bytes)
//    - ECDSA: signature size depends on curve (P-256=64, P-384=96, P-521=132 bytes)
//
// The Bug Under Investigation:
// ============================
// The library uses Certificate.SignatureAlgorithm to estimate signature buffer size.
// This is WRONG because it confuses the CA's signing algorithm with your key size.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/digitorus/pdfsign/revocation"
	"github.com/digitorus/pdfsign/verify"
)

// TestKeySize represents a test case for a specific key configuration
type TestKeySize struct {
	Name               string
	KeyType            string // "RSA" or "ECDSA"
	KeySize            int    // bits for RSA, curve size for ECDSA
	ExpectedSigSize    int    // expected signature size in bytes
	CASignatureAlgo    x509.SignatureAlgorithm
	AllocatedByLibrary int // what the library allocates based on CA algo
}

// Common PDF signing scenarios in the real world
var testKeySizes = []TestKeySize{
	// =========================================================================
	// RSA Keys - Most common in enterprise PDF signing
	// =========================================================================

	// RSA-1024: Legacy, insecure, but still found in old systems
	{
		Name:               "RSA-1024 with SHA1-RSA CA",
		KeyType:            "RSA",
		KeySize:            1024,
		ExpectedSigSize:    128,
		CASignatureAlgo:    x509.SHA1WithRSA,
		AllocatedByLibrary: 128,
	},
	{
		Name:               "RSA-1024 with SHA256-RSA CA",
		KeyType:            "RSA",
		KeySize:            1024,
		ExpectedSigSize:    128,
		CASignatureAlgo:    x509.SHA256WithRSA,
		AllocatedByLibrary: 256,
	},

	// RSA-2048: Current industry standard minimum
	{
		Name:               "RSA-2048 with SHA1-RSA CA",
		KeyType:            "RSA",
		KeySize:            2048,
		ExpectedSigSize:    256,
		CASignatureAlgo:    x509.SHA1WithRSA,
		AllocatedByLibrary: 128, // under-allocated
	},
	{
		Name:               "RSA-2048 with SHA256-RSA CA",
		KeyType:            "RSA",
		KeySize:            2048,
		ExpectedSigSize:    256,
		CASignatureAlgo:    x509.SHA256WithRSA,
		AllocatedByLibrary: 256,
	},
	{
		Name:               "RSA-2048 with SHA384-RSA CA",
		KeyType:            "RSA",
		KeySize:            2048,
		ExpectedSigSize:    256,
		CASignatureAlgo:    x509.SHA384WithRSA,
		AllocatedByLibrary: 384,
	},

	// RSA-3072: Recommended for security beyond 2030
	{
		Name:               "RSA-3072 with SHA256-RSA CA",
		KeyType:            "RSA",
		KeySize:            3072,
		ExpectedSigSize:    384,
		CASignatureAlgo:    x509.SHA256WithRSA,
		AllocatedByLibrary: 256, // under-allocated
	},
	{
		Name:               "RSA-3072 with SHA384-RSA CA",
		KeyType:            "RSA",
		KeySize:            3072,
		ExpectedSigSize:    384,
		CASignatureAlgo:    x509.SHA384WithRSA,
		AllocatedByLibrary: 384,
	},
	{
		Name:               "RSA-3072 with SHA512-RSA CA",
		KeyType:            "RSA",
		KeySize:            3072,
		ExpectedSigSize:    384,
		CASignatureAlgo:    x509.SHA512WithRSA,
		AllocatedByLibrary: 512,
	},

	// RSA-4096: High security applications
	{
		Name:               "RSA-4096 with SHA256-RSA CA",
		KeyType:            "RSA",
		KeySize:            4096,
		ExpectedSigSize:    512,
		CASignatureAlgo:    x509.SHA256WithRSA,
		AllocatedByLibrary: 256, // under-allocated
	},
	{
		Name:               "RSA-4096 with SHA384-RSA CA",
		KeyType:            "RSA",
		KeySize:            4096,
		ExpectedSigSize:    512,
		CASignatureAlgo:    x509.SHA384WithRSA,
		AllocatedByLibrary: 384, // under-allocated
	},
	{
		Name:               "RSA-4096 with SHA512-RSA CA",
		KeyType:            "RSA",
		KeySize:            4096,
		ExpectedSigSize:    512,
		CASignatureAlgo:    x509.SHA512WithRSA,
		AllocatedByLibrary: 512,
	},

	// =========================================================================
	// ECDSA Keys - Increasingly common, especially in modern PKI
	// =========================================================================

	// ECDSA P-256: Most widely deployed elliptic curve
	{
		Name:               "ECDSA P-256 with ECDSA-SHA256 CA",
		KeyType:            "ECDSA",
		KeySize:            256,
		ExpectedSigSize:    64,
		CASignatureAlgo:    x509.ECDSAWithSHA256,
		AllocatedByLibrary: 256,
	},

	// ECDSA P-384: Higher security curve
	{
		Name:               "ECDSA P-384 with ECDSA-SHA384 CA",
		KeyType:            "ECDSA",
		KeySize:            384,
		ExpectedSigSize:    96,
		CASignatureAlgo:    x509.ECDSAWithSHA384,
		AllocatedByLibrary: 384,
	},

	// ECDSA P-521: Highest standard NIST curve
	{
		Name:               "ECDSA P-521 with ECDSA-SHA512 CA",
		KeyType:            "ECDSA",
		KeySize:            521,
		ExpectedSigSize:    132,
		CASignatureAlgo:    x509.ECDSAWithSHA512,
		AllocatedByLibrary: 512,
	},
}

// generateTestCertificate creates a self-signed certificate with the specified key
func generateTestCertificate(keyType string, keySize int, caAlgo x509.SignatureAlgorithm) (crypto.Signer, *x509.Certificate, error) {
	var privateKey crypto.Signer
	var err error

	// Generate the key
	switch keyType {
	case "RSA":
		privateKey, err = rsa.GenerateKey(rand.Reader, keySize)
	case "ECDSA":
		var curve elliptic.Curve
		switch keySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, nil, fmt.Errorf("unsupported ECDSA curve size: %d", keySize)
		}
		privateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("Test %s-%d Certificate", keyType, keySize),
			Organization: []string{"PDF Signing Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    caAlgo,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return privateKey, cert, nil
}

// TestResult captures the actual test outcome
type TestResult struct {
	Name           string
	KeyType        string
	KeySize        int
	CAAlgo         string
	Allocated      int
	Needed         int
	SignOK         bool
	VerifyOK       bool
	RetryTriggered bool
	Error          string
}

// TestPDFSigningKeyMatrix runs the comprehensive test matrix and reports actual behavior
func TestPDFSigningKeyMatrix(t *testing.T) {
	inputFilePath := "../testfiles/testfile20.pdf"

	// Verify test file exists
	if _, err := os.Stat(inputFilePath); os.IsNotExist(err) {
		t.Fatalf("test file not found: %s", inputFilePath)
	}

	var results []TestResult

	for _, tc := range testKeySizes {
		t.Run(tc.Name, func(t *testing.T) {
			result := TestResult{
				Name:      tc.Name,
				KeyType:   tc.KeyType,
				KeySize:   tc.KeySize,
				CAAlgo:    tc.CASignatureAlgo.String(),
				Allocated: tc.AllocatedByLibrary,
				Needed:    tc.ExpectedSigSize,
			}

			// Generate key and certificate
			privateKey, cert, err := generateTestCertificate(tc.KeyType, tc.KeySize, tc.CASignatureAlgo)
			if err != nil {
				result.Error = fmt.Sprintf("cert generation failed: %v", err)
				results = append(results, result)
				t.Logf("SKIP: %s", result.Error)
				return
			}

			// Create temp file for output
			tmpfile, err := os.CreateTemp("", fmt.Sprintf("pdf_sign_test_%s_%d_*.pdf", tc.KeyType, tc.KeySize))
			if err != nil {
				t.Fatalf("failed to create temp file: %v", err)
			}
			defer func() { _ = os.Remove(tmpfile.Name()) }()
			_ = tmpfile.Close()

			// Attempt to sign the PDF
			signErr := SignFile(inputFilePath, tmpfile.Name(), SignData{
				Signature: SignDataSignature{
					Info: SignDataSignatureInfo{
						Name:        fmt.Sprintf("%s-%d Test", tc.KeyType, tc.KeySize),
						Location:    "Test Location",
						Reason:      fmt.Sprintf("Testing %s-%d key", tc.KeyType, tc.KeySize),
						ContactInfo: "test@example.com",
						Date:        time.Now().Local(),
					},
					CertType:   CertificationSignature,
					DocMDPPerm: AllowFillingExistingFormFieldsAndSignaturesPerms,
				},
				Signer:             privateKey,
				DigestAlgorithm:    crypto.SHA256,
				Certificate:        cert,
				RevocationData:     revocation.InfoArchival{},
				RevocationFunction: DefaultEmbedRevocationStatusFunction,
			})

			if signErr != nil {
				result.SignOK = false
				result.Error = signErr.Error()
			} else {
				result.SignOK = true

				// Try to verify the signed PDF
				signedFile, err := os.Open(tmpfile.Name())
				if err != nil {
					t.Fatalf("failed to open signed file: %v", err)
				}
				defer func() { _ = signedFile.Close() }()

				_, verifyErr := verifyFile(signedFile)
				if verifyErr != nil {
					result.VerifyOK = false
					// Truncate error for readability
					errStr := verifyErr.Error()
					if len(errStr) > 100 {
						errStr = errStr[:100] + "..."
					}
					result.Error = errStr
				} else {
					result.VerifyOK = true
				}
			}

			results = append(results, result)

			// Report result
			status := "✗ FAIL"
			if result.SignOK && result.VerifyOK {
				status = "✓ PASS"
			}
			t.Logf("%s | Key: %s-%d | CA: %s | Alloc: %d | Need: %d",
				status, tc.KeyType, tc.KeySize, tc.CASignatureAlgo, tc.AllocatedByLibrary, tc.ExpectedSigSize)
			if result.Error != "" {
				t.Logf("  Error: %s", result.Error)
			}
		})
	}

	// Print summary at the end
	t.Log("")
	t.Log("============================================================")
	t.Log("SUMMARY: PDF Signing Key Size Compatibility")
	t.Log("============================================================")
	t.Log("Key         | CA Algorithm | Alloc | Need | Sign | Verify")
	t.Log("------------|--------------|-------|------|------|-------")
	for _, r := range results {
		signStatus := "✗"
		if r.SignOK {
			signStatus = "✓"
		}
		verifyStatus := "✗"
		if r.VerifyOK {
			verifyStatus = "✓"
		}
		t.Logf("%-11s | %-12s | %5d | %4d | %4s | %s",
			fmt.Sprintf("%s-%d", r.KeyType, r.KeySize),
			r.CAAlgo, r.Allocated, r.Needed, signStatus, verifyStatus)
	}
}

// verifyFile is a helper to verify a signed PDF using the actual verify package
func verifyFile(f *os.File) (bool, error) {
	_, err := f.Seek(0, 0)
	if err != nil {
		return false, err
	}

	_, err = verify.VerifyFile(f)
	if err != nil {
		return false, err
	}

	return true, nil
}

// TestCertificateSizes measures actual certificate sizes for different key types
// This helps understand why the buffer calculation is failing
func TestCertificateSizes(t *testing.T) {
	t.Log("Certificate Size Analysis")
	t.Log("==========================")
	t.Log("Larger keys = larger certificates = larger CMS structures")
	t.Log("")

	keySizes := []struct {
		keyType string
		keySize int
		algo    x509.SignatureAlgorithm
	}{
		{"RSA", 1024, x509.SHA256WithRSA},
		{"RSA", 2048, x509.SHA256WithRSA},
		{"RSA", 3072, x509.SHA256WithRSA},
		{"RSA", 4096, x509.SHA256WithRSA},
		{"ECDSA", 256, x509.ECDSAWithSHA256},
		{"ECDSA", 384, x509.ECDSAWithSHA384},
		{"ECDSA", 521, x509.ECDSAWithSHA512},
	}

	t.Log("| Key Type    | Cert Size | PubKey Size | Raw Sig Size |")
	t.Log("|-------------|-----------|-------------|--------------|")

	for _, ks := range keySizes {
		privateKey, cert, err := generateTestCertificate(ks.keyType, ks.keySize, ks.algo)
		if err != nil {
			t.Logf("| %-11s | ERROR: %v", fmt.Sprintf("%s-%d", ks.keyType, ks.keySize), err)
			continue
		}

		// Get raw signature size based on key type
		var sigSize int
		switch k := privateKey.(type) {
		case *rsa.PrivateKey:
			sigSize = k.Size()
		case *ecdsa.PrivateKey:
			// ECDSA signature size is 2 * coordinate size (r, s values)
			sigSize = (k.Curve.Params().BitSize + 7) / 8 * 2
		}

		t.Logf("| %-11s | %9d | %11d | %12d |",
			fmt.Sprintf("%s-%d", ks.keyType, ks.keySize),
			len(cert.Raw),
			len(cert.RawSubjectPublicKeyInfo),
			sigSize)
	}

	t.Log("")
	t.Log("Note: CMS structure size = Cert + Signature + Overhead")
	t.Log("The library must allocate enough space for the entire CMS structure,")
	t.Log("not just the raw signature.")
}

// TestPDFSigningKeySizeSummary prints a summary table of all test cases
func TestPDFSigningKeySizeSummary(t *testing.T) {
	t.Log("PDF Signing Key Size Compatibility Matrix")
	t.Log("==========================================")
	t.Log("")
	t.Log("This table shows how the library allocates buffer space based on")
	t.Log("Certificate.SignatureAlgorithm (CA's signing algorithm) vs what's")
	t.Log("actually needed based on the certificate's public key size.")
	t.Log("")
	t.Log("| Key Config  | Sig Size | CA Algorithm  | Lib Alloc | Risk        |")
	t.Log("|-------------|----------|---------------|-----------|-------------|")

	for _, tc := range testKeySizes {
		risk := "OK"
		if tc.AllocatedByLibrary < tc.ExpectedSigSize {
			risk = "UNDERALLOC"
		}
		t.Logf("| %-11s | %4d     | %-13s | %5d     | %-11s |",
			fmt.Sprintf("%s-%d", tc.KeyType, tc.KeySize),
			tc.ExpectedSigSize,
			tc.CASignatureAlgo,
			tc.AllocatedByLibrary,
			risk)
	}

	t.Log("")
	t.Log("Legend:")
	t.Log("  - Sig Size: Actual signature size produced by the key (bytes)")
	t.Log("  - CA Algorithm: Algorithm used to sign the certificate (Certificate.SignatureAlgorithm)")
	t.Log("  - Lib Alloc: Bytes allocated by library based on CA Algorithm")
	t.Log("  - UNDERALLOC: Library allocates less than needed, may trigger retry")
}
