package pdfsign_test

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestCryptoAlgorithms(t *testing.T) {
	testCases := []struct {
		name    string
		profile testpki.KeyProfile
	}{
		{"RSA_2048", testpki.RSA_2048},
		{"RSA_3072", testpki.RSA_3072},
		{"RSA_4096", testpki.RSA_4096},
		{"ECDSA_P256", testpki.ECDSA_P256},
		{"ECDSA_P384", testpki.ECDSA_P384},
		{"ECDSA_P521", testpki.ECDSA_P521},
	}

	inputFile := "testfiles/testfile12.pdf"

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 1. Initialize PKI with specific profile
			pki := testpki.NewTestPKIWithConfig(t, testpki.TestPKIConfig{
				Profile:         tc.profile,
				IntermediateCAs: 1, // Standard chain
			})
			defer pki.Close()
			pki.StartCRLServer()

			// 2. Issue Leaf Certificate
			key, cert := pki.IssueLeaf("Crypto Test User")
			chain := pki.Chain()

			// 3. Prepare PDF
			f, err := os.Open(inputFile)
			if err != nil {
				t.Fatalf("failed to open input file: %v", err)
			}
			defer func() { _ = f.Close() }()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("failed to stat input file: %v", err)
			}

			doc, err := pdfsign.Open(f, info.Size())
			if err != nil {
				t.Fatalf("failed to create document: %v", err)
			}

			// 4. Sign PDF
			// Sign() stages the operation. Write() executes it.
			doc.Sign(key, cert, chain...)

			// 5. Verify Output
			outputDir := "testfiles/crypto_test_output"
			_ = os.MkdirAll(outputDir, 0755)
			outputPath := filepath.Join(outputDir, fmt.Sprintf("signed_%s.pdf", tc.name))

			outFile, err := os.Create(outputPath)
			if err != nil {
				t.Fatalf("failed to create output file: %v", err)
			}
			defer func() { _ = outFile.Close() }()

			if _, err := doc.Write(outFile); err != nil {
				t.Errorf("Sign() failed for %s: %v", tc.name, err)
			}
			_ = outFile.Close() // Close explicitly before validation

			// 6. Internal Verification (pdf package)
			// Verify using our own library to ensure cryptographic validity.
			verifyDoc, err := pdfsign.OpenFile(outputPath)
			if err != nil {
				t.Fatalf("failed to open signed pdf for verification: %v", err)
			}

			// Configure verification based on profile
			var verifyResult *pdfsign.VerifyBuilder
			switch tc.profile {
			case testpki.RSA_2048:
				verifyResult = verifyDoc.Verify().
					AllowedAlgorithms(x509.RSA).
					MinRSAKeySize(2048)
			case testpki.RSA_3072:
				verifyResult = verifyDoc.Verify().
					AllowedAlgorithms(x509.RSA).
					MinRSAKeySize(3072)
			case testpki.RSA_4096:
				verifyResult = verifyDoc.Verify().
					AllowedAlgorithms(x509.RSA).
					MinRSAKeySize(4096)
			case testpki.ECDSA_P256:
				verifyResult = verifyDoc.Verify().
					AllowedAlgorithms(x509.ECDSA).
					MinECDSAKeySize(256)
			case testpki.ECDSA_P384:
				verifyResult = verifyDoc.Verify().
					AllowedAlgorithms(x509.ECDSA).
					MinECDSAKeySize(384)
			case testpki.ECDSA_P521:
				verifyResult = verifyDoc.Verify().
					AllowedAlgorithms(x509.ECDSA).
					MinECDSAKeySize(521)
			}
			if verifyResult.Err() != nil {
				t.Fatalf("internal verification failed to execute: %v", verifyResult.Err())
			}
			if !verifyResult.Valid() {
				t.Errorf("internal verification reported invalid signature for %s", tc.name)
				for _, sig := range verifyResult.Signatures() {
					if !sig.Valid {
						t.Errorf("  invalid signature: %s (Reason: %s)", sig.SignerName, sig.Reason)
						for _, w := range sig.Warnings {
							t.Logf("    warning: %s", w)
						}
					}
				}
			} else {
				t.Logf("internal verification passed for %s (algo/size checked via API)", tc.name)
			}

			// 7. External Validation (pdfcpu) if available
			// Validate PDF structure using strict mode to ensure no corruption was introduced.
			// We use a known-good input file (testfile12.pdf) so strict validation should pass.
			pdfcpuPath, err := exec.LookPath("pdfcpu")
			if err == nil {
				// Strict mode only. If this fails, it means we likely broke the PDF structure
				// (assuming the input file was clean).
				cmd := exec.Command(pdfcpuPath, "validate", "-mode=strict", outputPath)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Errorf("pdfcpu validation failed for %s: %v\nOutput: %s", tc.name, err, out)
				} else {
					t.Logf("pdfcpu validated %s successfully", tc.name)
				}
			} else {
				t.Logf("pdfcpu not found, skipping external validation for %s", tc.name)
			}
		})
	}
}
