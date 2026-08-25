package pdfsign_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

// ExampleDocument_Sign_postQuantumOnly signs and validates a PAdES B-T PDF
// without introducing a classical public-key signature in the signer, CA,
// revocation, or timestamp paths.
func ExampleDocument_Sign_postQuantumOnly() {
	doc, err := pdfsign.OpenFile("testfiles/testfile12.pdf")
	if err != nil {
		log.Fatal(err)
	}

	pki := testpki.NewTestPKIWithConfig(nil, testpki.TestPKIConfig{
		Profile:         testpki.MLDSA_65,
		IntermediateCAs: 1,
	})
	pki.StartCRLServer()
	defer pki.Close()

	privateKey, certificate := pki.IssueLeaf("PQC PDF Signer")
	tsaURL := pki.StartMockTSA()

	doc.Sign(privateKey, certificate, pki.Chain()...).
		Format(pdfsign.PAdES_B_T).
		Digest(crypto.SHA512).
		Timestamp(tsaURL).
		Reason("Post-quantum approval")

	var output bytes.Buffer
	if _, err := doc.Write(&output); err != nil {
		log.Fatal(err)
	}

	signed, err := pdfsign.Open(bytes.NewReader(output.Bytes()), int64(output.Len()))
	if err != nil {
		log.Fatal(err)
	}
	result := signed.Verify().
		TrustedRoots(pki.RootPool()).
		AllowedAlgorithms(x509.MLDSA).
		ValidateFullChain(true).
		ValidateTimestampCertificates(true).
		ExternalChecks(true)

	signature := result.Signatures()[0]
	pqcSignerAndTSA := signature.Certificate.PublicKeyAlgorithm == x509.MLDSA &&
		signature.Timestamp != nil && signature.Timestamp.Certificate.PublicKeyAlgorithm == x509.MLDSA

	fmt.Printf("ML-DSA signer and TSA: %t\n", pqcSignerAndTSA)
	fmt.Printf("OCSP and CRL checked: %t\n", pki.OCSPRequests > 0 && pki.Requests > 0)
	fmt.Printf("Signature and timestamp valid: %t\n", result.Valid() && signature.TimestampValid)

	// Output:
	// ML-DSA signer and TSA: true
	// OCSP and CRL checked: true
	// Signature and timestamp valid: true
}
