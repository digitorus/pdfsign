package pdfsign_test

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"log"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

// ExampleDocument_Verify demonstrates how to verify a signed PDF with the fluent API.
func ExampleDocument_Verify() {
	// Setup: Create a signed PDF in memory to verify
	pki := testpki.NewTestPKI(nil) // Use nil for examples (uses log.Fatal on error)
	pki.StartCRLServer()
	defer pki.Close()

	key, cert := pki.IssueLeaf("Example Signer")

	docToSign, _ := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	appearance := pdfsign.NewAppearance(200, 80)
	appearance.Text("Digitally Signed").Position(10, 40)
	docToSign.Sign(key, cert, pki.Chain()...).Appearance(appearance, 1, 100, 100)

	var signedBuffer bytes.Buffer
	if _, err := docToSign.Write(&signedBuffer); err != nil {
		log.Fatal(err)
	}

	// --- Verification with Fluent API ---
	doc, err := pdfsign.Open(bytes.NewReader(signedBuffer.Bytes()), int64(signedBuffer.Len()))
	if err != nil {
		log.Fatal(err)
	}

	// Configure verification with chainable methods
	// Access .Valid() triggers lazy execution
	result := doc.Verify().
		TrustSignatureTime(true).
		MinRSAKeySize(2048).
		AllowedAlgorithms(x509.ECDSA)

	// Check validity (this triggers the actual verification)
	if result.Valid() {
		fmt.Println("Document is valid")
		for _, sig := range result.Signatures() {
			fmt.Printf("Signed by: %s\n", sig.SignerName)
		}
	} else {
		fmt.Println("Document has invalid signatures")
		if result.Err() != nil {
			fmt.Printf("Error: %v\n", result.Err())
		}
	}

	// Output:
	// Document is valid
	// Signed by: Example Signer
}

// Example_verifyStrict demonstrates strict verification mode.
func Example_verifyStrict() {
	doc, err := pdfsign.OpenFile("testfiles/testfile_multi.pdf")
	if err != nil {
		log.Fatal(err)
	}

	// Strict() enables all security checks
	result := doc.Verify().Strict()

	fmt.Printf("Found %d signatures\n", result.Count())
	fmt.Printf("All valid: %v\n", result.Valid())

	// Output:
	// Found 3 signatures
	// All valid: false
}
