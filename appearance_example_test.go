package pdfsign_test

import (
	"bytes"
	"fmt"
	"log"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

// ExampleNewAppearance demonstrates creating a basic appearance.
func ExampleNewAppearance() {
	app := pdfsign.NewAppearance(200, 80)
	app.Text("Digitally Signed").Position(10, 40)

	fmt.Printf("Appearance: %gx%g\n", app.Width(), app.Height())
	// Output: Appearance: 200x80
}

// ExampleAppearance_advanced demonstrates building a complex visual signature and verifying it.
func ExampleAppearance_advanced() {
	// Setup: Create a PKI environment
	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Advanced Signer")

	// Open a PDF to sign
	docToSign, _ := pdfsign.OpenFile("testfiles/testfile_form.pdf")

	// Create appearance with 300x100 dimensions
	app := pdfsign.NewAppearance(300, 100)

	// 1. Add Background and Border
	app.Background(240, 240, 240)  // Light Gray
	app.Border(1.0, 100, 100, 100) // Dark Gray Border

	// 2. Add styled text
	app.Text("Digitally Signed").
		Font(nil, 10). // Standard font (Helvetica)
		SetColor(50, 50, 50).
		Position(10, 80)

	// 3. Add dynamic variables
	app.Text("{{Name}}").
		Font(pdfsign.StandardFont(pdfsign.HelveticaBold), 14).
		SetColor(0, 0, 0).
		Position(10, 60)

	app.Text("Date: {{Date}}").
		Font(nil, 9).
		Position(10, 40)

	// 4. Add a "Seal" (simulated with text here)
	app.Text("[ SEAL ]").
		Font(pdfsign.StandardFont(pdfsign.Courier), 12).
		SetColor(0, 0, 128).
		Position(220, 40)

	// Sign the document with this appearance
	docToSign.Sign(key, cert, pki.Chain()...).Appearance(app, 1, 100, 300)

	// Write signature
	var signedBuffer bytes.Buffer
	if _, err := docToSign.Write(&signedBuffer); err != nil {
		log.Fatal(err)
	}

	// Verify the result
	doc, err := pdfsign.Open(bytes.NewReader(signedBuffer.Bytes()), int64(signedBuffer.Len()))
	if err != nil {
		log.Fatal(err)
	}

	result := doc.Verify().TrustSelfSigned(true) // Trust our test PKI

	fmt.Printf("Signature valid: %v\n", result.Valid())
	fmt.Printf("Signer: %s\n", result.Signatures()[0].SignerName)

	// Output:
	// Signature valid: true
	// Signer: Advanced Signer
}

// ExampleAppearance_Standard demonstrates using the built-in standard appearance.
func ExampleAppearance_Standard() {
	// Create a standard appearance with professional metadata layout
	app := pdfsign.NewAppearance(300, 100).Standard()

	// The Standard() method pre-populates the appearance with:
	// - {{Name}} - Signer name (larger font)
	// - Reason: {{Reason}}
	// - Location: {{Location}}
	// - Date: {{Date}}

	// These template variables are automatically expanded when the signature
	// is rendered, using values from SignBuilder's SignerName(), Reason(), Location().

	fmt.Printf("Standard appearance with dimensions %gx%g\n", app.Width(), app.Height())

	// Demonstrate actual usage
	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Standard Signer")
	docToSign, _ := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	docToSign.Sign(key, cert).Appearance(app, 1, 100, 100)

	var buf bytes.Buffer
	_, _ = docToSign.Write(&buf)

	// Verify
	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if signedDoc.Verify().TrustSelfSigned(true).Valid() {
		fmt.Println("Successfully signed and verified with standard appearance")
	}

	// Output:
	// Standard appearance with dimensions 300x100
	// Successfully signed and verified with standard appearance
}
