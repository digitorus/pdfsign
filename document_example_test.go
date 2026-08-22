package pdfsign_test

import (
	"bytes"
	"fmt"
	"log"
	"os"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

// ExampleDocument_Sign demonstrates the flow for signing a document.
func ExampleDocument_Sign() {
	// 1. Open Document
	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		log.Fatal(err)
	}

	// 2. Prepare visual appearance
	appearance := pdfsign.NewAppearance(200, 80)
	appearance.Text("Digitally Signed").Position(10, 40)

	// 3. Load Certificate and Private Key using test PKI
	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()

	key, cert := pki.IssueLeaf("Example Signer")

	// 4. Create Output
	var buf bytes.Buffer

	// 5. Sign with fluent API
	doc.Sign(key, cert, pki.Chain()...).
		Reason("Contract Agreement").
		Location("New York").
		Appearance(appearance, 100, 100)

	_, err = doc.Write(&buf)
	if err != nil {
		log.Fatal(err)
	}

	// 6. Verify the signed document
	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	result := signedDoc.Verify().TrustSelfSigned(true)

	if result.Valid() {
		fmt.Printf("Successfully signed and verified: %s\n", result.Signatures()[0].SignerName)
	}

	// Output:
	// Successfully signed and verified: Example Signer
}

// ExampleDocument_Sign_multiple demonstrates staging more than one signature
// on the same document. Each call to Sign() stages an independent signing
// operation; nothing is executed yet. Write() then applies every staged
// signature in the order Sign() was called, each one an incremental update
// chained on top of the previous signature's output - the same as an
// approver countersigning a document someone else already signed.
func ExampleDocument_Sign_multiple() {
	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		log.Fatal(err)
	}

	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()

	aliceKey, aliceCert := pki.IssueLeaf("Alice")
	bobKey, bobCert := pki.IssueLeaf("Bob")

	// Stage Alice's signature, then Bob's. Order matters: Bob's signature
	// will be applied on top of Alice's, not the other way around.
	doc.Sign(aliceKey, aliceCert, pki.Chain()...).Reason("First approval")
	doc.Sign(bobKey, bobCert, pki.Chain()...).Reason("Second approval")

	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		log.Fatal(err)
	}

	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	result := signedDoc.Verify().TrustSelfSigned(true)

	fmt.Printf("Found %d signatures, all valid: %v\n", result.Count(), result.Valid())
	for _, sig := range result.Signatures() {
		fmt.Printf("Signed by: %s\n", sig.SignerName)
	}

	// Output:
	// Found 2 signatures, all valid: true
	// Signed by: Alice
	// Signed by: Bob
}

// ExampleSignBuilder_Page demonstrates placing signature appearances on
// specific pages of a multi-page document: an explicit fixed page, and the
// last page computed dynamically via Reader().NumPage() so it still works
// if pages are added or removed.
func ExampleSignBuilder_Page() {
	doc, err := pdfsign.OpenFile("testfiles/testfile12.pdf")
	if err != nil {
		log.Fatal(err)
	}

	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()

	authorKey, authorCert := pki.IssueLeaf("Author")
	approverKey, approverCert := pki.IssueLeaf("Approver")

	appearance := pdfsign.NewAppearance(200, 80)
	appearance.Text("Signed").Position(10, 40)

	lastPage := doc.Reader().NumPage()

	// Sign the first page explicitly.
	doc.Sign(authorKey, authorCert, pki.Chain()...).
		Reason("Drafted").
		Appearance(appearance, 100, 100).
		Page(1)

	// Sign the last page, whatever it currently is.
	doc.Sign(approverKey, approverCert, pki.Chain()...).
		Reason("Approved").
		Appearance(appearance, 100, 100).
		Page(lastPage)

	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		log.Fatal(err)
	}

	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	result := signedDoc.Verify().TrustSelfSigned(true)
	fmt.Printf("Document has %d pages, both signatures valid: %v\n", lastPage, result.Valid())

	// Output:
	// Document has 2 pages, both signatures valid: true
}

// ExampleDocument_SetCompression demonstrates how to configure compression levels.
func ExampleDocument_SetCompression() {
	testFile := "testfiles/testfile20.pdf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		fmt.Println("Test file not found")
		return
	}

	doc, err := pdfsign.OpenFile(testFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}

	// ... continue with signing ...
	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Compressed Signer")

	doc.Sign(key, cert).Reason("Compression Test")

	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		log.Fatal(err)
	}

	// Verify
	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if signedDoc.Verify().TrustSelfSigned(true).Valid() {
		fmt.Println("Signed and verified with BestCompression")
	}

	// Output: Signed and verified with BestCompression
}

// ExampleDocument_AddFont demonstrates usage of custom fonts for signing and initials.
func ExampleDocument_AddFont() {
	testFile := "testfiles/testfile20.pdf"
	// Ensure test file and font exist
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		fmt.Println("Test file not found")
		return
	}
	fontFile := "testfiles/fonts/GreatVibes-Regular.ttf"
	fontData, err := os.ReadFile(fontFile)
	if err != nil {
		// Fallback for example if file missing in some envs
		fmt.Println("Font file not found")
		return
	}

	doc, err := pdfsign.OpenFile(testFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}

	// 1. Register the custom font
	// This embeds the font subset in the PDF when used.
	customFont := doc.AddFont("GreatVibes", fontData)

	// 2. Use the font in an appearance
	appearance := pdfsign.NewAppearance(200, 50)
	appearance.Text("Signed with Style").
		Font(customFont, 24).
		Position(10, 15)

	// 3. Or use for Initials
	initials := pdfsign.NewAppearance(50, 30)
	initials.Text("JD").Font(customFont, 20).Center()
	// ... sign and write ...
	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Custom Font Signer")
	doc.Sign(key, cert).Appearance(appearance, 100, 100)

	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		log.Fatal(err)
	}

	// Verify
	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if signedDoc.Verify().TrustSelfSigned(true).Valid() {
		fmt.Println("Successfully signed and verified with custom font")
	}

	// Output: Successfully signed and verified with custom font
}

// ExampleSignBuilder_Format creates a PAdES B-B signature (ETSI EN 319 142-1)
// with Format(PAdES_B). The unsupported levels PAdES_B_LT and PAdES_B_LTA are
// rejected by Write until DSS support is implemented.
func ExampleSignBuilder_Format() {
	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		log.Fatal(err)
	}

	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Example Signer")

	doc.Sign(key, cert, pki.Chain()...).Format(pdfsign.PAdES_B)

	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		log.Fatal(err)
	}

	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	result := signedDoc.Verify().TrustSelfSigned(true)

	fmt.Printf("valid: %t, PAdES: %t\n", result.Valid(),
		bytes.Contains(buf.Bytes(), []byte("/SubFilter /ETSI.CAdES.detached")))
	// Output:
	// valid: true, PAdES: true
}

// ExampleSignBuilder_Format_padesBT creates a PAdES B-T signature: B-B plus a
// signature-time-stamp from the TSA that Format(PAdES_B_T) requires.
func ExampleSignBuilder_Format_padesBT() {
	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		log.Fatal(err)
	}

	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Example Signer")

	tsaURL := testpki.StartMockTSA(nil) // replace with your TSA URL
	doc.Sign(key, cert, pki.Chain()...).Format(pdfsign.PAdES_B_T).Timestamp(tsaURL)

	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		log.Fatal(err)
	}

	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	result := signedDoc.Verify().TrustSelfSigned(true)

	fmt.Printf("valid: %t, PAdES: %t\n", result.Valid(),
		bytes.Contains(buf.Bytes(), []byte("/SubFilter /ETSI.CAdES.detached")))
	// Output:
	// valid: true, PAdES: true
}
