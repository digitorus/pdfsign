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
		Appearance(appearance, 1, 100, 100)

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
	doc.Sign(key, cert).Appearance(appearance, 1, 100, 100)

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
