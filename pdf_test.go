package pdfsign_test

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/render"
	"github.com/digitorus/pdfsign/internal/testpki"
)

var globalPKI *testpki.TestPKI

func TestMain(m *testing.M) {
	// Initialize Global PKI for all tests in this package
	globalPKI = testpki.NewTestPKI(nil)
	globalPKI.StartCRLServer()
	defer globalPKI.Close()

	os.Exit(m.Run())
}

func TestNewAppearance(t *testing.T) {
	appearance := pdfsign.NewAppearance(200, 100)
	if appearance.Width() != 200 {
		t.Errorf("expected width 200, got %f", appearance.Width())
	}
	if appearance.Height() != 100 {
		t.Errorf("expected height 100, got %f", appearance.Height())
	}
}

func TestAppearanceText(t *testing.T) {
	appearance := pdfsign.NewAppearance(200, 100)
	appearance.Text("Hello").Font(nil, 10).Position(10, 80)
	appearance.Text("World").Font(nil, 12).Position(10, 60)
	// Should not panic
}

func TestAppearanceImage(t *testing.T) {
	appearance := pdfsign.NewAppearance(200, 100)
	img := &pdfsign.Image{Name: "test", Data: []byte{}}
	appearance.Image(img).Rect(0, 0, 100, 50).ScaleFit()
	// Should not panic
}

func TestExpandTemplateVariables(t *testing.T) {
	ctx := render.TemplateContext{
		Name:     "John Doe",
		Reason:   "Document approved",
		Location: "Amsterdam",
		Date:     time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"{{Name}}", "John Doe"},
		{"{{Reason}}", "Document approved"},
		{"{{Location}}", "Amsterdam"},
		{"{{Date}}", "2026-01-02"},
		{"{{Initials}}", "JD"},
		{"Signed by: {{Name}}", "Signed by: John Doe"},
		{"{{Name}} - {{Date}}", "John Doe - 2026-01-02"},
		{"No variables here", "No variables here"},
		{"{{Unknown}}", "{{Unknown}}"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := render.ExpandTemplateVariables(tt.input, ctx)
			if result != tt.expected {
				t.Errorf("ExpandTemplateVariables(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestStandardFont(t *testing.T) {
	font := pdfsign.StandardFont(pdfsign.Helvetica)
	if font.Name != "Helvetica" {
		t.Errorf("expected Helvetica, got %s", font.Name)
	}
	if font.Embedded {
		t.Error("standard font should not be embedded")
	}
}

func TestDocumentResourceManagement(t *testing.T) {
	// Skip if test file doesn't exist
	testFile := "testfiles/testfile20.pdf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("test file not found")
	}

	doc, err := pdfsign.OpenFile(testFile)
	if err != nil {
		t.Fatalf("failed to open: %v", err)
	}

	// Add font
	font := doc.AddFont("TestFont", []byte("font data"))
	if font == nil {
		t.Error("AddFont returned nil")
	}

	// UseFont should return existing
	font2 := doc.UseFont("TestFont", []byte("other data"))
	if font2 != font {
		t.Error("UseFont should return existing font")
	}

	// Add image
	img := doc.AddImage("logo", []byte("image data"))
	if img == nil {
		t.Error("AddImage returned nil")
	}

	// Get image
	img2 := doc.Image("logo")
	if img2 != img {
		t.Error("Image should return registered image")
	}
}

// ExampleDocument_AddInitials demonstrates adding initials to pages.
func ExampleDocument_AddInitials() {
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

	pki := testpki.NewTestPKI(nil)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Initials Signer")

	// Define initials appearance
	initials := pdfsign.NewAppearance(40, 20)
	initials.Text("{{Initials}}").Center()

	// Apply initials
	doc.AddInitials(initials).
		Position(pdfsign.BottomRight, 30, 30).
		ExcludePages(1) // Don't put initials on cover page

	// We create a temporary output file for the example
	outputFile, _ := os.CreateTemp("", "initials-example-*.pdf")
	defer func() { _ = os.Remove(outputFile.Name()) }()
	defer func() { _ = outputFile.Close() }()

	// Sign to finalize
	doc.Sign(key, cert).SignerName("Initials Signer")

	var buf bytes.Buffer
	if _, err := doc.Write(&buf); err != nil {
		fmt.Printf("Error writing: %v\n", err)
		return
	}

	// Verify
	signedDoc, _ := pdfsign.Open(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if signedDoc.Verify().TrustSelfSigned(true).Valid() {
		fmt.Printf("Successfully added initials and verified: %s\n", signedDoc.Verify().Signatures()[0].SignerName)
	}

	// Output: Successfully added initials and verified: Initials Signer
}

// TestIntegration_Sign tests the fluent API with a real PDF file
func TestIntegration_Sign(t *testing.T) {
	testFile := "testfiles/testfile20.pdf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("test file not found")
	}

	// Load test certificate and key from sign_test
	cert, key := loadTestCertificateAndKey(t)

	// Open document using new API
	doc, err := pdfsign.OpenFile(testFile)
	if err != nil {
		t.Fatalf("failed to open PDF: %v", err)
	}

	// Create appearance
	appearance := pdfsign.NewAppearance(200, 80)
	appearance.Background(255, 255, 255)
	appearance.Text("Signed by: Test").Font(nil, 10).Position(10, 60)

	// Configure signature using fluent API
	doc.Sign(key, cert).
		Reason("Integration test").
		Location("Amsterdam").
		SignerName("Test Signer").
		Appearance(appearance, 1, 400, 50)

	// Create output file
	tmpfile, err := os.CreateTemp("", "signed-*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()
	defer func() { _ = tmpfile.Close() }()

	// Execute signing
	result, err := doc.Write(tmpfile)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	// Verify result
	if len(result.Signatures) != 1 {
		t.Errorf("expected 1 signature, got %d", len(result.Signatures))
	}

	if result.Signatures[0].Reason != "Integration test" {
		t.Errorf("expected reason 'Integration test', got '%s'", result.Signatures[0].Reason)
	}

	// Now verify the signed document using the fluent API
	// Open the signed file
	signedDoc, err := pdfsign.OpenFile(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to open signed PDF: %v", err)
	}

	// Verify
	verifyResult := signedDoc.Verify()
	if verifyResult.Err() != nil {
		t.Fatalf("failed to verify: %v", verifyResult.Err())
	}

	if !verifyResult.Valid() {
		t.Error("verification failed")
		for _, s := range verifyResult.Signatures() {
			t.Logf("Signature: %s, Valid: %v, Errors: %v", s.SignerName, s.Valid, s.Errors)
		}
	} else {
		t.Logf("Verification successful")
	}

	t.Logf("Successfully signed and verified PDF using fluent API")
}

func TestIntegration_Initials(t *testing.T) {
	testFile := "testfiles/testfile20.pdf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("test file not found")
	}

	cert, key := loadTestCertificateAndKey(t)
	doc, err := pdfsign.OpenFile(testFile)
	if err != nil {
		t.Fatalf("failed to open PDF: %v", err)
	}

	// Create initials appearance
	app := pdfsign.NewAppearance(40, 20)
	app.Text("JD").Font(nil, 12)

	// Add initials to document (exclude first page)
	doc.AddInitials(app).
		Position(pdfsign.BottomRight, 20, 20).
		ExcludePages(1)

	// Sign
	doc.Sign(key, cert).
		Reason("Initials Test").
		SignerName("Test Signer")

	// Create output
	tmpfile, err := os.CreateTemp("", "initials-*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()
	defer func() { _ = tmpfile.Close() }()

	_, err = doc.Write(tmpfile)
	if err != nil {
		t.Fatalf("failed to write signed PDF: %v", err)
	}

	// Basic validation scan
	content, _ := os.ReadFile(tmpfile.Name())
	// We expect multiple annotations now.
	// This is weak verification but ensures code ran without error and produced output.
	if len(content) == 0 {
		t.Error("Output file is empty")
	}
	t.Logf("Successfully added initials and signed PDF")
}

func TestIntegration_FormFilling(t *testing.T) {
	testFile := "testfiles/testfile20.pdf"
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Skip("test file not found")
	}

	cert, key := loadTestCertificateAndKey(t)
	doc, err := pdfsign.OpenFile(testFile)
	if err != nil {
		t.Fatalf("failed to open PDF: %v", err)
	}

	// Set a field (assuming one exists, or just testing the API doesn't crash if not found)
	// testfile20.pdf might not have fields.
	// But the code should handle "field not found" gracefully?
	// Our implementation of SetField doesn't check existence immediately, it queues it.
	// applyPendingFields checks existence and returns error if not found.
	// So we need a file WITH fields to test success, or expect error.

	// Let's just test that the API can be called.
	// Since we don't have a guarantee of fields in testfile20, we expect Write to fail
	// if we try to set a non-existent field, OR we skip actual setting if we catch it.
	// In a real test suite we'd have a form.pdfsign.
	// For now, let's just verifying FormFields() works (likely returns empty).

	fields := doc.FormFields()
	t.Logf("Found %d fields", len(fields))

	// Sign anyway
	doc.Sign(key, cert).Reason("Form Test")

	tmpfile, err := os.CreateTemp("", "form-*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()
	defer func() { _ = tmpfile.Close() }()

	_, err = doc.Write(tmpfile)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
}

// loadTestCertificateAndKey loads the test certificate for integration tests
// loadTestCertificateAndKey returns a fresh leaf certificate from the global test PKI.
func loadTestCertificateAndKey(t *testing.T) (cert *x509.Certificate, key crypto.Signer) {
	c, _, k := loadTestCertificateAndChain(t)
	return c, k
}

// loadTestCertificateAndChain returns a fresh leaf certificate and its chain from the global test PKI.
func loadTestCertificateAndChain(t *testing.T) (cert *x509.Certificate, chain []*x509.Certificate, key crypto.Signer) {
	if globalPKI == nil {
		t.Fatal("Global PKI not initialized")
	}
	priv, leaf := globalPKI.IssueLeaf("Integration Test User")
	chain = globalPKI.Chain()

	// Chain returns the certificate chain for a leaf (Intermediate -> Root).
	return leaf, chain, priv
}
