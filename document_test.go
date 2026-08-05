package pdfsign

import (
	"crypto"
	"crypto/x509"
	"os"
	"testing"

	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestSignBuilder_FluentAPI(t *testing.T) {
	doc := &Document{}
	cert := &x509.Certificate{}

	sb := doc.Sign(nil, cert)
	sb.Contact("email@example.com").
		Type(CertificationSignature).
		Permission(AllowFormFilling).
		Format(PAdES_B_LTA).
		Timestamp("http://tsa.example.com").
		TimestampAuth("user", "pass").
		Digest(crypto.SHA512).
		C2PACreator("TestApp").
		C2PAClaimGenerator("TestGen")

	if sb.contact != "email@example.com" {
		t.Errorf("Expected contact email@example.com, got %s", sb.contact)
	}
	if sb.sigType != CertificationSignature {
		t.Errorf("Expected sigType CertificationSignature, got %v", sb.sigType)
	}
	if sb.permission != AllowFormFilling {
		t.Errorf("Expected permission AllowFormFilling, got %v", sb.permission)
	}
	if sb.format != PAdES_B_LTA {
		t.Errorf("Expected format PAdES_B_LTA, got %v", sb.format)
	}
	if sb.tsa != "http://tsa.example.com" {
		t.Errorf("Expected tsa http://tsa.example.com, got %s", sb.tsa)
	}
	if sb.tsaUser != "user" {
		t.Errorf("Expected tsaUser user, got %s", sb.tsaUser)
	}
	if sb.tsaPass != "pass" {
		t.Errorf("Expected tsaPass pass, got %s", sb.tsaPass)
	}
	if sb.digest != crypto.SHA512 {
		t.Errorf("Expected digest SHA512, got %v", sb.digest)
	}
	if sb.c2paCreator != "TestApp" {
		t.Errorf("Expected c2paCreator TestApp, got %s", sb.c2paCreator)
	}
	if sb.c2paClaim != "TestGen" {
		t.Errorf("Expected c2paClaim TestGen, got %s", sb.c2paClaim)
	}
}

// TestWrite_MultipleStagedSignatures is a regression test for a bug where
// Write() signed every staged doc.Sign() call against the document's
// original unsigned bytes and wrote each pass's full output to the same
// writer, instead of chaining each pass as an incremental update on top of
// the previous pass's signed output. That produced a stream of concatenated,
// unrelated single-signature documents rather than one document carrying
// every staged signature.
func TestWrite_MultipleStagedSignatures(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	keyAlice, certAlice := pki.IssueLeaf("Alice")
	keyBob, certBob := pki.IssueLeaf("Bob")

	doc, err := OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}

	doc.Sign(keyAlice, certAlice, pki.Chain()...).Reason("First (Alice)")
	doc.Sign(keyBob, certBob, pki.Chain()...).Reason("Second (Bob)")

	outPath := t.TempDir() + "/multisig.pdf"
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("failed to create output file: %v", err)
	}
	if _, err := doc.Write(out); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close output: %v", err)
	}

	verifyDoc, err := OpenFile(outPath)
	if err != nil {
		t.Fatalf("re-opening signed document: %v", err)
	}

	vr := verifyDoc.Verify().TrustSelfSigned(true)
	if err := vr.Err(); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if vr.Count() != 2 {
		t.Fatalf("expected 2 signatures, got %d", vr.Count())
	}

	var names []string
	for _, sig := range vr.Signatures() {
		names = append(names, sig.SignerName)
		if !sig.Valid {
			t.Errorf("signature %s invalid: %v", sig.SignerName, sig.Errors)
		}
	}
	if len(names) != 2 || names[0] != "Alice" || names[1] != "Bob" {
		t.Errorf("expected signers [Alice Bob] in order, got %v", names)
	}
}

func TestDocument_SimpleMethods(t *testing.T) {
	doc := &Document{}

	// Timestamp builder
	ts := doc.Timestamp("http://tsa.example.com")
	if ts == nil {
		t.Error("Timestamp builder returned nil")
	}

	// Compliance
	doc.SetCompliance(PDFA_1B)

	// Reader (will be nil for empty doc, but method runs)
	if doc.Reader() != nil {
		t.Error("Expected nil reader for empty doc")
	}

	// Open invalid file
	_, err := OpenFile("non_existent_file.pdf")
	if err == nil {
		t.Error("Expected error opening non-existent file")
	}
}
