package pdfsign

import (
	"crypto"
	"crypto/x509"
	"os"
	"testing"

	pdflib "github.com/digitorus/pdf"
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

// TestAddInitials_PreservesInlinePageAttributes is a regression test for a
// bug in addAnnotToPage where inline (non-indirect) page attributes -
// Resources, Rotate, and each element of MediaBox/CropBox - were corrupted
// into self-referencing pointers back at the page object itself.
//
// Value.GetPtr() reports the ID of the object a value was last dereferenced
// *into*; for a value that was never behind an indirect reference at all
// (e.g. a literal array element, or an inline dict), it reports the ID of
// the *containing* object rather than zero. addAnnotToPage used
// `ptr.GetID() > 0` alone to decide "is this a reference", which is
// indistinguishable from "this value simply lives inside object N" without
// also checking that the ID differs from the page's own. testfile12.pdf's
// pages embed MediaBox/CropBox/Rotate/Resources inline (not as indirect
// refs), which triggered exactly this: they came out as e.g. "/Rotate 7 0 R"
// instead of "/Rotate 0" when object 7 was the page being rewritten.
func TestAddInitials_PreservesInlinePageAttributes(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()
	key, cert := pki.IssueLeaf("Initials Tester")

	doc, err := OpenFile("testfiles/testfile12.pdf")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}

	// Capture the original page 1 attributes before any rewriting.
	origPage, err := doc.findPage(1)
	if err != nil {
		t.Fatalf("findPage: %v", err)
	}
	origMediaBox := origPage.Key("MediaBox")
	if origMediaBox.Kind() != pdflib.Array {
		t.Fatalf("expected page 1 to have an inline MediaBox array in the fixture, got kind %v", origMediaBox.Kind())
	}
	var wantMediaBox [4]float64
	for i := 0; i < 4 && i < origMediaBox.Len(); i++ {
		wantMediaBox[i] = origMediaBox.Index(i).Float64()
	}

	appearance := NewAppearance(100, 50)
	appearance.Text("JD")
	// Position the signature on page 2 so page 1 goes through
	// addAnnotToPage (the buggy path) rather than the signature's own
	// createIncPageUpdate rewrite.
	doc.Sign(key, cert).Reason("Test").Appearance(appearance, 10, 10).Page(2)
	doc.AddInitials(appearance).Position(BottomRight, 20, 20)

	outPath := t.TempDir() + "/initials.pdf"
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
	newPage, err := verifyDoc.findPage(1)
	if err != nil {
		t.Fatalf("findPage on signed doc: %v", err)
	}

	newMediaBox := newPage.Key("MediaBox")
	if newMediaBox.Kind() != pdflib.Array {
		t.Fatalf("expected MediaBox to remain a literal array, got kind %v (corrupted into a reference?)", newMediaBox.Kind())
	}
	for i := 0; i < 4; i++ {
		if got := newMediaBox.Index(i).Float64(); got != wantMediaBox[i] {
			t.Errorf("MediaBox[%d] = %v, want %v", i, got, wantMediaBox[i])
		}
	}

	if rotate := newPage.Key("Rotate"); !rotate.IsNull() {
		if rotate.Kind() != pdflib.Integer {
			t.Errorf("expected Rotate to remain a literal integer, got kind %v (corrupted into a reference?)", rotate.Kind())
		}
	}

	if resources := newPage.Key("Resources"); resources.Kind() != pdflib.Dict {
		t.Errorf("expected Resources to remain an inline dict, got kind %v (corrupted into a reference?)", resources.Kind())
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
