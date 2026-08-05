package pdfsign_test

import (
	"bytes"
	"testing"

	"github.com/digitorus/pdfsign"
	"github.com/digitorus/pdfsign/internal/testpki"
)

func TestVerify_Execute_NoFile(t *testing.T) {
	// Test behavior when document has no reader (dummy doc)
	doc := &pdfsign.Document{} // initialized without OpenFile

	result := doc.Verify()
	if result.Err() == nil {
		t.Error("Expected error when verifying uninitialized document")
	}
}

// TestVerify_TrustedRoots proves TrustedRoots() actually gates chain trust
// instead of being a no-op: the exact same signed document must verify as
// trusted against its real issuing root, and as untrusted against an
// unrelated root, with TrustSelfSigned left at its secure default (false).
func TestVerify_TrustedRoots(t *testing.T) {
	pki := testpki.NewTestPKI(t)
	pki.StartCRLServer()
	defer pki.Close()

	key, cert := pki.IssueLeaf("Trusted Roots Tester")

	doc, err := pdfsign.OpenFile("testfiles/testfile_form.pdf")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	doc.Sign(key, cert, pki.Chain()...).Reason("TrustedRoots test")

	var signed bytes.Buffer
	if _, err := doc.Write(&signed); err != nil {
		t.Fatalf("Write: %v", err)
	}

	t.Run("correct root is trusted", func(t *testing.T) {
		verifyDoc, err := pdfsign.Open(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		result := verifyDoc.Verify().TrustedRoots(pki.RootPool())
		if err := result.Err(); err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !result.Valid() {
			t.Fatalf("expected Valid() with the correct root pool, signatures: %+v", result.Signatures())
		}
		if len(result.Signatures()) != 1 || !result.Signatures()[0].TrustedChain {
			t.Errorf("expected TrustedChain=true with the correct root pool, got %+v", result.Signatures())
		}
	})

	t.Run("unrelated root is untrusted", func(t *testing.T) {
		otherPKI := testpki.NewTestPKI(t)
		otherPKI.StartCRLServer()
		defer otherPKI.Close()

		verifyDoc, err := pdfsign.Open(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		result := verifyDoc.Verify().TrustedRoots(otherPKI.RootPool())
		if result.Valid() {
			t.Fatal("expected Valid()==false against an unrelated root pool")
		}
		if len(result.Signatures()) != 1 || result.Signatures()[0].TrustedChain {
			t.Errorf("expected TrustedChain=false against an unrelated root pool, got %+v", result.Signatures())
		}
	})

	t.Run("no trusted roots and no TrustSelfSigned is untrusted by default", func(t *testing.T) {
		verifyDoc, err := pdfsign.Open(bytes.NewReader(signed.Bytes()), int64(signed.Len()))
		if err != nil {
			t.Fatalf("Open: %v", err)
		}

		result := verifyDoc.Verify()
		if result.Valid() {
			t.Fatal("expected Valid()==false by default with no TrustedRoots and no TrustSelfSigned")
		}
	})
}

// Integration verification tests for specific options are covered in pdf_test.go
