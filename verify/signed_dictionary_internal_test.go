package verify

import (
	"bytes"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
)

// TestSignedSignatureDictionary covers ISO 32000-1 12.8.1: the signature
// dictionary lies inside its own /ByteRange, so the copy in the signed revision
// is the one to validate. An incremental update cannot un-certify a document
// by redefining the dictionary, or by pointing its field at a copy.
func TestSignedSignatureDictionary(t *testing.T) {
	certified := signedPDF{catalog: certifiedCatalog, field: signatureField, signature: signatureDict(docMDPReference + " /Name (Alice)")}

	t.Run("an unchanged dictionary passes", func(t *testing.T) {
		f := certified
		f.updateID, f.updateBody = 7, newAnnotation
		signer, err := checkFixture(t, f)
		if err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Fatalf("expected the P=1 rejection for the update, got %v", err)
		}
		if len(signer.ValidationErrors) != 0 {
			t.Fatalf("expected no validation error before the DocMDP check, got %v", signer.ValidationErrors)
		}
	})

	t.Run("a redefined dictionary is validated as signed", func(t *testing.T) {
		// The update rewrites the signature dictionary with the same bytes
		// and range but no DocMDP transform and another name.
		f := certified
		f.updateID, f.updateBody = 5, signatureDict("/Name (Mallory)")
		signer, err := checkFixture(t, f)
		if !hasValidationError(signer, "modified after signing: /Reference") {
			t.Errorf("expected the redefinition to be reported, got %v", signer.ValidationErrors)
		}
		if err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Errorf("expected the signed transform to stay enforced, got %v", err)
		}
	})

	t.Run("a field pointed at a new dictionary is rejected", func(t *testing.T) {
		// The update points the field at object 8, a signature dictionary
		// the signed revision does not contain.
		f := certified
		f.updateID, f.updateBody = 4, "<< /FT /Sig /T (sig1) /V 8 0 R >>"
		f.updates = []updateObject{{8, strings.Replace(signatureDict(""), "<01>", "<02>", 1)}}
		signer, _ := checkFixture(t, f)
		if !hasValidationError(signer, "not part of the revision") {
			t.Errorf("expected the repointed field to be reported, got %v", signer.ValidationErrors)
		}
	})

	t.Run("a field pointed at a copy is matched by its bytes", func(t *testing.T) {
		// Object 8 copies the signed dictionary without its transform; the
		// field is pointed at it. The copy is found by its /Contents and its
		// missing /Reference reported.
		f := certified
		f.updateID, f.updateBody = 4, "<< /FT /Sig /T (sig1) /V 8 0 R >>"
		f.updates = []updateObject{{8, signatureDict("")}}
		signer, err := checkFixture(t, f)
		if !hasValidationError(signer, "modified after signing: /Reference") {
			t.Errorf("expected the copy to be reported, got %v", signer.ValidationErrors)
		}
		if err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Errorf("expected the signed transform to stay enforced, got %v", err)
		}
	})

	t.Run("VerifySignature reads the signer from the signed copy", func(t *testing.T) {
		f := certified
		f.updateID, f.updateBody = 5, signatureDict(docMDPReference+" /Name (Mallory)")
		fileBytes := f.build(t)
		rdr, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		v := rdr.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(0).Key("V")
		if got := v.Key("Name").Text(); got != "Mallory" {
			t.Fatalf("fixture: current /Name = %q, want Mallory", got)
		}

		// The fixture's /Contents is not a PKCS#7 blob, so verification
		// stops there; what was decided before that is what matters here.
		signer, _ := VerifySignature(v, bytes.NewReader(fileBytes), int64(len(fileBytes)), DefaultVerifyOptions())
		if signer.Name != "Alice" {
			t.Errorf("signer name = %q, want the signed copy's Alice", signer.Name)
		}
		// The update itself is a change P=1 forbids; the changed /Name is
		// informational and is not reported as a modified dictionary.
		if hasValidationError(signer, "modified after signing") {
			t.Errorf("a changed /Name alone must not count as a modified dictionary, got %v", signer.ValidationErrors)
		}
	})
}

func TestCanonical(t *testing.T) {
	inline := signedPDF{catalog: certifiedCatalog, field: signatureField, signature: signatureDict(docMDPReference)}
	fileBytes := inline.build(t)
	rdr, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	ref := rdr.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(0).Key("V").Key("Reference")

	got := canonical(ref, 0)
	want := `[<</TransformMethod /DocMDP /TransformParams <</P 1 /Type /TransformParams /V /1.2>> /Type /SigRef>>]`
	if got != want {
		t.Errorf("canonical(/Reference) = %s, want %s", got, want)
	}
}
