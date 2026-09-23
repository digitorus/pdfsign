package verify

import (
	"bytes"
	"io"
	"testing"

	"github.com/digitorus/pdf"
)

// TestSignatureSet covers the enumeration behind VerifySignatures: the
// current field tree first, then the catalog /Perms /DocMDP entry, then the
// signatures a signed revision held, each signature once.
func TestSignatureSet(t *testing.T) {
	contents := func(set signatureSet) []string {
		var out []string
		for _, sig := range set.found {
			out = append(out, sig.dict.Key("Contents").RawString())
		}
		return out
	}
	equal := func(a, b []string) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	t.Run("a signed revision holds a signature the current tree dropped", func(t *testing.T) {
		// Revision 1 certifies the document with signature 5 in field 4; the
		// update replaces the catalog with one whose /Fields holds only the
		// new field 7, an approval signature 8 covering revision 1, and no
		// /Perms.
		f := signedPDF{
			catalog:    certifiedCatalog,
			field:      signatureField,
			signature:  signatureDict(docMDPReference),
			updateID:   1,
			updateBody: "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] /SigFlags 3 >> >>",
			updates: []updateObject{
				{7, "<< /FT /Sig /T (sig2) /V 8 0 R >>"},
				{8, "<< /Type /Sig /Filter /Adobe.PPKLite /Contents <03> /ByteRange [0 0 0 " + endToken + "] >>"},
			},
		}
		fileBytes := f.build(t)
		file := bytes.NewReader(fileBytes)
		size := int64(len(fileBytes))
		rdr, err := pdf.NewReader(file, size)
		if err != nil {
			t.Fatalf("read: %v", err)
		}

		var set signatureSet
		root := rdr.Trailer().Key("Root")
		set.addFields(root, fromFields)
		set.addPerms(root, fromPerms)
		if got := contents(set); !equal(got, []string{"\x03"}) {
			t.Fatalf("current document: found %q, want the approval signature only", got)
		}

		// The file has one earlier revision, the one the approval
		// signature's /ByteRange covers.
		end, ok := signedRangeEnd(set.found[0].dict, size)
		if !ok {
			t.Fatal("approval signature has no usable /ByteRange")
		}
		if ends := revisionEnds(file, size); len(ends) != 1 || ends[0] != markerEnd(file, end) {
			t.Fatalf("revisionEnds = %v, want [%d]", ends, markerEnd(file, end))
		}
		set.addRevision(file, markerEnd(file, end), "")
		if got := contents(set); !equal(got, []string{"\x03", "\x01"}) || set.found[1].source != fromRevision {
			t.Fatalf("with the earlier revision: found %q, want the certification signature recovered once", got)
		}
		revision, err := pdf.NewReader(io.NewSectionReader(file, 0, end), end)
		if err != nil {
			t.Fatalf("read signed revision: %v", err)
		}
		signedRoot := revision.Trailer().Key("Root")
		set.addFields(signedRoot, fromRevision)
		set.addPerms(signedRoot, fromRevision)
		if got := contents(set); len(got) != 2 {
			t.Fatalf("adding the signed revision as well: found %q, want no further signature", got)
		}

		// VerifySignatures walks the same way. Both signatures stop at a
		// validation error before their bytes are parsed: the approval
		// signature is not part of the revision it claims to cover, and the
		// certification signature is reported as removed first, with its P=1
		// restriction enforced against the update, and is not valid.
		signers, found := VerifySignatures(rdr, file, size, DefaultVerifyOptions())
		if found != 2 || len(signers) != 2 {
			t.Fatalf("VerifySignatures found %d signatures and processed %d, want 2 and 2", found, len(signers))
		}
		if hasValidationError(signers[0], removedSignature) || !hasValidationError(signers[0], "not part of the revision") {
			t.Errorf("approval signature: errors %v", signers[0].ValidationErrors)
		}
		if errs := signers[1].ValidationErrors; len(errs) < 2 || errs[0].Error() != removedSignature || !hasValidationError(signers[1], "P=1") || signers[1].ValidSignature {
			t.Errorf("recovered certification signature: errors %v, valid %v", errs, signers[1].ValidSignature)
		}
	})

	t.Run("the catalog /Perms names a signature the tree does not reach", func(t *testing.T) {
		// An update follows, so the P=1 restriction records an error before
		// the signature bytes are parsed and the signature is processed.
		f := signedPDF{
			catalog:    "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] /SigFlags 3 >> /Perms << /DocMDP 5 0 R >> >>",
			field:      signatureField,
			signature:  signatureDict(docMDPReference),
			updateID:   3,
			updateBody: rotatedPage,
		}
		fileBytes := f.build(t)
		rdr, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var set signatureSet
		root := rdr.Trailer().Key("Root")
		set.addFields(root, fromFields)
		if len(set.found) != 0 {
			t.Fatalf("field tree: found %d signatures, want none", len(set.found))
		}
		set.addPerms(root, fromPerms)
		if got := contents(set); !equal(got, []string{"\x01"}) || set.found[0].source != fromPerms {
			t.Errorf("with /Perms: found %q, want the certification signature", got)
		}
		signers, _ := VerifySignatures(rdr, bytes.NewReader(fileBytes), int64(len(fileBytes)), DefaultVerifyOptions())
		if len(signers) != 1 || len(signers[0].ValidationErrors) < 2 || signers[0].ValidationErrors[0].Error() != permsOnlySignature || !hasValidationError(signers[0], "P=1") || signers[0].ValidSignature {
			t.Errorf("VerifySignatures: %+v", signers)
		}
	})

	t.Run("fields sharing one signature are each reported", func(t *testing.T) {
		f := signedPDF{
			catalog:   "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R 6 0 R] /SigFlags 3 >> >>",
			field:     signatureField,
			signature: signatureDict(""),
		}
		// Object 6 is turned into a second field holding the same signature.
		f.updateID, f.updateBody = 6, "<< /FT /Sig /T (sig2) /V 5 0 R >>"
		fileBytes := f.build(t)
		rdr, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		var set signatureSet
		set.addFields(rdr.Trailer().Key("Root"), fromFields)
		if got := contents(set); !equal(got, []string{"\x01", "\x01"}) {
			t.Errorf("found %q, want the signature once per field", got)
		}
	})
}
