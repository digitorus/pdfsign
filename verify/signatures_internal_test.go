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
		for _, v := range set.found {
			out = append(out, v.Key("Contents").RawString())
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

		set := signatureSet{seen: make(map[string]bool)}
		root := rdr.Trailer().Key("Root")
		set.addFields(root, true)
		set.addPerms(root)
		if got := contents(set); !equal(got, []string{"\x03"}) {
			t.Fatalf("current document: found %q, want the approval signature only", got)
		}

		end, ok := signedRangeEnd(set.found[0], size)
		if !ok {
			t.Fatal("approval signature has no usable /ByteRange")
		}
		revision, err := pdf.NewReader(io.NewSectionReader(file, 0, end), end)
		if err != nil {
			t.Fatalf("read signed revision: %v", err)
		}
		signedRoot := revision.Trailer().Key("Root")
		set.addFields(signedRoot, false)
		set.addPerms(signedRoot)
		if got := contents(set); !equal(got, []string{"\x03", "\x01"}) {
			t.Fatalf("with the signed revision: found %q, want the certification signature recovered once", got)
		}
		set.addFields(signedRoot, false)
		set.addPerms(signedRoot)
		if got := contents(set); len(got) != 2 {
			t.Fatalf("adding the revision again: found %q, want no further signature", got)
		}

		// VerifySignatures walks the same way. Both signatures stop at a
		// validation error before their bytes are parsed: the approval
		// signature is not part of the revision it claims to cover, and the
		// certification signature is reported as unreachable first, with its
		// P=1 restriction enforced against the update.
		signers, found := VerifySignatures(rdr, file, size, DefaultVerifyOptions())
		if found != 2 || len(signers) != 2 {
			t.Fatalf("VerifySignatures found %d signatures and processed %d, want 2 and 2", found, len(signers))
		}
		if hasValidationError(signers[0], unreachableSignature) || !hasValidationError(signers[0], "not part of the revision") {
			t.Errorf("approval signature: errors %v", signers[0].ValidationErrors)
		}
		if errs := signers[1].ValidationErrors; len(errs) < 2 || errs[0].Error() != unreachableSignature || !hasValidationError(signers[1], "P=1") {
			t.Errorf("recovered certification signature: errors %v", errs)
		}
	})

	t.Run("the catalog /Perms names a signature the tree does not reach", func(t *testing.T) {
		f := signedPDF{
			catalog:   "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] /SigFlags 3 >> /Perms << /DocMDP 5 0 R >> >>",
			field:     signatureField,
			signature: signatureDict(docMDPReference),
		}
		fileBytes := f.build(t)
		rdr, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		set := signatureSet{seen: make(map[string]bool)}
		root := rdr.Trailer().Key("Root")
		set.addFields(root, true)
		if len(set.found) != 0 {
			t.Fatalf("field tree: found %d signatures, want none", len(set.found))
		}
		set.addPerms(root)
		if got := contents(set); !equal(got, []string{"\x01"}) {
			t.Errorf("with /Perms: found %q, want the certification signature", got)
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
		set := signatureSet{seen: make(map[string]bool)}
		set.addFields(rdr.Trailer().Key("Root"), true)
		if got := contents(set); !equal(got, []string{"\x01", "\x01"}) {
			t.Errorf("found %q, want the signature once per field", got)
		}
	})
}
