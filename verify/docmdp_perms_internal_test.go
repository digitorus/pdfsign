package verify

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
)

const (
	// endToken in a fixture object is replaced with the 10-digit end of
	// revision 1, so a /ByteRange can name the bytes a signature covers.
	endToken = "@END@"

	// docMDPReference is a signature /Reference declaring a DocMDP transform
	// that permits no changes.
	docMDPReference = `/Reference [ << /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 1 /V /1.2 >> >> ]`

	// newAnnotation is an incremental update that only adds an object.
	newAnnotation = "<< /Type /Annot /Subtype /Widget /Rect [0 0 10 10] >>"

	// signatureField is the signature field (object 4) whose value is the
	// signature dictionary in object 5.
	signatureField = "<< /FT /Sig /T (sig1) /V 5 0 R >>"

	// certifiedCatalog references the signature dictionary in object 5 from
	// /Perms; plainCatalog carries no /Perms; otherCatalog references the
	// unrelated signature dictionary in object 6.
	certifiedCatalog = "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> /Perms << /DocMDP 5 0 R >> >>"
	plainCatalog     = "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>"
	otherCatalog     = "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> /Perms << /DocMDP 6 0 R >> >>"
)

// signatureDict returns a signature dictionary whose /ByteRange covers exactly
// revision 1, carrying the given extra entries.
func signatureDict(entries string) string {
	return "<< /Type /Sig /Filter /Adobe.PPKLite /Contents <01> /ByteRange [0 0 0 " + endToken + "] " + entries + " >>"
}

// signedPDF describes a one-page fixture: the catalog (object 1), the
// signature field (object 4) and the signature dictionary (object 5), with
// object 6 an unrelated signature dictionary. endOffset shifts the value
// endToken expands to away from the true end of revision 1. When updateID is
// not zero, an incremental update writing updateBody under that object number
// follows revision 1; updates adds further objects to that update.
type signedPDF struct {
	catalog, field, signature string
	endOffset                 int64
	updateID                  int
	updateBody                string
	updates                   []updateObject
}

// updateObject is an object written by the incremental update of a fixture.
type updateObject struct {
	id   int
	body string
}

func (f signedPDF) build(t *testing.T) []byte {
	t.Helper()

	// The end of revision 1 depends on the width of the value written for
	// endToken; a fixed width makes the second pass come out at the same
	// length as the first.
	render := func(signedEnd int64) ([]byte, int64) {
		expand := func(obj string) string {
			return strings.ReplaceAll(obj, endToken, fmt.Sprintf("%010d", signedEnd+f.endOffset))
		}
		var buf bytes.Buffer
		buf.WriteString("%PDF-1.7\n")
		offsets := make(map[int]int64)
		offsets[1] = writeObj(&buf, 1, expand(f.catalog))
		offsets[2] = writeObj(&buf, 2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
		offsets[3] = writeObj(&buf, 3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>")
		offsets[4] = writeObj(&buf, 4, expand(f.field))
		offsets[5] = writeObj(&buf, 5, expand(f.signature))
		offsets[6] = writeObj(&buf, 6, "<< /Type /Sig /Filter /Adobe.PPKLite /Contents <02> >>")
		xref := int64(buf.Len())
		buf.WriteString("xref\n0 7\n0000000000 65535 f \n")
		for i := 1; i <= 6; i++ {
			fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
		}
		fmt.Fprintf(&buf, "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
		end := int64(buf.Len())

		updates := f.updates
		if f.updateID != 0 {
			updates = append([]updateObject{{f.updateID, f.updateBody}}, updates...)
		}
		if len(updates) > 0 {
			offsets := make([]int64, len(updates))
			size := 7
			for i, u := range updates {
				offsets[i] = writeObj(&buf, u.id, expand(u.body))
				if u.id >= size {
					size = u.id + 1
				}
			}
			xref2 := int64(buf.Len())
			buf.WriteString("xref\n")
			for i, u := range updates {
				fmt.Fprintf(&buf, "%d 1\n%010d 00000 n \n", u.id, offsets[i])
			}
			fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", size, xref, xref2)
		}
		return buf.Bytes(), end
	}

	_, signedEnd := render(0)
	fileBytes, check := render(signedEnd)
	if check != signedEnd {
		t.Fatalf("revision 1 length changed between passes: %d != %d", check, signedEnd)
	}
	return fileBytes
}

// checkFixture runs checkDocMDP over the first signature field of the fixture.
func checkFixture(t *testing.T, f signedPDF) (*Signer, error) {
	t.Helper()

	fileBytes := f.build(t)
	rdr, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	v := rdr.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(0).Key("V")

	signer := NewSigner()
	file := bytes.NewReader(fileBytes)
	signed, revision, ok := signedSignatureDictionary(v, file, int64(len(fileBytes)), signer, "")
	if !ok {
		return signer, nil
	}
	err = checkDocMDP(signed, revision, file, int64(len(fileBytes)), signer, "")
	return signer, err
}

// TestCheckDocMDPCatalogPerms covers ISO 32000-1 12.8.2.2: the DocMDP
// permission level is applied only to the signature the document catalog's
// /Perms /DocMDP entry references, as read from the revision that signature
// covers.
func TestCheckDocMDPCatalogPerms(t *testing.T) {
	certified := signedPDF{catalog: certifiedCatalog, field: signatureField, signature: signatureDict(docMDPReference)}

	t.Run("a referenced certification signature is enforced", func(t *testing.T) {
		f := certified
		f.updateID, f.updateBody = 7, newAnnotation
		if _, err := checkFixture(t, f); err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Fatalf("expected the P=1 rejection, got %v", err)
		}
	})

	t.Run("a referenced certification signature without changes passes", func(t *testing.T) {
		signer, err := checkFixture(t, certified)
		if err != nil || len(signer.Warnings) != 0 {
			t.Fatalf("expected no error and no warning, got %v and %d warnings", err, len(signer.Warnings))
		}
	})

	t.Run("a transform the catalog does not reference is an approval signature", func(t *testing.T) {
		for name, catalog := range map[string]string{
			"no /Perms":                    plainCatalog,
			"/Perms naming another object": otherCatalog,
		} {
			t.Run(name, func(t *testing.T) {
				f := certified
				f.catalog = catalog
				f.updateID, f.updateBody = 7, newAnnotation
				signer, err := checkFixture(t, f)
				if err != nil {
					t.Fatalf("P=1 must not be enforced on an approval signature, got %v", err)
				}
				if len(signer.Warnings) != 1 || !strings.Contains(signer.Warnings[0].Error(), "approval signature") {
					t.Fatalf("expected one warning naming the approval signature, got %v", signer.Warnings)
				}
			})
		}
	})

	t.Run("a later update removing /Perms does not lift the restriction", func(t *testing.T) {
		// The update rewrites the catalog without /Perms; the signed revision
		// still carries it, so the certification stays enforced.
		f := certified
		f.updateID, f.updateBody = 1, plainCatalog
		if _, err := checkFixture(t, f); err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Fatalf("expected the P=1 rejection, got %v", err)
		}
	})

	t.Run("an unreadable signed revision is enforced as declared", func(t *testing.T) {
		// The ByteRange ends inside revision 1's trailer, so the covered
		// bytes are not a readable document; the transform must not be
		// downgraded to an approval signature on that account.
		f := certified
		f.endOffset = -40
		f.updateID, f.updateBody = 7, newAnnotation
		signer, err := checkFixture(t, f)
		if err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Fatalf("expected the P=1 rejection, got %v", err)
		}
		if len(signer.Warnings) != 1 || !strings.Contains(signer.Warnings[0].Error(), "enforced as declared") {
			t.Fatalf("expected one warning about the unreadable revision, got %v", signer.Warnings)
		}
	})

	t.Run("a signature dictionary written into its field is matched by its bytes", func(t *testing.T) {
		// Neither dictionary is an indirect object, so both carry their
		// container's pointer; the /Contents identify the signature instead.
		direct := signatureDict(docMDPReference)
		f := signedPDF{
			catalog:    "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> /Perms << /DocMDP " + direct + " >> >>",
			field:      "<< /FT /Sig /T (sig1) /V " + direct + " >>",
			signature:  "<< /Type /Sig /Contents <09> >>",
			updateID:   7,
			updateBody: newAnnotation,
		}
		if _, err := checkFixture(t, f); err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Fatalf("expected the P=1 rejection, got %v", err)
		}
	})
}

// hasValidationError reports whether any validation error on the signer
// contains text.
func hasValidationError(signer *Signer, text string) bool {
	for _, e := range signer.ValidationErrors {
		if strings.Contains(e.Error(), text) {
			return true
		}
	}
	return false
}
