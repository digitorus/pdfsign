package verify

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/digitorus/pdf"
)

const (
	// docMDPReference is a signature /Reference declaring a DocMDP transform
	// that permits no changes.
	docMDPReference = `/Reference [ << /Type /SigRef /TransformMethod /DocMDP /TransformParams << /Type /TransformParams /P 1 /V /1.2 >> >> ]`

	// newAnnotation is an incremental update that only adds an object.
	newAnnotation = "<< /Type /Annot /Subtype /Widget /Rect [0 0 10 10] >>"

	// certifiedCatalog is the catalog with a /Perms entry referencing the
	// signature dictionary (object 5); plainCatalog is the same without it.
	certifiedCatalog = "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> /Perms << /DocMDP 5 0 R >> >>"
	plainCatalog     = "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>"
)

// buildSignedPDF builds a one-page PDF whose single signature field (object 4)
// holds a signature dictionary (object 5) carrying sigEntries next to /Type,
// /Filter, /Contents and a /ByteRange that covers exactly revision 1. Object 6
// is a second, unrelated signature dictionary. When updateID is not zero, an
// incremental update writing updateBody under that object number follows.
func buildSignedPDF(t *testing.T, catalog, sigEntries string, updateID int, updateBody string) []byte {
	t.Helper()

	// The ByteRange has to name the end of revision 1, which depends on the
	// ByteRange's own width; a fixed-width placeholder makes the second pass
	// come out at the same length as the first.
	build := func(signedEnd int64) ([]byte, int64) {
		var buf bytes.Buffer
		buf.WriteString("%PDF-1.7\n")
		offsets := make(map[int]int64)
		offsets[1] = writeObj(&buf, 1, catalog)
		offsets[2] = writeObj(&buf, 2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
		offsets[3] = writeObj(&buf, 3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>")
		offsets[4] = writeObj(&buf, 4, "<< /FT /Sig /T (sig1) /V 5 0 R >>")
		offsets[5] = writeObj(&buf, 5, fmt.Sprintf("<< /Type /Sig /Filter /Adobe.PPKLite /Contents <01> /ByteRange [0 0 0 %010d] %s >>", signedEnd, sigEntries))
		offsets[6] = writeObj(&buf, 6, "<< /Type /Sig /Filter /Adobe.PPKLite /Contents <02> >>")
		xref := int64(buf.Len())
		buf.WriteString("xref\n0 7\n0000000000 65535 f \n")
		for i := 1; i <= 6; i++ {
			fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
		}
		fmt.Fprintf(&buf, "trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)
		end := int64(buf.Len())

		if updateID != 0 {
			offset := writeObj(&buf, updateID, updateBody)
			xref2 := int64(buf.Len())
			fmt.Fprintf(&buf, "xref\n%d 1\n%010d 00000 n \n", updateID, offset)
			fmt.Fprintf(&buf, "trailer\n<< /Size 8 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", xref, xref2)
		}
		return buf.Bytes(), end
	}

	_, signedEnd := build(0)
	fileBytes, check := build(signedEnd)
	if check != signedEnd {
		t.Fatalf("revision 1 length changed between passes: %d != %d", check, signedEnd)
	}
	return fileBytes
}

// signatureDictionary returns the signature dictionary of the first field.
func signatureDictionary(t *testing.T, fileBytes []byte) pdf.Value {
	t.Helper()
	rdr, err := pdf.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return rdr.Trailer().Key("Root").Key("AcroForm").Key("Fields").Index(0).Key("V")
}

// TestCheckDocMDPCatalogPerms covers ISO 32000-1 12.8.2.2: the DocMDP
// permission level is applied only to the signature the document catalog's
// /Perms /DocMDP entry references, as read from the revision that signature
// covers.
func TestCheckDocMDPCatalogPerms(t *testing.T) {
	run := func(t *testing.T, fileBytes []byte) (*Signer, error) {
		t.Helper()
		signer := NewSigner()
		err := checkDocMDP(signatureDictionary(t, fileBytes), bytes.NewReader(fileBytes), int64(len(fileBytes)), signer, "")
		return signer, err
	}

	t.Run("a referenced certification signature is enforced", func(t *testing.T) {
		_, err := run(t, buildSignedPDF(t, certifiedCatalog, docMDPReference, 7, newAnnotation))
		if err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Fatalf("expected the P=1 rejection, got %v", err)
		}
	})

	t.Run("a referenced certification signature without changes passes", func(t *testing.T) {
		signer, err := run(t, buildSignedPDF(t, certifiedCatalog, docMDPReference, 0, ""))
		if err != nil || len(signer.Warnings) != 0 {
			t.Fatalf("expected no error and no warning, got %v and %d warnings", err, len(signer.Warnings))
		}
	})

	t.Run("a transform the catalog does not reference is an approval signature", func(t *testing.T) {
		for name, catalog := range map[string]string{
			"no /Perms":                    plainCatalog,
			"/Perms naming another object": strings.Replace(certifiedCatalog, "/DocMDP 5 0 R", "/DocMDP 6 0 R", 1),
		} {
			t.Run(name, func(t *testing.T) {
				signer, err := run(t, buildSignedPDF(t, catalog, docMDPReference, 7, newAnnotation))
				if err != nil {
					t.Fatalf("P=1 must not be enforced on an approval signature, got %v", err)
				}
				if len(signer.Warnings) != 1 || !strings.Contains(signer.Warnings[0].Error(), "approval signature") {
					t.Fatalf("expected one warning naming the approval signature, got %v", signer.Warnings)
				}
			})
		}
	})

	t.Run("a referenced signature without a transform is reported", func(t *testing.T) {
		signer, err := run(t, buildSignedPDF(t, certifiedCatalog, "", 7, newAnnotation))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if len(signer.Warnings) != 1 || !strings.Contains(signer.Warnings[0].Error(), "declares no DocMDP transform") {
			t.Fatalf("expected one warning about the missing transform, got %v", signer.Warnings)
		}
	})

	t.Run("a later update removing /Perms does not lift the restriction", func(t *testing.T) {
		// The update rewrites the catalog without /Perms; the signed revision
		// still carries it, so the certification stays enforced.
		_, err := run(t, buildSignedPDF(t, certifiedCatalog, docMDPReference, 1, plainCatalog))
		if err == nil || !strings.Contains(err.Error(), "permits none") {
			t.Fatalf("expected the P=1 rejection, got %v", err)
		}
	})
}
